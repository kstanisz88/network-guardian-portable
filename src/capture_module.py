#!/usr/bin/env python3
"""
Task 3: Network Capture Module - nfstream wrapper for real-time flow capture
Provides continuous flow capture with callback per flow.
"""

import threading
import time
import logging
from typing import Callable, Dict, Any, Optional, List
from dataclasses import dataclass
from collections import deque
from pathlib import Path

from nfstream import NFStreamer

logger = logging.getLogger(__name__)


@dataclass
class CaptureStats:
    """Statistics for the capture session."""
    total_flows: int = 0
    flows_per_second: float = 0.0
    bytes_processed: int = 0
    packets_processed: int = 0
    start_time: float = 0.0
    last_flow_time: float = 0.0
    errors: int = 0


class ConnectionTracker:
    """
    Stateful connection tracking for computing ct_* features.
    Maintains sliding window counters per IP/port combinations.
    """
    
    def __init__(self, window_seconds: int = 120, max_entries: int = 100000):
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        
        # Counters: key -> (count, last_seen_timestamp)
        self.src_ip_counts = {}
        self.dst_ip_counts = {}
        self.src_port_counts = {}
        self.dst_port_counts = {}
        self.ip_pair_counts = {}
        self.service_counts = {}
        
        self._lock = threading.Lock()
    
    def update(self, flow: Dict[str, Any]) -> Dict[str, float]:
        """Update counters and return ct_* features for this flow."""
        now = time.time()
        src_ip = flow.get('src_ip', '')
        dst_ip = flow.get('dst_ip', '')
        src_port = flow.get('src_port', 0)
        dst_port = flow.get('dst_port', 0)
        service = flow.get('application_name', 'unknown').lower()
        
        with self._lock:
            self._cleanup_old_entries(now)
            
            # Update and get counts
            features = {}
            
            # ct_src_ltm: connections from src_ip in last window
            features['ct_src_ltm'] = self._increment_and_get(self.src_ip_counts, src_ip, now)
            
            # ct_dst_ltm: connections to dst_ip in last window
            features['ct_dst_ltm'] = self._increment_and_get(self.dst_ip_counts, dst_ip, now)
            
            # ct_src_dport_ltm: connections from src_ip to dst_port
            features['ct_src_dport_ltm'] = self._increment_and_get(
                self.src_port_counts, (src_ip, dst_port), now
            )
            
            # ct_dst_sport_ltm: connections to dst_ip from src_port
            features['ct_dst_sport_ltm'] = self._increment_and_get(
                self.dst_port_counts, (dst_ip, src_port), now
            )
            
            # ct_dst_src_ltm: connections between this IP pair
            features['ct_dst_src_ltm'] = self._increment_and_get(
                self.ip_pair_counts, (src_ip, dst_ip), now
            )
            
            # ct_srv_dst: connections to this service on dst_ip
            features['ct_srv_dst'] = self._increment_and_get(
                self.service_counts, (dst_ip, service), now
            )
            
            # ct_state_ttl, ct_flw_http_mthd: placeholders
            features['ct_state_ttl'] = 0.0
            features['ct_flw_http_mthd'] = 0.0
            
            return features
    
    def _increment_and_get(self, counter_dict: dict, key: Any, now: float) -> float:
        """Increment counter for key and return current count."""
        if key not in counter_dict:
            counter_dict[key] = [0, now]
        counter_dict[key][0] += 1
        counter_dict[key][1] = now
        return float(counter_dict[key][0])
    
    def _cleanup_old_entries(self, now: float):
        """Remove entries older than window."""
        cutoff = now - self.window_seconds
        for d in [self.src_ip_counts, self.dst_ip_counts, self.src_port_counts,
                  self.dst_port_counts, self.ip_pair_counts, self.service_counts]:
            to_delete = [k for k, v in d.items() if v[1] < cutoff]
            for k in to_delete:
                del d[k]
            
            # Enforce max entries
            if len(d) > self.max_entries:
                # Remove oldest entries
                sorted_items = sorted(d.items(), key=lambda x: x[1][1])
                for k, _ in sorted_items[:len(d) - self.max_entries]:
                    del d[k]


class FlowCapture:
    """
    Continuous network flow capture using nfstream.
    Runs in background thread, calls callback for each flow.
    """
    
    def __init__(
        self,
        interface: str = "any",
        callback: Callable[[Dict[str, Any]], None] = None,
        bpf_filter: str = None,
        idle_timeout: int = 120,
        active_timeout: int = 1800,
        max_flows: int = 0,
        enable_connection_tracking: bool = True,
        tracking_window: int = 120,
        statistical: bool = True,
        n_dissections: int = 20
    ):
        """
        Initialize flow capture.
        
        Args:
            interface: Network interface ('any', 'eth0', 'Wi-Fi', etc.)
            callback: Function to call for each flow: callback(flow_dict, ct_features)
            bpf_filter: BPF filter string (e.g., "tcp port 80")
            idle_timeout: Flow idle timeout in seconds
            active_timeout: Flow active timeout in seconds
            max_flows: Max flows to capture (0 = unlimited)
            enable_connection_tracking: Enable ct_* feature computation
            tracking_window: Connection tracking window in seconds
            statistical: Enable statistical flow features
            n_dissections: Number of packet dissections for L7 analysis
        """
        self.interface = interface
        self.callback = callback
        self.bpf_filter = bpf_filter
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_flows = max_flows if max_flows >= 0 else 0
        self.enable_connection_tracking = enable_connection_tracking
        
        # Connection tracker for ct_* features
        self.tracker = ConnectionTracker(window_seconds=tracking_window) if enable_connection_tracking else None
        
        # NFStreamer
        self._streamer: Optional[NFStreamer] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Stats
        self.stats = CaptureStats()
        self._flow_times = deque(maxlen=1000)
        
        # NFStreamer config
        self._streamer_config = {
            'source': self.interface,
            'decode_tunnels': True,
            'bpf_filter': self.bpf_filter,
            'promiscuous_mode': True,
            'snapshot_length': 1536,
            'idle_timeout': self.idle_timeout,
            'active_timeout': self.active_timeout,
            'accounting_mode': 0,  # 0=standard, 1=netflow v5, 2=netflow v9
            'n_dissections': n_dissections,
            'statistical_analysis': statistical,
            'splt_analysis': 0,
            'n_meters': 0,
            'max_nflows': self.max_flows if self.max_flows > 0 else None,
            'performance_report': 0,
            'system_visibility_mode': 0,
        }
        
        # Windows-specific: try to get interface name
        if self.interface == "any":
            self.interface = self._detect_active_interface()
    
    def _detect_active_interface(self) -> str:
        """Detect active network interface on Windows/Linux."""
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == 2 and not addr.address.startswith("127."):  # AF_INET, not loopback
                        logger.info(f"Auto-detected interface: {name}")
                        return name
        except Exception as e:
            logger.warning(f"Interface auto-detection failed: {e}")
        return "any"  # Let nfstream decide
    
    def start(self):
        """Start capture in background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("Capture already running")
            return
        
        self._stop_event.clear()
        self.stats = CaptureStats()
        self.stats.start_time = time.time()
        self._flow_times.clear()
        
        self._thread = threading.Thread(target=self._run, daemon=True, name="FlowCapture")
        self._thread.start()
        logger.info(f"🚀 Flow capture started on interface: {self.interface}")
    
    def stop(self, timeout: float = 5.0):
        """Stop capture gracefully."""
        if not self._thread:
            return
        
        logger.info("🛑 Stopping flow capture...")
        self._stop_event.set()
        
        if self._streamer:
            try:
                self._streamer.close()
            except Exception as e:
                logger.error(f"Error closing streamer: {e}")
        
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("Capture thread did not stop in time")
        else:
            logger.info("✅ Flow capture stopped")
        
        self._thread = None
    
    def _run(self):
        """Main capture loop (runs in background thread)."""
        try:
            self._streamer = NFStreamer(**self._streamer_config)
            
            for flow in self._streamer:
                if self._stop_event.is_set():
                    break
                
                try:
                    # Convert flow to dict
                    flow_dict = flow.to_dict()
                    
                    # Add connection tracking features
                    ct_features = {}
                    if self.tracker:
                        ct_features = self.tracker.update(flow_dict)
                        flow_dict.update(ct_features)
                    
                    # Update stats
                    self._update_stats(flow_dict)
                    
                    # Call callback
                    if self.callback:
                        try:
                            self.callback(flow_dict)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                            self.stats.errors += 1
                    
                except Exception as e:
                    logger.error(f"Flow processing error: {e}")
                    self.stats.errors += 1
        
        except Exception as e:
            logger.error(f"Capture thread error: {e}")
            self.stats.errors += 1
        finally:
            logger.info("Capture loop ended")
    
    def _update_stats(self, flow_dict: Dict[str, Any]):
        """Update capture statistics."""
        now = time.time()
        self.stats.total_flows += 1
        self.stats.last_flow_time = now
        self._flow_times.append(now)
        
        # Flows per second (rolling window)
        if len(self._flow_times) > 1:
            window = now - self._flow_times[0]
            if window > 0:
                self.stats.flows_per_second = len(self._flow_times) / window
        
        # Bytes and packets
        self.stats.bytes_processed += flow_dict.get('bidirectional_bytes', 0)
        self.stats.packets_processed += flow_dict.get('bidirectional_packets', 0)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current capture statistics."""
        uptime = time.time() - self.stats.start_time if self.stats.start_time > 0 else 0
        return {
            'total_flows': self.stats.total_flows,
            'flows_per_second': round(self.stats.flows_per_second, 2),
            'bytes_processed': self.stats.bytes_processed,
            'packets_processed': self.stats.packets_processed,
            'uptime_seconds': round(uptime, 1),
            'errors': self.stats.errors,
            'interface': self.interface,
            'running': self._thread is not None and self._thread.is_alive()
        }
    
    def is_running(self) -> bool:
        """Check if capture is running."""
        return self._thread is not None and self._thread.is_alive()
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


def create_capture(
    interface: str = "auto",
    callback: Callable = None,
    **kwargs
) -> FlowCapture:
    """Factory function to create flow capture."""
    if interface == "auto":
        interface = "any"
    return FlowCapture(interface=interface, callback=callback, **kwargs)


if __name__ == "__main__":
    # Test capture module
    import signal
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def flow_handler(flow: Dict[str, Any]):
        print(f"Flow: {flow.get('src_ip')}:{flow.get('src_port')} -> "
              f"{flow.get('dst_ip')}:{flow.get('dst_port')} "
              f"({flow.get('protocol_name', 'N/A')}) "
              f"bytes={flow.get('bidirectional_bytes', 0)} "
              f"pkts={flow.get('bidirectional_packets', 0)}")
    
    capture = create_capture(
        interface="auto",
        callback=flow_handler,
        statistical=True,
        idle_timeout=30
    )
    
    def signal_handler(sig, frame):
        print("\nStopping...")
        capture.stop()
        stats = capture.get_stats()
        print(f"\n📊 Stats: {stats}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("Starting capture test (Ctrl+C to stop)...")
    capture.start()
    
    # Keep running
    while capture.is_running():
        time.sleep(5)
        stats = capture.get_stats()
        print(f"📊 {stats['total_flows']} flows, {stats['flows_per_second']:.1f} flows/s, "
              f"{stats['bytes_processed']/1024/1024:.2f} MB")