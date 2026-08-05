#!/usr/bin/env python3
"""
Task 1: Analyze UNSW-NB15 Feature Mapping for nfstream
Maps nfstream flow features to the 49 features expected by trained models.
"""

from nfstream import NFStreamer
import pandas as pd
import numpy as np

# UNSW-NB15 feature names (from training script + literature)
UNSW_NB15_FEATURES = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt',
    'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz',
    'trans_depth', 'res_bdy_len', 'ct_state_ttl', 'ct_flw_http_mthd', 'ct_ftp_cmd',
    'ct_src_ltm', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    'ct_dst_src_ltm', 'is_ftp_login', 'is_sm_ips_ports', 'ct_ftp_cmd', 'stime',
    'ltime', 'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat'
]

# nfstream to UNSW-NB15 feature mapping (based on nfstream docs and feature analysis)
NFSTREAM_TO_UNSW = {
    # Duration
    'bidirectional_duration_ms': 'dur',  # microseconds -> milliseconds
    
    # Protocol
    'protocol': 'proto',
    'protocol_name': 'service',  # mapped to service
    
    # Packets
    'src2dst_packets': 'spkts',
    'dst2src_packets': 'dpkts',
    'bidirectional_packets': None,  # derived
    
    # Bytes
    'src2dst_bytes': 'sbytes',
    'dst2src_bytes': 'dbytes',
    'bidirectional_bytes': None,  # derived
    
    # Rate
    'bidirectional_rate': 'rate',  # packets per second
    
    # TTL
    'src2dst_first_seen_ttl': 'sttl',
    'dst2src_first_seen_ttl': 'dttl',
    
    # Load (bits per second)
    'src2dst_bitrate': 'sload',
    'dst2src_bitrate': 'dload',
    
    # Loss
    'src2dst_retransmission_packets': 'sloss',  # proxy
    'dst2src_retransmission_packets': 'dloss',  # proxy
    
    # Inter-packet timing
    'src2dst_mean_iat': 'sinpkt',  # mean inter-arrival time
    'dst2src_mean_iat': 'dinpkt',
    'src2dst_std_iat': 'sjit',  # jitter = std of IAT
    'dst2src_std_iat': 'djit',
    
    # TCP window
    'src2dst_first_tcp_win': 'swin',
    'src2dst_tcp_bytes': 'stcpb',
    'dst2src_tcp_bytes': 'dtcpb',
    
    # Mean packet size
    'src2dst_mean_ps': 'smeansz',
    'dst2src_mean_ps': 'dmeansz',
    
    # Connection state (mapped from nfstream state)
    'tcp_state': 'state',
    
    # Advanced (connection tracking) - need computation
    'trans_depth': None,  # HTTP transaction depth
    'res_bdy_len': None,  # response body length
    
    # Connection tracking features (ct_*) - computed over time windows
    # These require stateful tracking across flows
    'ct_state_ttl': None,
    'ct_flw_http_mthd': None,
    'ct_ftp_cmd': None,
    'ct_src_ltm': None,
    'ct_srv_dst': None,
    'ct_dst_ltm': None,
    'ct_src_dport_ltm': None,
    'ct_dst_sport_ltm': None,
    'ct_dst_src_ltm': None,
    
    # FTP
    'is_ftp_login': None,
    'is_sm_ips_ports': None,
    
    # Timestamps
    'src2dst_first_seen_ms': 'stime',
    'dst2src_first_seen_ms': 'ltime',
    
    # TCP timing
    'tcprtt': None,  # TCP round trip time
    'synack': None,  # SYN-ACK time
    'ackdat': None,  # ACK-DATA time
}

# Additional nfstream features that are useful
NFSTREAM_EXTRA_FEATURES = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'src_ip_country', 'dst_ip_country',
    'application_name', 'application_category_name',
    'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms',
    'src2dst_max_ps', 'dst2src_max_ps',
    'src2dst_min_ps', 'dst2src_min_ps',
    'src2dst_ps_flags', 'dst2src_ps_flags',
]

def analyze_nfstream_features():
    """Print all available nfstream flow attributes."""
    print("=" * 80)
    print("NFSTREAM FLOW ATTRIBUTES ANALYSIS")
    print("=" * 80)
    
    print("\n📋 MAPPING TABLE (nfstream → UNSW-NB15):")
    print("-" * 80)
    mapped = 0
    unmapped = 0
    for nf_feat, unsw_feat in NFSTREAM_TO_UNSW.items():
        if unsw_feat:
            print(f"  ✅ {nf_feat:<45} → {unsw_feat}")
            mapped += 1
        else:
            print(f"  ❌ {nf_feat:<45} → [NEEDS COMPUTATION]")
            unmapped += 1
    
    print(f"\n📊 SUMMARY: {mapped} direct mappings, {unmapped} need computation")
    print(f"   UNSW-NB15 target features: {len(UNSW_NB15_FEATURES)}")
    
    # Check coverage
    covered = set(v for v in NFSTREAM_TO_UNSW.values() if v)
    missing = set(UNSW_NB15_FEATURES) - covered
    print(f"\n🔍 MISSING UNSW FEATURES (need custom computation):")
    for feat in sorted(missing):
        print(f"   - {feat}")
    
    return NFSTREAM_TO_UNSW, missing


def get_nfstream_available_attrs():
    """Get actual nfstream flow attributes by inspecting the class."""
    from nfstream import NFStreamer
    import inspect
    
    # Get NFStreamer attributes
    print("\n🔬 NFStreamer class inspection:")
    print("-" * 80)
    
    # Check what statistical=True enables
    print("Statistical features enabled when statistical=True:")
    statistical_features = [
        'bidirectional_duration_ms',
        'bidirectional_packets', 'bidirectional_bytes',
        'bidirectional_rate', 'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms',
        'src2dst_packets', 'dst2src_packets',
        'src2dst_bytes', 'dst2src_bytes',
        'src2dst_bitrate', 'dst2src_bitrate',
        'src2dst_mean_iat', 'dst2src_mean_iat',
        'src2dst_std_iat', 'dst2src_std_iat',
        'src2dst_mean_ps', 'dst2src_mean_ps',
        'src2dst_min_ps', 'dst2src_min_ps',
        'src2dst_max_ps', 'dst2src_max_ps',
        'src2dst_ps_flags', 'dst2src_ps_flags',
        'src2dst_retransmission_packets', 'dst2src_retransmission_packets',
        'src2dst_first_seen_ttl', 'dst2src_first_seen_ttl',
        'src2dst_first_tcp_win', 'dst2src_first_tcp_win',
        'src2dst_tcp_bytes', 'dst2src_tcp_bytes',
    ]
    for feat in statistical_features:
        print(f"   • {feat}")
    
    return statistical_features


if __name__ == "__main__":
    mapping, missing = analyze_nfstream_features()
    get_nfstream_available_attrs()
    
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS FOR MISSING FEATURES:")
    print("=" * 80)
    print("""
1. ct_* features (connection tracking): Require stateful tracking across flows
   - Implement sliding window counters (per src_ip, dst_ip, port combinations)
   - Use Redis or in-memory dict with TTL expiration

2. trans_depth, res_bdy_len: Need HTTP/HTTPS application layer parsing
   - nfstream can do this with nfstream.NFStreamer(..., n_dissections=20)

3. tcprtt, synack, ackdat: Need TCP handshake timing
   - Available in nfstream with statistical=True and packet capture

4. is_ftp_login, is_sm_ips_ports: Protocol-specific
   - FTP: check for USER/PASS commands in payload
   - SMTP: check for same port pattern

5. state: Map nfstream tcp_state to UNSW state labels
   - CON, REQ, RST, etc. → map to UNSW state taxonomy
""")