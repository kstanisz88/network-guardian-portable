#!/usr/bin/env python3
"""
Firewall Manager for Windows
Handles IP blocking (quarantine) and whitelisting via Windows Firewall.
"""

import subprocess
import logging
import re
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Manages Windows Firewall rules for IP blocking and whitelisting.
    Uses netsh advfirewall for Windows 10/11 compatibility.
    """
    
    QUARANTINE_PREFIX = "NG_Quarantine_"
    WHITELIST_PREFIX = "NG_Whitelist_"
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._rule_cache: Dict[str, Dict] = {}
        self._refresh_cache()
    
    def _refresh_cache(self):
        """Refresh internal rule cache from firewall."""
        try:
            self._rule_cache = self._get_all_rules()
        except Exception as e:
            logger.warning(f"Could not refresh firewall cache: {e}")
            self._rule_cache = {}
    
    def _get_all_rules(self) -> Dict[str, Dict]:
        """Get all existing Network Guardian firewall rules."""
        rules = {}
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                return {}
            
            current_rule = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith("Rule Name:"):
                    if current_rule and current_rule.get("name"):
                        rules[current_rule["name"]] = current_rule
                    current_rule = {"name": line.split(":", 1)[1].strip()}
                elif line and ":" in line and current_rule:
                    key, value = line.split(":", 1)
                    current_rule[key.strip().lower().replace(" ", "_")] = value.strip()
            
            if current_rule and current_rule.get("name"):
                rules[current_rule["name"]] = current_rule
                
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
        
        return rules
    
    def _run_netsh(self, args: List[str]) -> bool:
        """Execute netsh command."""
        if self.dry_run:
            logger.info(f"[DRY RUN] netsh {' '.join(args)}")
            return True
        
        try:
            cmd = ["netsh", "advfirewall", "firewall"] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return True
            else:
                logger.error(f"netsh failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("netsh command timed out")
            return False
        except Exception as e:
            logger.error(f"netsh error: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str = "", direction: str = "out") -> bool:
        """
        Block an IP address (quarantine).
        
        Args:
            ip: IP address to block
            reason: Reason for blocking (added to rule description)
            direction: "out" (outbound), "in" (inbound), or "both"
            
        Returns:
            True if successful
        """
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        rule_name = f"{self.QUARANTINE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        
        # Check if rule already exists
        if rule_name in self._rule_cache:
            logger.info(f"IP {ip} already quarantined")
            return True
        
        success = True
        directions = ["out", "in"] if direction == "both" else [direction]
        
        for dir in directions:
            desc = f"Network Guardian Quarantine: {reason}" if reason else "Network Guardian Quarantine"
            args = [
                "add", "rule",
                f"name={rule_name}_{dir}",
                f"description={desc}",
                f"dir={dir}",
                "action=block",
                f"remoteip={ip}",
                "protocol=any",
                "enable=yes",
                "profile=any"
            ]
            
            if not self._run_netsh(args):
                success = False
                logger.error(f"Failed to create {dir}bound quarantine rule for {ip}")
            else:
                logger.info(f"✅ Quarantined {ip} ({dir}bound): {reason}")
        
        if success:
            self._refresh_cache()
        
        return success
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Remove quarantine for an IP address.
        
        Returns:
            True if successful
        """
        rule_name = f"{self.QUARANTINE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        
        # Delete both inbound and outbound rules
        success = True
        for dir in ["in", "out"]:
            full_name = f"{rule_name}_{dir}"
            if full_name in self._rule_cache:
                if not self._run_netsh(["delete", "rule", f"name={full_name}"]):
                    success = False
                else:
                    logger.info(f"✅ Removed quarantine for {ip} ({dir}bound)")
        
        if success:
            self._refresh_cache()
        
        return success
    
    def whitelist_ip(self, ip: str, reason: str = "") -> bool:
        """
        Add IP to whitelist (allow all traffic).
        
        Returns:
            True if successful
        """
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        rule_name = f"{self.WHITELIST_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        
        if rule_name in self._rule_cache:
            logger.info(f"IP {ip} already whitelisted")
            return True
        
        # Whitelist: allow both inbound and outbound
        success = True
        for dir in ["in", "out"]:
            desc = f"Network Guardian Whitelist: {reason}" if reason else "Network Guardian Whitelist"
            args = [
                "add", "rule",
                f"name={rule_name}_{dir}",
                f"description={desc}",
                f"dir={dir}",
                "action=allow",
                f"remoteip={ip}",
                "protocol=any",
                "enable=yes",
                "profile=any"
            ]
            
            if not self._run_netsh(args):
                success = False
                logger.error(f"Failed to create {dir}bound whitelist rule for {ip}")
            else:
                logger.info(f"✅ Whitelisted {ip} ({dir}bound): {reason}")
        
        if success:
            self._refresh_cache()
        
        return success
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist."""
        rule_name = f"{self.WHITELIST_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        
        success = True
        for dir in ["in", "out"]:
            full_name = f"{rule_name}_{dir}"
            if full_name in self._rule_cache:
                if not self._run_netsh(["delete", "rule", f"name={full_name}"]):
                    success = False
                else:
                    logger.info(f"✅ Removed whitelist for {ip} ({dir}bound)")
        
        if success:
            self._refresh_cache()
        
        return success
    
    def is_quarantined(self, ip: str) -> bool:
        """Check if IP is quarantined."""
        rule_name = f"{self.QUARANTINE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        return any(rule_name in name for name in self._rule_cache.keys())
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        rule_name = f"{self.WHITELIST_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        return any(rule_name in name for name in self._rule_cache.keys())
    
    def get_quarantined_ips(self) -> List[str]:
        """Get list of all quarantined IPs."""
        ips = set()
        for name in self._rule_cache:
            if name.startswith(self.QUARANTINE_PREFIX):
                # Extract IP from rule name
                parts = name.replace(self.QUARANTINE_PREFIX, "").split("_")
                if len(parts) >= 4:  # IPv4
                    ip = ".".join(parts[:4])
                    ips.add(ip)
        return list(ips)
    
    def get_whitelisted_ips(self) -> List[str]:
        """Get list of all whitelisted IPs."""
        ips = set()
        for name in self._rule_cache:
            if name.startswith(self.WHITELIST_PREFIX):
                parts = name.replace(self.WHITELIST_PREFIX, "").split("_")
                if len(parts) >= 4:
                    ip = ".".join(parts[:4])
                    ips.add(ip)
        return list(ips)
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IPv4 or IPv6 address."""
        # Simple IPv4 validation
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        
        # Simple IPv6 validation (basic)
        if ':' in ip and ip.count(':') >= 2:
            return True
        
        return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get firewall manager status."""
        return {
            "quarantined_count": len(self.get_quarantined_ips()),
            "whitelisted_count": len(self.get_whitelisted_ips()),
            "quarantined_ips": self.get_quarantined_ips(),
            "whitelisted_ips": self.get_whitelisted_ips(),
            "dry_run": self.dry_run
        }


def create_firewall_manager(dry_run: bool = False) -> Optional[FirewallManager]:
    """Factory function to create firewall manager."""
    if sys.platform != "win32":
        logger.warning("FirewallManager only works on Windows")
        return None
    
    # Check if netsh is available
    try:
        subprocess.run(["netsh", "?"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.error("netsh not available")
        return None
    
    return FirewallManager(dry_run=dry_run)


if __name__ == "__main__":
    import sys
    import re
    logging.basicConfig(level=logging.INFO)
    
    fw = create_firewall_manager(dry_run=True)
    if fw:
        print("Testing FirewallManager (dry run)...")
        fw.block_ip("192.168.1.100", "Test quarantine")
        fw.whitelist_ip("10.0.0.1", "Test whitelist")
        print(f"Status: {fw.get_status()}")
        print("✅ FirewallManager test completed")
    else:
        print("❌ FirewallManager not available (not on Windows or netsh missing)")