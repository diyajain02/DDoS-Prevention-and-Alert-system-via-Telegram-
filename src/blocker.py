"""IP blocking engine using nftables (preferred) or iptables fallback."""
import subprocess
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from pathlib import Path
import threading

from src.models import BlockedIP
from src.config_loader import get_config


class IPBlocker:
    """Manages IP blocking via nftables/iptables."""

    def __init__(self):
        self.config = get_config()
        blocker_config = self.config.get('blocker', {})
        self.enabled = blocker_config.get('enabled', True)
        self.backend = blocker_config.get('backend', 'nftables')
        self.chain_name = blocker_config.get('chain_name', 'light-soc-block')
        self.table_name = blocker_config.get('table_name', 'inet light-soc')
        self.whitelist = set(blocker_config.get('whitelist', []))
        self.auto_unblock = blocker_config.get('auto_unblock', True)
        self.default_duration = blocker_config.get('default_block_duration', 3600)

        self.blocked_ips: Dict[str, BlockedIP] = {}
        self.lock = threading.Lock()
        self._init_firewall()
        self._load_persisted_blocks()

    def _init_firewall(self):
        """Initialize nftables table and chain."""
        if self.backend == 'nftables':
            self._init_nftables()
        else:
            self._init_iptables()

    def _init_nftables(self):
        """Create nftables table and chain if they don't exist."""
        try:
            # Create table
            subprocess.run(['nft', 'add', 'table', self.table_name], capture_output=True, check=True)
            # Create chain with hook for input traffic
            subprocess.run([
                'nft', 'add', 'chain', self.table_name, self.chain_name,
                '{', 'type', 'filter', 'hook', 'input', 'priority', '0', ';', '}'
            ], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Warning: nftables not available ({e}), falling back to iptables")
            self.backend = 'iptables'
            self._init_iptables()

    def _init_iptables(self):
        """Create iptables chain if it doesn't exist."""
        try:
            subprocess.run(['iptables', '-N', self.chain_name], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            pass  # Chain might already exist
        try:
            subprocess.run(['iptables', '-C', 'INPUT', '-j', self.chain_name], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            subprocess.run(['iptables', '-I', 'INPUT', '-j', self.chain_name], capture_output=True, check=True)

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.whitelist:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except ValueError:
            pass
        return False

    def block_ip(self, ip: str, reason: str, duration_seconds: Optional[int] = None) -> bool:
        """Block an IP address."""
        if not self.enabled:
            print("Blocker disabled, skipping block")
            return False

        if self._is_whitelisted(ip):
            print(f"IP {ip} is whitelisted, not blocking")
            return False

        with self.lock:
            if ip in self.blocked_ips and self.blocked_ips[ip].active:
                print(f"IP {ip} already blocked")
                return True

            if duration_seconds is None:
                duration_seconds = self.default_duration

            expires_at = datetime.now() + timedelta(seconds=duration_seconds) if duration_seconds > 0 else None

            # Add firewall rule
            rule_handle = self._add_firewall_rule(ip)
            if rule_handle is None:
                return False

            blocked = BlockedIP(
                ip=ip,
                reason=reason,
                blocked_at=datetime.now(),
                expires_at=expires_at,
                rule_handle=rule_handle,
                active=True
            )
            self.blocked_ips[ip] = blocked
            self._persist_blocks()
            print(f"Blocked IP: {ip} (reason: {reason}, duration: {duration_seconds}s)")
            return True

    def _add_firewall_rule(self, ip: str) -> Optional[str]:
        """Add firewall rule, return rule handle."""
        if self.backend == 'nftables':
            return self._add_nftables_rule(ip)
        else:
            return self._add_iptables_rule(ip)

    def _add_nftables_rule(self, ip: str) -> Optional[str]:
        """Add nftables rule, return handle."""
        try:
            # Add rule and get handle
            result = subprocess.run([
                'nft', 'add', 'rule', self.table_name, self.chain_name,
                'ip', 'saddr', ip, 'drop'
            ], capture_output=True, text=True, check=True)

            # Get the handle of the last added rule
            list_result = subprocess.run([
                'nft', '-a', 'list', 'chain', self.table_name, self.chain_name
            ], capture_output=True, text=True, check=True)

            # Parse handle from output (last line with our IP)
            for line in list_result.stdout.split('\n'):
                if ip in line and 'drop' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'handle':
                            return parts[i + 1]
            return "unknown"
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Failed to add nftables rule: {e}")
            return None

    def _add_iptables_rule(self, ip: str) -> Optional[str]:
        """Add iptables rule."""
        try:
            subprocess.run([
                'iptables', '-A', self.chain_name, '-s', ip, '-j', 'DROP'
            ], check=True, capture_output=True)
            return f"iptables-{ip}"
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Failed to add iptables rule: {e}")
            return None

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        with self.lock:
            if ip not in self.blocked_ips:
                return False

            blocked = self.blocked_ips[ip]
            if not blocked.active:
                return True

            # Remove firewall rule
            success = self._remove_firewall_rule(blocked)
            if success:
                blocked.active = False
                self._persist_blocks()
                print(f"Unblocked IP: {ip}")
                return True
            return False

    def _remove_firewall_rule(self, blocked: BlockedIP) -> bool:
        """Remove firewall rule."""
        if self.backend == 'nftables':
            return self._remove_nftables_rule(blocked)
        else:
            return self._remove_iptables_rule(blocked)

    def _remove_nftables_rule(self, blocked: BlockedIP) -> bool:
        """Remove nftables rule by handle."""
        try:
            if blocked.rule_handle and blocked.rule_handle != "unknown":
                subprocess.run([
                    'nft', 'delete', 'rule', self.table_name, self.chain_name,
                    'handle', blocked.rule_handle
                ], check=True, capture_output=True)
            else:
                # Fallback: delete by IP match
                result = subprocess.run([
                    'nft', '-a', 'list', 'chain', self.table_name, self.chain_name
                ], capture_output=True, text=True, check=True)

                for line in result.stdout.split('\n'):
                    if blocked.ip in line and 'drop' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'handle':
                                subprocess.run([
                                    'nft', 'delete', 'rule', self.table_name, self.chain_name,
                                    'handle', parts[i + 1]
                                ], check=True, capture_output=True)
                                break
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Failed to remove nftables rule: {e}")
            return False

    def _remove_iptables_rule(self, blocked: BlockedIP) -> bool:
        """Remove iptables rule."""
        try:
            subprocess.run([
                'iptables', '-D', self.chain_name, '-s', blocked.ip, '-j', 'DROP'
            ], check=True, capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Failed to remove iptables rule: {e}")
            return False

    def check_expired_blocks(self):
        """Check and unblock expired IPs."""
        if not self.auto_unblock:
            return

        now = datetime.now()
        with self.lock:
            expired = [
                ip for ip, blocked in self.blocked_ips.items()
                if blocked.active and blocked.expires_at and blocked.expires_at <= now
            ]
            for ip in expired:
                self.unblock_ip(ip)

    def get_blocked_ips(self) -> List[BlockedIP]:
        """Get all currently blocked IPs."""
        with self.lock:
            return [b for b in self.blocked_ips.values() if b.active]

    def get_all_blocks(self) -> List[BlockedIP]:
        """Get all blocks including expired."""
        with self.lock:
            return list(self.blocked_ips.values())

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        with self.lock:
            blocked = self.blocked_ips.get(ip)
            return blocked is not None and blocked.active

    def _persist_blocks(self):
        """Persist blocked IPs to disk."""
        persist_file = Path(self.config['general']['blocked_ips_dir']) / 'blocked_ips.json'
        persist_file.parent.mkdir(parents=True, exist_ok=True)
        data = {ip: blocked.to_dict() for ip, blocked in self.blocked_ips.items()}
        with open(persist_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _load_persisted_blocks(self):
        """Load persisted blocks and re-apply firewall rules."""
        persist_file = Path(self.config['general']['blocked_ips_dir']) / 'blocked_ips.json'
        if not persist_file.exists():
            return

        try:
            with open(persist_file, 'r') as f:
                data = json.load(f)

            for ip, block_data in data.items():
                blocked = BlockedIP(
                    ip=block_data['ip'],
                    reason=block_data['reason'],
                    blocked_at=datetime.fromisoformat(block_data['blocked_at']),
                    expires_at=datetime.fromisoformat(block_data['expires_at']) if block_data['expires_at'] else None,
                    rule_handle=block_data['rule_handle'],
                    active=block_data['active']
                )
                self.blocked_ips[ip] = blocked

                # Re-apply rule if still active and not expired
                if blocked.active:
                    if blocked.expires_at and blocked.expires_at <= datetime.now():
                        blocked.active = False
                    else:
                        self._add_firewall_rule(ip)
        except Exception as e:
            print(f"Failed to load persisted blocks: {e}")


def get_blocker() -> IPBlocker:
    """Get singleton blocker instance."""
    if not hasattr(get_blocker, '_instance'):
        get_blocker._instance = IPBlocker()
    return get_blocker._instance