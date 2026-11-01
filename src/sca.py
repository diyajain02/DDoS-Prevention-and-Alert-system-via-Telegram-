"""Security Configuration Assessment (SCA) module for Light-SOC.
Scans system settings against security benchmarks (CIS, custom rules)."""
import json
import logging
import os
import pwd
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import grp
import stat

from src.config_loader import get_config
from src.models import LogEntry


logger = logging.getLogger(__name__)


@dataclass
class SCARule:
    """A single security configuration rule."""
    id: str
    title: str
    description: str
    rationale: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # access_control, network, logging, authentication, etc.
    benchmark: str  # CIS, NIST, custom
    benchmark_version: str = ""
    benchmark_control: str = ""
    check_type: str = "command"  # command, file, package, service, kernel_param, user, group
    check_content: Dict[str, Any] = field(default_factory=dict)
    expected_result: Any = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class SCACheckResult:
    """Result of a single SCA check."""
    rule: SCARule
    passed: bool
    actual_result: Any
    expected_result: Any
    timestamp: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None

    def to_log_entry(self) -> LogEntry:
        """Convert to LogEntry for detection engine."""
        details = {
            'rule_id': self.rule.id,
            'title': self.rule.title,
            'severity': self.rule.severity,
            'category': self.rule.category,
            'benchmark': self.rule.benchmark,
            'passed': self.passed,
            'actual_result': str(self.actual_result),
            'expected_result': str(self.expected_result),
            'remediation': self.rule.remediation,
        }
        return LogEntry(
            timestamp=self.timestamp,
            raw_line=f"SCA: {'PASS' if self.passed else 'FAIL'} - {self.rule.id}: {self.rule.title}",
            source_ip="127.0.0.1",
            username="system",
            event_type="sca_check",
            details=details,
        )


@dataclass
class SCAScanResult:
    """Result of a full SCA scan."""
    scan_id: str
    timestamp: datetime
    benchmark: str
    total_checks: int
    passed: int
    failed: int
    errors: int
    critical_failures: int
    high_failures: int
    medium_failures: int
    low_failures: int
    info_failures: int
    results: List[SCACheckResult]


class SCACheckEngine:
    """Executes individual SCA checks."""

    @staticmethod
    def run_check(rule: SCARule) -> SCACheckResult:
        """Run a single SCA check based on its type."""
        try:
            if rule.check_type == 'command':
                return SCACheckEngine._check_command(rule)
            elif rule.check_type == 'file':
                return SCACheckEngine._check_file(rule)
            elif rule.check_type == 'package':
                return SCACheckEngine._check_package(rule)
            elif rule.check_type == 'service':
                return SCACheckEngine._check_service(rule)
            elif rule.check_type == 'kernel_param':
                return SCACheckEngine._check_kernel_param(rule)
            elif rule.check_type == 'user':
                return SCACheckEngine._check_user(rule)
            elif rule.check_type == 'group':
                return SCACheckEngine._check_group(rule)
            elif rule.check_type == 'ssh_config':
                return SCACheckEngine._check_ssh_config(rule)
            elif rule.check_type == 'custom':
                return SCACheckEngine._check_custom(rule)
            else:
                return SCACheckResult(
                    rule=rule,
                    passed=False,
                    actual_result=None,
                    expected_result=rule.expected_result,
                    error=f"Unknown check type: {rule.check_type}",
                )
        except Exception as e:
            logger.error(f"SCA check {rule.id} failed with error: {e}")
            return SCACheckResult(
                rule=rule,
                passed=False,
                actual_result=None,
                expected_result=rule.expected_result,
                error=str(e),
            )

    @staticmethod
    def _check_command(rule: SCARule) -> SCACheckResult:
        """Execute a command and check its output."""
        cmd = rule.check_content.get('command', '')
        expected = rule.expected_result
        match_type = rule.check_content.get('match_type', 'exact')  # exact, contains, regex, exit_code
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()
        
        if match_type == 'exit_code':
            actual = result.returncode
            passed = actual == expected
        elif match_type == 'regex':
            import re
            passed = bool(re.search(expected, output))
            actual = output
        elif match_type == 'contains':
            passed = expected in output
            actual = output
        else:  # exact
            passed = output == expected
            actual = output
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected,
        )

    @staticmethod
    def _check_file(rule: SCARule) -> SCACheckResult:
        """Check file existence, permissions, ownership, content."""
        path = rule.check_content.get('path', '')
        filepath = Path(path)
        
        check_attr = rule.check_content.get('attribute', 'exists')  # exists, permissions, owner, group, content, hash
        expected = rule.expected_result
        
        if not filepath.exists():
            return SCACheckResult(
                rule=rule,
                passed=False,
                actual_result='missing',
                expected_result=expected,
            )
        
        if check_attr == 'exists':
            return SCACheckResult(
                rule=rule,
                passed=True,
                actual_result='exists',
                expected_result=expected,
            )
        
        elif check_attr == 'permissions':
            actual = oct(stat.S_IMODE(filepath.stat().st_mode))
            passed = actual == expected
            
        elif check_attr == 'owner':
            actual = filepath.stat().st_uid
            try:
                actual = pwd.getpwuid(actual).pw_name
            except KeyError:
                pass
            passed = actual == expected
            
        elif check_attr == 'group':
            actual = filepath.stat().st_gid
            try:
                actual = grp.getgrgid(actual).gr_name
            except KeyError:
                pass
            passed = actual == expected
            
        elif check_attr == 'content':
            try:
                actual = filepath.read_text().strip()
                match_type = rule.check_content.get('match_type', 'exact')
                if match_type == 'regex':
                    import re
                    passed = bool(re.search(expected, actual))
                elif match_type == 'contains':
                    passed = expected in actual
                else:
                    passed = actual == expected
            except Exception:
                actual = 'unreadable'
                passed = False
                
        elif check_attr == 'hash':
            import hashlib
            hasher = hashlib.sha256()
            hasher.update(filepath.read_bytes())
            actual = hasher.hexdigest()
            passed = actual == expected
            
        else:
            actual = 'unknown_check'
            passed = False
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected,
        )

    @staticmethod
    def _check_package(rule: SCARule) -> SCACheckResult:
        """Check if a package is installed/not installed/version."""
        package_name = rule.check_content.get('package', '')
        manager = rule.check_content.get('manager', 'auto')
        expected_state = rule.expected_result  # installed, not_installed, version
        
        # Try to detect package
        if manager == 'auto':
            managers = ['apt', 'rpm', 'pacman', 'apk']
        else:
            managers = [manager]
        
        found = False
        version = None
        
        for mgr in managers:
            try:
                if mgr in ('apt', 'dpkg'):
                    result = subprocess.run(
                        ['dpkg-query', '-W', '-f=${Version}', package_name],
                        capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        found = True
                        version = result.stdout.strip()
                        break
                elif mgr in ('rpm', 'yum', 'dnf'):
                    result = subprocess.run(
                        ['rpm', '-q', package_name],
                        capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        found = True
                        version = result.stdout.strip()
                        break
                # Add more managers as needed
            except Exception:
                continue
        
        if expected_state == 'installed':
            passed = found
            actual = f"installed ({version})" if found else "not installed"
        elif expected_state == 'not_installed':
            passed = not found
            actual = f"installed ({version})" if found else "not installed"
        elif isinstance(expected_state, str) and expected_state.startswith('version:'):
            expected_version = expected_state.split(':', 1)[1]
            passed = found and version == expected_version
            actual = f"version {version}" if found else "not installed"
        else:
            passed = False
            actual = 'unknown_state'
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected_state,
        )

    @staticmethod
    def _check_service(rule: SCARule) -> SCACheckResult:
        """Check service status (systemd)."""
        service_name = rule.check_content.get('service', '')
        expected = rule.expected_result  # running, stopped, enabled, disabled
        
        actual = {}
        try:
            # Check active state
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True, text=True
            )
            actual['active'] = result.stdout.strip()
            
            # Check enabled state
            result = subprocess.run(
                ['systemctl', 'is-enabled', service_name],
                capture_output=True, text=True
            )
            actual['enabled'] = result.stdout.strip()
        except Exception:
            pass
        
        if expected == 'running':
            passed = actual.get('active') == 'active'
        elif expected == 'stopped':
            passed = actual.get('active') != 'active'
        elif expected == 'enabled':
            passed = actual.get('enabled') == 'enabled'
        elif expected == 'disabled':
            passed = actual.get('enabled') != 'enabled'
        else:
            passed = False
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected,
        )

    @staticmethod
    def _check_kernel_param(rule: SCARule) -> SCACheckResult:
        """Check kernel parameter value."""
        param = rule.check_content.get('parameter', '')
        expected = rule.expected_result
        
        try:
            result = subprocess.run(
                ['sysctl', '-n', param],
                capture_output=True, text=True, check=True
            )
            actual = result.stdout.strip()
            passed = actual == str(expected)
        except Exception:
            actual = 'unavailable'
            passed = False
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected,
        )

    @staticmethod
    def _check_user(rule: SCARule) -> SCACheckResult:
        """Check user account properties."""
        username = rule.check_content.get('user', '')
        attribute = rule.check_content.get('attribute', 'exists')  # exists, shell, home, uid, locked
        expected = rule.expected_result
        
        try:
            user = pwd.getpwnam(username)
            
            if attribute == 'exists':
                passed = True
                actual = 'exists'
            elif attribute == 'shell':
                actual = user.pw_shell
                passed = actual == expected
            elif attribute == 'home':
                actual = user.pw_dir
                passed = actual == expected
            elif attribute == 'uid':
                actual = user.pw_uid
                passed = actual == expected
            elif attribute == 'locked':
                # Check if account is locked (shell is nologin/false)
                actual = user.pw_shell in ('/usr/sbin/nologin', '/bin/false', '/sbin/nologin')
                passed = actual == expected
            else:
                actual = 'unknown'
                passed = False
                
        except KeyError:
            actual = 'not_found'
            passed = expected == 'not_found' if attribute == 'exists' else False
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected,
        )

    @staticmethod
    def _check_group(rule: SCARule) -> SCACheckResult:
        """Check group properties."""
        groupname = rule.check_content.get('group', '')
        attribute = rule.check_content.get('attribute', 'exists')
        expected = rule.expected_result
        
        try:
            group = grp.getgrnam(groupname)
            
            if attribute == 'exists':
                passed = True
                actual = 'exists'
            elif attribute == 'gid':
                actual = group.gr_gid
                passed = actual == expected
            elif attribute == 'members':
                actual = list(group.gr_mem)
                if isinstance(expected, list):
                    passed = set(actual) == set(expected)
                else:
                    passed = expected in actual
            else:
                actual = 'unknown'
                passed = False
                
        except KeyError:
            actual = 'not_found'
            passed = expected == 'not_found' if attribute == 'exists' else False
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected,
        )

    @staticmethod
    def _check_ssh_config(rule: SCARule) -> SCACheckResult:
        """Check SSH daemon configuration."""
        config_path = rule.check_content.get('path', '/etc/ssh/sshd_config')
        parameter = rule.check_content.get('parameter', '')
        expected = rule.expected_result
        
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            
            # Parse SSH config (simplified - handles key=value, ignores comments)
            actual_value = None
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    if ' ' in line:
                        key, value = line.split(' ', 1)
                        if key.lower() == parameter.lower():
                            actual_value = value.strip()
                            break
            
            if actual_value is None:
                actual = 'not_set'
                passed = False
            else:
                match_type = rule.check_content.get('match_type', 'exact')
                if match_type == 'regex':
                    import re
                    passed = bool(re.search(expected, actual_value))
                elif match_type == 'contains':
                    passed = expected in actual_value
                else:
                    passed = actual_value == expected
                actual = actual_value
                
        except Exception as e:
            actual = f'error: {e}'
            passed = False
        
        return SCACheckResult(
            rule=rule,
            passed=passed,
            actual_result=actual,
            expected_result=expected,
        )

    @staticmethod
    def _check_custom(rule: SCARule) -> SCACheckResult:
        """Run a custom Python function for checking."""
        func_name = rule.check_content.get('function', '')
        # This would allow loading custom check functions
        # For now, return not implemented
        return SCACheckResult(
            rule=rule,
            passed=False,
            actual_result='not_implemented',
            expected_result=rule.expected_result,
            error=f"Custom check function not implemented: {func_name}",
        )


class SCARuleSet:
    """Manages SCA rule sets (CIS, custom)."""

    @staticmethod
    def get_cis_linux_level1_rules() -> List[SCARule]:
        """Get CIS Linux Benchmark Level 1 rules."""
        return [
            # 1.1 Filesystem Configuration
            SCARule(
                id="CIS-1.1.1.1",
                title="Ensure mounting of cramfs filesystems is disabled",
                description="The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems.",
                rationale="Removing support for unneeded filesystem types reduces the local attack surface.",
                severity="MEDIUM",
                category="filesystem",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="1.1.1.1",
                check_type="kernel_param",
                check_content={"parameter": "kernel.modules_disabled"},
                expected_result="1",
                remediation="Add 'install cramfs /bin/true' to /etc/modprobe.d/cramfs.conf",
            ),
            SCARule(
                id="CIS-1.1.1.2",
                title="Ensure mounting of freevxfs filesystems is disabled",
                description="FreeVxFS is a filesystem type for Veritas VxFS.",
                rationale="Removing support for unneeded filesystem types reduces the local attack surface.",
                severity="MEDIUM",
                category="filesystem",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="1.1.1.2",
                check_type="command",
                check_content={"command": "modprobe -n -v freevxfs", "match_type": "contains"},
                expected_result="install /bin/true",
                remediation="Add 'install freevxfs /bin/true' to /etc/modprobe.d/freevxfs.conf",
            ),
            SCARule(
                id="CIS-1.1.1.3",
                title="Ensure mounting of jffs2 filesystems is disabled",
                description="JFFS2 is a log-structured filesystem for flash memory devices.",
                rationale="Removing support for unneeded filesystem types reduces the local attack surface.",
                severity="MEDIUM",
                category="filesystem",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="1.1.1.3",
                check_type="command",
                check_content={"command": "modprobe -n -v jffs2", "match_type": "contains"},
                expected_result="install /bin/true",
                remediation="Add 'install jffs2 /bin/true' to /etc/modprobe.d/jffs2.conf",
            ),
            
            # 1.4 Secure Boot Settings
            SCARule(
                id="CIS-1.4.1",
                title="Ensure bootloader password is set",
                description="Setting the bootloader password prevents unauthorized users from modifying boot parameters.",
                rationale="Bootloader password prevents unauthorized kernel parameter changes.",
                severity="HIGH",
                category="bootloader",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="1.4.1",
                check_type="file",
                check_content={"path": "/boot/grub/grub.cfg", "attribute": "content", "match_type": "contains"},
                expected_result="password_pbkdf2",
                remediation="Generate password with grub-mkpasswd-pbkdf2 and add to /etc/grub.d/40_custom",
            ),
            SCARule(
                id="CIS-1.4.2",
                title="Ensure permissions on bootloader config are configured",
                description="Ensure the bootloader configuration file has secure permissions.",
                rationale="Protect bootloader configuration from unauthorized modification.",
                severity="MEDIUM",
                category="bootloader",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="1.4.2",
                check_type="file",
                check_content={"path": "/boot/grub/grub.cfg", "attribute": "permissions"},
                expected_result="0o600",
                remediation="chmod 600 /boot/grub/grub.cfg",
            ),
            
            # 1.7 Additional Process Hardening
            SCARule(
                id="CIS-1.7.1",
                title="Ensure ASLR is enabled",
                description="Address Space Layout Randomization (ASLR) randomizes memory addresses used by processes.",
                rationale="ASLR makes it more difficult for attackers to predict memory locations.",
                severity="HIGH",
                category="kernel_hardening",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="1.7.1",
                check_type="kernel_param",
                check_content={"parameter": "kernel.randomize_va_space"},
                expected_result="2",
                remediation="Set kernel.randomize_va_space = 2 in /etc/sysctl.d/99-sysctl.conf",
            ),
            
            # 2.1 Services
            SCARule(
                id="CIS-2.1.1",
                title="Ensure chrony is configured",
                description="Chrony is an NTP implementation for time synchronization.",
                rationale="Time synchronization is critical for log correlation and security protocols.",
                severity="MEDIUM",
                category="time_sync",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="2.1.1",
                check_type="service",
                check_content={"service": "chronyd"},
                expected_result="running",
                remediation="Install and enable chrony: systemctl enable --now chronyd",
            ),
            
            # 3.1 Network Parameters
            SCARule(
                id="CIS-3.1.1",
                title="Ensure IP forwarding is disabled",
                description="IP forwarding allows the system to route packets between interfaces.",
                rationale="Disable IP forwarding unless the system is a router.",
                severity="HIGH",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.1.1",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.ip_forward"},
                expected_result="0",
                remediation="Set net.ipv4.ip_forward = 0 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.1.2",
                title="Ensure packet redirect sending is disabled",
                description="ICMP redirects can be used to manipulate routing tables.",
                rationale="Disable sending ICMP redirects to prevent MITM attacks.",
                severity="MEDIUM",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.1.2",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.conf.all.send_redirects"},
                expected_result="0",
                remediation="Set net.ipv4.conf.all.send_redirects = 0 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.1",
                title="Ensure source routed packets are not accepted",
                description="Source routing allows the sender to specify the route packets take.",
                rationale="Disable source routing to prevent routing manipulation.",
                severity="HIGH",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.1",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.conf.all.accept_source_route"},
                expected_result="0",
                remediation="Set net.ipv4.conf.all.accept_source_route = 0 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.2",
                title="Ensure ICMP redirects are not accepted",
                description="ICMP redirects can modify routing tables.",
                rationale="Disable accepting ICMP redirects to prevent routing manipulation.",
                severity="MEDIUM",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.2",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.conf.all.accept_redirects"},
                expected_result="0",
                remediation="Set net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.3",
                title="Ensure secure ICMP redirects are not accepted",
                description="Secure ICMP redirects still allow routing table modification.",
                rationale="Disable secure ICMP redirects.",
                severity="MEDIUM",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.3",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.conf.all.secure_redirects"},
                expected_result="0",
                remediation="Set net.ipv4.conf.all.secure_redirects = 0 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.4",
                title="Ensure suspicious packets are logged",
                description="Log packets with impossible addresses (Martians).",
                rationale="Log martian packets for security monitoring.",
                severity="MEDIUM",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.4",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.conf.all.log_martians"},
                expected_result="1",
                remediation="Set net.ipv4.conf.all.log_martians = 1 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.5",
                title="Ensure broadcast ICMP requests are ignored",
                description="Ignore ICMP echo requests sent to broadcast/multicast addresses.",
                rationale="Prevent SMURF attacks and reduce network noise.",
                severity="MEDIUM",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.5",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.icmp_echo_ignore_broadcasts"},
                expected_result="1",
                remediation="Set net.ipv4.icmp_echo_ignore_broadcasts = 1 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.6",
                title="Ensure bogus ICMP responses are ignored",
                description="Ignore bogus ICMP error responses.",
                rationale="Prevent TCP connection disruption via ICMP.",
                severity="MEDIUM",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.6",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.icmp_ignore_bogus_error_responses"},
                expected_result="1",
                remediation="Set net.ipv4.icmp_ignore_bogus_error_responses = 1 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.7",
                title="Ensure Reverse Path Filtering is enabled",
                description="Reverse path filtering validates source IP of received packets.",
                rationale="Prevent IP spoofing attacks.",
                severity="HIGH",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.7",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.conf.all.rp_filter"},
                expected_result="1",
                remediation="Set net.ipv4.conf.all.rp_filter = 1 in /etc/sysctl.d/99-sysctl.conf",
            ),
            SCARule(
                id="CIS-3.2.8",
                title="Ensure TCP SYN Cookies is enabled",
                description="SYN cookies protect against SYN flood attacks.",
                rationale="Enable SYN cookies for DoS protection.",
                severity="HIGH",
                category="network",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="3.2.8",
                check_type="kernel_param",
                check_content={"parameter": "net.ipv4.tcp_syncookies"},
                expected_result="1",
                remediation="Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.d/99-sysctl.conf",
            ),
            
            # 4.1 Logging
            SCARule(
                id="CIS-4.1.1",
                title="Ensure auditd is installed",
                description="auditd is the userspace component of the Linux Auditing System.",
                rationale="Audit logs are critical for security monitoring.",
                severity="HIGH",
                category="logging",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="4.1.1",
                check_type="package",
                check_content={"package": "auditd", "manager": "apt"},
                expected_result="installed",
                remediation="apt-get install auditd",
            ),
            SCARule(
                id="CIS-4.1.2",
                title="Ensure auditd service is enabled and running",
                description="The auditd service must be running to collect audit logs.",
                rationale="Auditd must be active to capture audit events.",
                severity="HIGH",
                category="logging",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="4.1.2",
                check_type="service",
                check_content={"service": "auditd"},
                expected_result="running",
                remediation="systemctl enable --now auditd",
            ),
            
            # 5.1 SSH Configuration
            SCARule(
                id="CIS-5.1.1",
                title="Ensure SSH Protocol is set to 2",
                description="SSH protocol version 2 is more secure than version 1.",
                rationale="SSHv1 has known vulnerabilities.",
                severity="HIGH",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.1",
                check_type="ssh_config",
                check_content={"parameter": "Protocol"},
                expected_result="2",
                remediation="Set Protocol 2 in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.2",
                title="Ensure SSH LogLevel is set to INFO",
                description="INFO level provides sufficient logging for SSH events.",
                rationale="Verbose logging helps detect brute-force attacks.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.2",
                check_type="ssh_config",
                check_content={"parameter": "LogLevel"},
                expected_result="INFO",
                remediation="Set LogLevel INFO in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.3",
                title="Ensure SSH X11 forwarding is disabled",
                description="X11 forwarding can expose the local X server to attack.",
                rationale="Disable X11 forwarding unless required.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.3",
                check_type="ssh_config",
                check_content={"parameter": "X11Forwarding"},
                expected_result="no",
                remediation="Set X11Forwarding no in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.4",
                title="Ensure SSH MaxAuthTries is set to 4 or less",
                description="Limiting authentication attempts reduces brute-force risk.",
                rationale="Limit failed login attempts.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.4",
                check_type="ssh_config",
                check_content={"parameter": "MaxAuthTries"},
                expected_result="4",
                remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.5",
                title="Ensure SSH IgnoreRhosts is enabled",
                description="Ignore rhosts/shosts files for authentication.",
                rationale="Prevent trust-based authentication bypass.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.5",
                check_type="ssh_config",
                check_content={"parameter": "IgnoreRhosts"},
                expected_result="yes",
                remediation="Set IgnoreRhosts yes in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.6",
                title="Ensure SSH HostbasedAuthentication is disabled",
                description="Host-based authentication is insecure.",
                rationale="Disable host-based authentication.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.6",
                check_type="ssh_config",
                check_content={"parameter": "HostbasedAuthentication"},
                expected_result="no",
                remediation="Set HostbasedAuthentication no in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.7",
                title="Ensure SSH root login is disabled",
                description="Direct root login should be prohibited.",
                rationale="Prevent direct root login; use sudo instead.",
                severity="CRITICAL",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.7",
                check_type="ssh_config",
                check_content={"parameter": "PermitRootLogin"},
                expected_result="no",
                remediation="Set PermitRootLogin no in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.8",
                title="Ensure SSH PermitEmptyPasswords is disabled",
                description="Accounts with empty passwords should not be allowed.",
                rationale="Prevent login with empty passwords.",
                severity="HIGH",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.8",
                check_type="ssh_config",
                check_content={"parameter": "PermitEmptyPasswords"},
                expected_result="no",
                remediation="Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.9",
                title="Ensure SSH PermitUserEnvironment is disabled",
                description="User environment can bypass security controls.",
                rationale="Disable user environment processing.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.9",
                check_type="ssh_config",
                check_content={"parameter": "PermitUserEnvironment"},
                expected_result="no",
                remediation="Set PermitUserEnvironment no in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.10",
                title="Ensure SSH strong ciphers are used",
                description="Only strong encryption ciphers should be allowed.",
                rationale="Weak ciphers can be broken by attackers.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.10",
                check_type="ssh_config",
                check_content={"parameter": "Ciphers"},
                expected_result="aes256-ctr,aes192-ctr,aes128-ctr",
                remediation="Set strong Ciphers in /etc/ssh/sshd_config",
            ),
            SCARule(
                id="CIS-5.1.11",
                title="Ensure SSH strong MAC algorithms are used",
                description="Only strong message authentication codes should be allowed.",
                rationale="Weak MACs can be forged.",
                severity="MEDIUM",
                category="ssh",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.1.11",
                check_type="ssh_config",
                check_content={"parameter": "MACs"},
                expected_result="hmac-sha2-256,hmac-sha2-512",
                remediation="Set strong MACs in /etc/ssh/sshd_config",
            ),
            
            # 5.2 User Accounts
            SCARule(
                id="CIS-5.2.1",
                title="Ensure password expiration is 90 days or less",
                description="Passwords should expire periodically.",
                rationale="Regular password rotation limits exposure from compromised credentials.",
                severity="MEDIUM",
                category="authentication",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.2.1",
                check_type="file",
                check_content={"path": "/etc/login.defs", "attribute": "content", "match_type": "regex"},
                expected_result=r"PASS_MAX_DAYS\s+90",
                remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs",
            ),
            SCARule(
                id="CIS-5.2.2",
                title="Ensure minimum password age is 7 days or more",
                description="Prevent immediate password reuse.",
                rationale="Prevent users from cycling through passwords to bypass history.",
                severity="LOW",
                category="authentication",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.2.2",
                check_type="file",
                check_content={"path": "/etc/login.defs", "attribute": "content", "match_type": "regex"},
                expected_result=r"PASS_MIN_DAYS\s+7",
                remediation="Set PASS_MIN_DAYS 7 in /etc/login.defs",
            ),
            SCARule(
                id="CIS-5.2.3",
                title="Ensure password expiration warning is 7 days or more",
                description="Warn users before password expires.",
                rationale="Give users time to change passwords before expiration.",
                severity="LOW",
                category="authentication",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.2.3",
                check_type="file",
                check_content={"path": "/etc/login.defs", "attribute": "content", "match_type": "regex"},
                expected_result=r"PASS_WARN_AGE\s+7",
                remediation="Set PASS_WARN_AGE 7 in /etc/login.defs",
            ),
            SCARule(
                id="CIS-5.2.4",
                title="Ensure inactive password lock is 30 days or less",
                description="Lock accounts after password expiration.",
                rationale="Prevent use of accounts with expired passwords.",
                severity="MEDIUM",
                category="authentication",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.2.4",
                check_type="file",
                check_content={"path": "/etc/default/useradd", "attribute": "content", "match_type": "regex"},
                expected_result=r"INACTIVE=30",
                remediation="Set INACTIVE=30 in /etc/default/useradd",
            ),
            
            # 5.3 PAM Configuration
            SCARule(
                id="CIS-5.3.1",
                title="Ensure password creation requirements are configured",
                description="Enforce strong passwords via PAM.",
                rationale="Strong passwords resist brute-force and dictionary attacks.",
                severity="HIGH",
                category="authentication",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="5.3.1",
                check_type="file",
                check_content={"path": "/etc/security/pwquality.conf", "attribute": "content", "match_type": "contains"},
                expected_result="minlen = 14",
                remediation="Configure minlen=14, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1 in /etc/security/pwquality.conf",
            ),
            
            # 6.1 File Permissions
            SCARule(
                id="CIS-6.1.1",
                title="Ensure permissions on /etc/passwd are configured",
                description="The /etc/passwd file should be readable by all but writable only by root.",
                rationale="Prevent unauthorized modification of user accounts.",
                severity="MEDIUM",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.1",
                check_type="file",
                check_content={"path": "/etc/passwd", "attribute": "permissions"},
                expected_result="0o644",
                remediation="chmod 644 /etc/passwd",
            ),
            SCARule(
                id="CIS-6.1.2",
                title="Ensure permissions on /etc/shadow are configured",
                description="The /etc/shadow file contains password hashes and must be restricted.",
                rationale="Prevent unauthorized access to password hashes.",
                severity="CRITICAL",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.2",
                check_type="file",
                check_content={"path": "/etc/shadow", "attribute": "permissions"},
                expected_result="0o640",
                remediation="chmod 640 /etc/shadow",
            ),
            SCARule(
                id="CIS-6.1.3",
                title="Ensure permissions on /etc/group are configured",
                description="The /etc/group file should be readable by all but writable only by root.",
                rationale="Prevent unauthorized modification of groups.",
                severity="MEDIUM",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.3",
                check_type="file",
                check_content={"path": "/etc/group", "attribute": "permissions"},
                expected_result="0o644",
                remediation="chmod 644 /etc/group",
            ),
            SCARule(
                id="CIS-6.1.4",
                title="Ensure permissions on /etc/gshadow are configured",
                description="The /etc/gshadow file contains group password hashes.",
                rationale="Prevent unauthorized access to group password hashes.",
                severity="CRITICAL",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.4",
                check_type="file",
                check_content={"path": "/etc/gshadow", "attribute": "permissions"},
                expected_result="0o640",
                remediation="chmod 640 /etc/gshadow",
            ),
            SCARule(
                id="CIS-6.1.5",
                title="Ensure permissions on /etc/passwd- are configured",
                description="Backup of /etc/passwd should be protected.",
                rationale="Prevent unauthorized access to user account backup.",
                severity="MEDIUM",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.5",
                check_type="file",
                check_content={"path": "/etc/passwd-", "attribute": "permissions"},
                expected_result="0o644",
                remediation="chmod 644 /etc/passwd-",
            ),
            SCARule(
                id="CIS-6.1.6",
                title="Ensure permissions on /etc/shadow- are configured",
                description="Backup of /etc/shadow should be protected.",
                rationale="Prevent unauthorized access to password hash backup.",
                severity="CRITICAL",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.6",
                check_type="file",
                check_content={"path": "/etc/shadow-", "attribute": "permissions"},
                expected_result="0o640",
                remediation="chmod 640 /etc/shadow-",
            ),
            SCARule(
                id="CIS-6.1.7",
                title="Ensure permissions on /etc/group- are configured",
                description="Backup of /etc/group should be protected.",
                rationale="Prevent unauthorized access to group backup.",
                severity="MEDIUM",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.7",
                check_type="file",
                check_content={"path": "/etc/group-", "attribute": "permissions"},
                expected_result="0o644",
                remediation="chmod 644 /etc/group-",
            ),
            SCARule(
                id="CIS-6.1.8",
                title="Ensure permissions on /etc/gshadow- are configured",
                description="Backup of /etc/gshadow should be protected.",
                rationale="Prevent unauthorized access to group password hash backup.",
                severity="CRITICAL",
                category="file_permissions",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.1.8",
                check_type="file",
                check_content={"path": "/etc/gshadow-", "attribute": "permissions"},
                expected_result="0o640",
                remediation="chmod 640 /etc/gshadow-",
            ),
            
            # 6.2 User and Group Settings
            SCARule(
                id="CIS-6.2.1",
                title="Ensure no duplicate UIDs exist",
                description="Each user must have a unique UID.",
                rationale="Duplicate UIDs break accountability.",
                severity="HIGH",
                category="user_accounts",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.2.1",
                check_type="command",
                check_content={"command": "cat /etc/passwd | cut -d: -f3 | sort | uniq -d", "match_type": "exact"},
                expected_result="",
                remediation="Investigate and fix duplicate UIDs",
            ),
            SCARule(
                id="CIS-6.2.2",
                title="Ensure no duplicate GIDs exist",
                description="Each group must have a unique GID.",
                rationale="Duplicate GIDs break accountability.",
                severity="HIGH",
                category="user_accounts",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.2.2",
                check_type="command",
                check_content={"command": "cat /etc/group | cut -d: -f3 | sort | uniq -d", "match_type": "exact"},
                expected_result="",
                remediation="Investigate and fix duplicate GIDs",
            ),
            SCARule(
                id="CIS-6.2.3",
                title="Ensure no duplicate user names exist",
                description="Each user must have a unique username.",
                rationale="Duplicate usernames break accountability.",
                severity="HIGH",
                category="user_accounts",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.2.3",
                check_type="command",
                check_content={"command": "cat /etc/passwd | cut -d: -f1 | sort | uniq -d", "match_type": "exact"},
                expected_result="",
                remediation="Investigate and fix duplicate usernames",
            ),
            SCARule(
                id="CIS-6.2.4",
                title="Ensure no duplicate group names exist",
                description="Each group must have a unique name.",
                rationale="Duplicate group names break accountability.",
                severity="HIGH",
                category="user_accounts",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.2.4",
                check_type="command",
                check_content={"command": "cat /etc/group | cut -d: -f1 | sort | uniq -d", "match_type": "exact"},
                expected_result="",
                remediation="Investigate and fix duplicate group names",
            ),
            SCARule(
                id="CIS-6.2.5",
                title="Ensure root PATH integrity",
                description="Root's PATH should not include world-writable directories.",
                rationale="Prevent execution of untrusted binaries as root.",
                severity="HIGH",
                category="root_account",
                benchmark="CIS",
                benchmark_version="2.0.0",
                benchmark_control="6.2.5",
                check_type="command",
                check_content={"command": "echo $PATH | tr ':' '\\n' | while read dir; do [ -d \"$dir\" ] && [ \"$(stat -c %a \"$dir\")\" = \"777\" ] && echo \"$dir\"; done", "match_type": "exact"},
                expected_result="",
                remediation="Remove world-writable directories from root's PATH",
            ),
        ]


class SCAScanner:
    """Main SCA scanner engine."""

    def __init__(self):
        self.config = get_config()
        sca_config = self.config.get('sca', {})
        self.enabled = sca_config.get('enabled', True)
        self.benchmark = sca_config.get('benchmark', 'CIS')
        self.benchmark_version = sca_config.get('benchmark_version', '2.0.0')
        self.scan_interval = sca_config.get('scan_interval_hours', 24)
        self.severity_threshold = sca_config.get('severity_threshold', 'MEDIUM')
        self.custom_rules_path = sca_config.get('custom_rules_path', '')
        
        self.rules: List[SCARule] = []
        self.last_scan: Optional[SCAScanResult] = None
        self.lock = threading.RLock()
        self.running = False
        self.scan_thread: Optional[threading.Thread] = None
        
        self._load_rules()

    def _load_rules(self):
        """Load SCA rules based on configuration."""
        if self.benchmark == 'CIS':
            self.rules = SCARuleSet.get_cis_linux_level1_rules()
        
        # Load custom rules if path specified
        if self.custom_rules_path:
            custom_rules = self._load_custom_rules(self.custom_rules_path)
            self.rules.extend(custom_rules)
        
        logger.info(f"SCA: Loaded {len(self.rules)} rules from {self.benchmark}")

    def _load_custom_rules(self, path: str) -> List[SCARule]:
        """Load custom rules from JSON file."""
        rules = []
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            for rule_data in data.get('rules', []):
                rules.append(SCARule(**rule_data))
        except Exception as e:
            logger.error(f"Failed to load custom SCA rules: {e}")
        return rules

    def scan(self) -> SCAScanResult:
        """Run all SCA checks."""
        logger.info(f"SCA: Starting {self.benchmark} scan")
        start_time = time.time()
        
        results = []
        for rule in self.rules:
            # Filter by severity threshold
            if not self._meets_severity_threshold(rule.severity):
                continue
            
            result = SCACheckEngine.run_check(rule)
            results.append(result)
        
        # Count results
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed and not r.error)
        errors = sum(1 for r in results if r.error)
        
        severity_failures = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for r in results:
            if not r.passed and not r.error:
                severity_failures[r.rule.severity] = severity_failures.get(r.rule.severity, 0) + 1
        
        scan_result = SCAScanResult(
            scan_id=f"sca_scan_{int(time.time())}",
            timestamp=datetime.now(),
            benchmark=self.benchmark,
            total_checks=len(results),
            passed=passed,
            failed=failed,
            errors=errors,
            critical_failures=severity_failures.get('CRITICAL', 0),
            high_failures=severity_failures.get('HIGH', 0),
            medium_failures=severity_failures.get('MEDIUM', 0),
            low_failures=severity_failures.get('LOW', 0),
            info_failures=severity_failures.get('INFO', 0),
            results=results,
        )
        
        with self.lock:
            self.last_scan = scan_result
        
        elapsed = time.time() - start_time
        logger.info(f"SCA: Scan completed in {elapsed:.2f}s")
        logger.info(f"  Total: {scan_result.total_checks}, Passed: {passed}, Failed: {failed}, Errors: {errors}")
        logger.info(f"  Failures by severity: Critical: {scan_result.critical_failures}, High: {scan_result.high_failures}, Medium: {scan_result.medium_failures}, Low: {scan_result.low_failures}")
        
        return scan_result

    def _meets_severity_threshold(self, severity: str) -> bool:
        """Check if severity meets threshold."""
        severity_order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        threshold_level = severity_order.get(self.severity_threshold, 2)
        rule_level = severity_order.get(severity, 2)
        return rule_level >= threshold_level

    def get_sca_alerts_as_log_entries(self) -> List[LogEntry]:
        """Convert failed checks to LogEntry for detection engine."""
        if not self.last_scan:
            return []
        
        entries = []
        for result in self.last_scan.results:
            if not result.passed and not result.error:
                # Only alert on failures above threshold
                if self._meets_severity_threshold(result.rule.severity):
                    entries.append(result.to_log_entry())
        return entries

    def start(self):
        """Start background scanning thread."""
        if self.running:
            return
        
        self.running = True
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        logger.info("SCA: Background scanning started")

    def stop(self):
        """Stop background scanning thread."""
        self.running = False
        if self.scan_thread:
            self.scan_thread.join(timeout=10)
        logger.info("SCA: Background scanning stopped")

    def _scan_loop(self):
        """Background scanning loop."""
        self.scan()
        
        while self.running:
            for _ in range(self.scan_interval * 3600):
                if not self.running:
                    break
                time.sleep(1)
            
            if self.running:
                try:
                    self.scan()
                except Exception as e:
                    logger.error(f"SCA scan error: {e}")

    def get_last_scan(self) -> Optional[SCAScanResult]:
        """Get last scan result."""
        with self.lock:
            return self.last_scan


def get_sca_scanner() -> SCAScanner:
    """Get singleton SCA scanner instance."""
    if not hasattr(get_sca_scanner, '_instance'):
        get_sca_scanner._instance = SCAScanner()
    return get_sca_scanner._instance