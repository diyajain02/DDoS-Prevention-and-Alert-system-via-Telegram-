"""Detection engine for Light-SOC - correlates log entries into incidents."""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import threading

from src.models import LogEntry, Severity, IncidentType
from src.config_loader import get_config


@dataclass
class IPActivity:
    """Track activity for a single IP address"""
    ip: str
    failed_attempts: List[LogEntry] = field(default_factory=list)
    accepted_attempts: List[LogEntry] = field(default_factory=list)
    invalid_users: List[LogEntry] = field(default_factory=list)
    root_attempts: List[LogEntry] = field(default_factory=list)
    unique_usernames: Set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def add_entry(self, entry: LogEntry):
        self.last_seen = entry.timestamp
        if self.first_seen is None:
            self.first_seen = entry.timestamp

        if entry.source_ip != self.ip:
            return

        if entry.username:
            self.unique_usernames.add(entry.username)

        if entry.event_type in ('failed_password', 'failed_publickey', 'pam_auth_failure'):
            self.failed_attempts.append(entry)
        elif entry.event_type == 'accepted_password':
            self.accepted_attempts.append(entry)
        elif entry.event_type == 'invalid_user':
            self.invalid_users.append(entry)

        if entry.username == 'root':
            self.root_attempts.append(entry)

    def get_recent_failures(self, window_seconds: int) -> List[LogEntry]:
        """Get failed attempts within time window."""
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        return [e for e in self.failed_attempts if e.timestamp >= cutoff]

    def get_recent_invalid_users(self, window_seconds: int) -> List[LogEntry]:
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        return [e for e in self.invalid_users if e.timestamp >= cutoff]

    def get_recent_root_attempts(self, window_seconds: int) -> List[LogEntry]:
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        return [e for e in self.root_attempts if e.timestamp >= cutoff]


class DetectionEngine:
    """Correlates log entries and detects attack patterns."""

    def __init__(self):
        self.config = get_config()
        self.ip_activities: Dict[str, IPActivity] = {}
        self.lock = threading.Lock()
        self.detected_incidents: List[Tuple[str, str]] = []  # (ip, incident_type)
        self._load_rules()

    def _load_rules(self):
        """Load detection rules from config."""
        rules = self.config.get('rules', {})
        self.ssh_bruteforce_config = rules.get('ssh_bruteforce', {})
        self.ssh_invalid_user_config = rules.get('ssh_invalid_user', {})
        self.ssh_root_login_config = rules.get('ssh_root_login_attempt', {})

    def process_entry(self, entry: LogEntry) -> List[str]:
        """Process a log entry, return list of triggered rule names."""
        if not entry.source_ip:
            return []

        triggered = []
        with self.lock:
            if entry.source_ip not in self.ip_activities:
                self.ip_activities[entry.source_ip] = IPActivity(ip=entry.source_ip)

            activity = self.ip_activities[entry.source_ip]
            activity.add_entry(entry)

            # Check SSH brute-force rule
            if self.ssh_bruteforce_config.get('enabled', True):
                if self._check_bruteforce(activity):
                    triggered.append('ssh_bruteforce')

            # Check invalid user enumeration
            if self.ssh_invalid_user_config.get('enabled', True):
                if self._check_invalid_user_enum(activity):
                    triggered.append('ssh_invalid_user')

            # Check root login attempts
            if self.ssh_root_login_config.get('enabled', True):
                if self._check_root_login(activity):
                    triggered.append('ssh_root_login_attempt')

        return triggered

    def _check_bruteforce(self, activity: IPActivity) -> bool:
        """Check for SSH brute-force pattern."""
        config = self.ssh_bruteforce_config
        max_failures = config.get('max_failures', 5)
        window = config.get('time_window_seconds', 300)

        recent_failures = activity.get_recent_failures(window)
        if len(recent_failures) >= max_failures:
            # Check if we already reported this
            incident_key = f"{activity.ip}:ssh_bruteforce"
            if incident_key not in self.detected_incidents:
                self.detected_incidents.append(incident_key)
                return True
        return False

    def _check_invalid_user_enum(self, activity: IPActivity) -> bool:
        """Check for invalid user enumeration."""
        config = self.ssh_invalid_user_config
        max_attempts = config.get('max_attempts', 10)
        window = config.get('time_window_seconds', 600)

        recent_invalid = activity.get_recent_invalid_users(window)
        if len(recent_invalid) >= max_attempts:
            incident_key = f"{activity.ip}:ssh_invalid_user"
            if incident_key not in self.detected_incidents:
                self.detected_incidents.append(incident_key)
                return True
        return False

    def _check_root_login(self, activity: IPActivity) -> bool:
        """Check for root login attempts."""
        config = self.ssh_root_login_config
        max_attempts = config.get('max_attempts', 3)
        window = config.get('time_window_seconds', 300)

        recent_root = activity.get_recent_root_attempts(window)
        if len(recent_root) >= max_attempts:
            incident_key = f"{activity.ip}:ssh_root_login_attempt"
            if incident_key not in self.detected_incidents:
                self.detected_incidents.append(incident_key)
                return True
        return False

    def get_incident_data(self, ip: str, incident_type: str) -> Dict:
        """Gather all relevant data for an incident."""
        with self.lock:
            activity = self.ip_activities.get(ip)
            if not activity:
                return {}

            config_map = {
                'ssh_bruteforce': self.ssh_bruteforce_config,
                'ssh_invalid_user': self.ssh_invalid_user_config,
                'ssh_root_login_attempt': self.ssh_root_login_config,
            }
            config = config_map.get(incident_type, {})
            window = config.get('time_window_seconds', 300)

            # Determine relevant entries based on incident type
            if incident_type == 'ssh_bruteforce':
                relevant_entries = activity.get_recent_failures(window)
            elif incident_type == 'ssh_invalid_user':
                relevant_entries = activity.get_recent_invalid_users(window)
            elif incident_type == 'ssh_root_login_attempt':
                relevant_entries = activity.get_recent_root_attempts(window)
            else:
                relevant_entries = activity.failed_attempts[-50:]  # fallback

            # Check for successful login after failures
            successful = len(activity.accepted_attempts) > 0
            if successful:
                # Check if success happened after failures
                last_failure = activity.failed_attempts[-1].timestamp if activity.failed_attempts else None
                first_success = activity.accepted_attempts[0].timestamp if activity.accepted_attempts else None
                if last_failure and first_success and first_success > last_failure:
                    successful = True
                else:
                    successful = False

            return {
                'ip': ip,
                'incident_type': incident_type,
                'entries': relevant_entries,
                'all_failed': activity.failed_attempts,
                'all_accepted': activity.accepted_attempts,
                'all_invalid_users': activity.invalid_users,
                'all_root_attempts': activity.root_attempts,
                'unique_usernames': list(activity.unique_usernames),
                'successful': successful,
                'first_seen': activity.first_seen,
                'last_seen': activity.last_seen,
                'config': config,
            }

    def cleanup_old_activities(self, max_age_seconds: int = 86400):
        """Remove IP activities older than max_age_seconds."""
        cutoff = datetime.now() - timedelta(seconds=max_age_seconds)
        with self.lock:
            to_remove = []
            for ip, activity in self.ip_activities.items():
                if activity.last_seen and activity.last_seen < cutoff:
                    to_remove.append(ip)
            for ip in to_remove:
                del self.ip_activities[ip]

            # Also clean up detected incidents for removed IPs
            self.detected_incidents = [
                inc for inc in self.detected_incidents
                if not any(inc.startswith(ip + ':') for ip in to_remove)
            ]