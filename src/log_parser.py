"""SSH auth.log parser for Light-SOC."""
import re
from datetime import datetime
from typing import Optional, List, Dict, Any
from src.models import LogEntry, Severity


# Regex patterns for common SSH log formats
SSH_PATTERNS = [
    # Failed password for user from IP
    re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+'
    ),
    # Accepted password for user from IP
    re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+'
    ),
    # Invalid user from IP
    re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+'
    ),
    # Failed publickey for user from IP
    re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Failed publickey for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+'
    ),
    # Connection closed by IP (pre-auth)
    re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Connection closed by (?P<ip>\S+) port \d+ \[preauth\]'
    ),
    # Received disconnect from IP
    re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Received disconnect from (?P<ip>\S+) port \d+:'
    ),
    # pam_unix(sshd:auth): authentication failure
    re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'pam_unix\(sshd:auth\): authentication failure; logname=\S* uid=\d+ euid=\d+ tty=\S+ ruser=\S* rhost=(?P<ip>\S+) user=(?P<user>\S+)'
    ),
]


def parse_timestamp(ts_str: str, year: Optional[int] = None) -> datetime:
    """Parse syslog timestamp (e.g., 'Sep 27 14:30:45') to datetime."""
    if year is None:
        year = datetime.now().year
    # Handle case where day might have leading space
    ts_str = ts_str.strip()
    return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")


def classify_event_type(match: re.Match, pattern_idx: int) -> str:
    """Classify the event type based on which pattern matched."""
    if pattern_idx == 0:
        return "failed_password"
    elif pattern_idx == 1:
        return "accepted_password"
    elif pattern_idx == 2:
        return "invalid_user"
    elif pattern_idx == 3:
        return "failed_publickey"
    elif pattern_idx == 4:
        return "connection_closed_preauth"
    elif pattern_idx == 5:
        return "received_disconnect"
    elif pattern_idx == 6:
        return "pam_auth_failure"
    return "unknown"


def parse_ssh_log_line(line: str, year: Optional[int] = None) -> Optional[LogEntry]:
    """Parse a single SSH auth.log line."""
    line = line.strip()
    if not line or 'sshd' not in line:
        return None

    for idx, pattern in enumerate(SSH_PATTERNS):
        match = pattern.search(line)
        if match:
            groups = match.groupdict()
            timestamp = parse_timestamp(groups['timestamp'], year)
            event_type = classify_event_type(match, idx)

            entry = LogEntry(
                timestamp=timestamp,
                raw_line=line,
                source_ip=groups.get('ip'),
                username=groups.get('user'),
                event_type=event_type,
                details={
                    'host': groups.get('host'),
                    'pid': groups.get('pid'),
                    'pattern_idx': idx,
                }
            )
            return entry

    # If no pattern matched but it's sshd-related, return basic entry
    if 'sshd' in line:
        # Try to extract IP with a generic pattern
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        user_match = re.search(r'user (\S+)', line) or re.search(r'for (\S+) from', line)
        return LogEntry(
            timestamp=datetime.now(),  # fallback
            raw_line=line,
            source_ip=ip_match.group(1) if ip_match else None,
            username=user_match.group(1) if user_match else None,
            event_type="unparsed_sshd",
            details={}
        )

    return None


def parse_log_file(filepath: str, since: Optional[datetime] = None, year: Optional[int] = None) -> List[LogEntry]:
    """Parse entire auth.log file, optionally filtering by timestamp."""
    entries = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                entry = parse_ssh_log_line(line, year)
                if entry and (since is None or entry.timestamp >= since):
                    entries.append(entry)
    except FileNotFoundError:
        print(f"Log file not found: {filepath}")
    except PermissionError:
        print(f"Permission denied reading: {filepath}")
    return entries


def tail_log_file(filepath: str, callback, year: Optional[int] = None):
    """Tail a log file and call callback for each new parsed entry."""
    import time
    with open(filepath, 'r') as f:
        f.seek(0, 2)  # Seek to end
        while True:
            line = f.readline()
            if line:
                entry = parse_ssh_log_line(line, year)
                if entry:
                    callback(entry)
            else:
                time.sleep(0.5)