"""Light-SOC core data models."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import json


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentType(str, Enum):
    SSH_BRUTEFORCE = "SSH Brute-Force"
    SSH_INVALID_USER = "SSH Invalid User Enumeration"
    SSH_ROOT_LOGIN_ATTEMPT = "SSH Root Login Attempt"
    SSH_SUCCESS_AFTER_FAILURE = "SSH Success After Failures"
    UNKNOWN = "Unknown"


@dataclass
class LogEntry:
    """Parsed log entry from auth.log"""
    timestamp: datetime
    raw_line: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None  # failed, accepted, invalid_user, etc.
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "raw_line": self.raw_line,
            "source_ip": self.source_ip,
            "username": self.username,
            "event_type": self.event_type,
            "details": self.details,
        }


@dataclass
class TimelineEvent:
    timestamp: str
    event: str
    details: str


@dataclass
class IncidentReport:
    """AI-generated incident report"""
    incident_type: str
    severity: str
    attacker_ip: str
    targeted_usernames: List[str]
    timeline: List[TimelineEvent]
    total_attempts: int
    successful: bool
    recommended_mitigation: List[str]
    confidence: float
    created_at: datetime = field(default_factory=datetime.now)
    raw_logs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_type": self.incident_type,
            "severity": self.severity,
            "attacker_ip": self.attacker_ip,
            "targeted_usernames": self.targeted_usernames,
            "timeline": [{"timestamp": t.timestamp, "event": t.event, "details": t.details} for t in self.timeline],
            "total_attempts": self.total_attempts,
            "successful": self.successful,
            "recommended_mitigation": self.recommended_mitigation,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "raw_logs": self.raw_logs,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        md = f"""# Incident Report: {self.incident_type}

**Severity:** {self.severity}  
**Attacker IP:** {self.attacker_ip}  
**Total Attempts:** {self.total_attempts}  
**Successful:** {'Yes' if self.successful else 'No'}  
**Confidence:** {self.confidence:.0%}  
**Generated:** {self.created_at.isoformat()}

## Targeted Usernames
{', '.join(self.targeted_usernames) if self.targeted_usernames else 'None'}

## Timeline of Events
"""
        for t in self.timeline:
            md += f"- **{t.timestamp}** — {t.event}: {t.details}\n"

        md += "\n## Recommended Mitigation\n"
        for m in self.recommended_mitigation:
            md += f"- {m}\n"

        if self.raw_logs:
            md += "\n## Raw Log Snippets\n```\n"
            md += "\n".join(self.raw_logs)
            md += "\n```\n"

        return md


@dataclass
class BlockedIP:
    """Record of a blocked IP"""
    ip: str
    reason: str
    blocked_at: datetime
    expires_at: Optional[datetime] = None
    rule_handle: Optional[str] = None  # nftables rule handle
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rule_handle": self.rule_handle,
            "active": self.active,
        }