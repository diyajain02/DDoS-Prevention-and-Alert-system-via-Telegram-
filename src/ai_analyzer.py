"""AI-powered incident analyzer using Ollama local LLM."""
import json
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
from src.models import IncidentReport, TimelineEvent, LogEntry
from src.config_loader import get_config


class OllamaAnalyzer:
    """Analyze incidents using local Ollama LLM."""

    def __init__(self):
        self.config = get_config()
        ai_config = self.config.get('ai_analyzer', {})
        self.enabled = ai_config.get('enabled', True)
        self.base_url = ai_config.get('base_url', 'http://localhost:11434')
        self.model = ai_config.get('model', 'llama3.1:8b')
        self.timeout = ai_config.get('timeout_seconds', 120)
        self.temperature = ai_config.get('temperature', 0.1)
        self.max_tokens = ai_config.get('max_tokens', 2048)
        self.system_prompt = ai_config.get('system_prompt', '')

    def analyze(self, incident_data: Dict) -> Optional[IncidentReport]:
        """Analyze incident data and generate report."""
        if not self.enabled:
            return self._fallback_analysis(incident_data)

        prompt = self._build_prompt(incident_data)

        try:
            response = self._call_ollama(prompt)
            return self._parse_response(response, incident_data)
        except Exception as e:
            print(f"AI analysis failed: {e}, falling back to rule-based analysis")
            return self._fallback_analysis(incident_data)

    def _build_prompt(self, incident_data: Dict) -> str:
        """Build the prompt for the LLM."""
        entries = incident_data.get('entries', [])
        ip = incident_data.get('ip', 'unknown')
        incident_type = incident_data.get('incident_type', 'unknown')

        # Format log entries for the prompt
        log_lines = []
        for entry in entries:
            log_lines.append(f"[{entry.timestamp.isoformat()}] {entry.raw_line}")

        logs_text = "\n".join(log_lines[-30:])  # Limit to last 30 entries

        prompt = f"""Analyze this SSH attack incident and produce a JSON report.

Attacker IP: {ip}
Incident Type: {incident_type}
Total Failed Attempts: {len(incident_data.get('all_failed', []))}
Total Invalid Users: {len(incident_data.get('all_invalid_users', []))}
Total Root Attempts: {len(incident_data.get('all_root_attempts', []))}
Unique Usernames Targeted: {', '.join(incident_data.get('unique_usernames', []))}
Successful Login After Failures: {incident_data.get('successful', False)}

Raw Log Entries:
{logs_text}

Output ONLY valid JSON matching this schema:
{{
  "incident_type": "string",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "attacker_ip": "string",
  "targeted_usernames": ["string"],
  "timeline": [
    {{"timestamp": "ISO8601", "event": "string", "details": "string"}}
  ],
  "total_attempts": "integer",
  "successful": "boolean",
  "recommended_mitigation": ["string"],
  "confidence": "float (0.0-1.0)"
}}"""
        return prompt

    def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API."""
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": self.system_prompt,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
            "format": "json"
        }

        response = requests.post(url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        return response.json().get('response', '')

    def _parse_response(self, response: str, incident_data: Dict) -> Optional[IncidentReport]:
        """Parse LLM response into IncidentReport."""
        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                try:
                    data = json.loads(response[start:end])
                except json.JSONDecodeError:
                    return self._fallback_analysis(incident_data)
            else:
                return self._fallback_analysis(incident_data)

        # Build timeline events
        timeline = []
        for t in data.get('timeline', []):
            timeline.append(TimelineEvent(
                timestamp=t.get('timestamp', ''),
                event=t.get('event', ''),
                details=t.get('details', '')
            ))

        # Get raw log snippets
        entries = incident_data.get('entries', [])
        raw_logs = [e.raw_line for e in entries[-20:]]

        return IncidentReport(
            incident_type=data.get('incident_type', incident_data.get('incident_type', 'Unknown')),
            severity=data.get('severity', 'MEDIUM'),
            attacker_ip=data.get('attacker_ip', incident_data.get('ip', 'unknown')),
            targeted_usernames=data.get('targeted_usernames', incident_data.get('unique_usernames', [])),
            timeline=timeline,
            total_attempts=data.get('total_attempts', len(incident_data.get('all_failed', []))),
            successful=data.get('successful', incident_data.get('successful', False)),
            recommended_mitigation=data.get('recommended_mitigation', [
                "Block attacker IP at firewall",
                "Enable fail2ban or similar intrusion prevention",
                "Enforce key-based authentication only",
                "Disable root SSH login"
            ]),
            confidence=data.get('confidence', 0.8),
            raw_logs=raw_logs
        )

    def _fallback_analysis(self, incident_data: Dict) -> IncidentReport:
        """Rule-based fallback analysis when AI is unavailable."""
        ip = incident_data.get('ip', 'unknown')
        incident_type = incident_data.get('incident_type', 'unknown')
        entries = incident_data.get('entries', [])
        all_failed = incident_data.get('all_failed', [])
        all_invalid = incident_data.get('all_invalid_users', [])
        all_root = incident_data.get('all_root_attempts', [])
        usernames = incident_data.get('unique_usernames', [])
        successful = incident_data.get('successful', False)

        # Determine severity based on incident type
        severity_map = {
            'ssh_bruteforce': 'HIGH',
            'ssh_invalid_user': 'MEDIUM',
            'ssh_root_login_attempt': 'CRITICAL',
        }
        severity = severity_map.get(incident_type, 'MEDIUM')

        # If successful login after failures, escalate
        if successful:
            severity = 'CRITICAL'

        # Build timeline
        timeline = []
        for entry in entries[-10:]:
            event_map = {
                'failed_password': 'Failed login attempt',
                'accepted_password': 'Successful login',
                'invalid_user': 'Invalid user attempted',
                'failed_publickey': 'Failed publickey auth',
                'pam_auth_failure': 'PAM authentication failure',
            }
            event = event_map.get(entry.event_type, 'SSH event')
            timeline.append(TimelineEvent(
                timestamp=entry.timestamp.isoformat(),
                event=event,
                details=f"User: {entry.username or 'unknown'}"
            ))

        # Basic mitigations
        mitigations = [
            f"Block IP {ip} at firewall (nftables/iptables)",
            "Enable fail2ban for SSH protection",
            "Enforce SSH key-based authentication only",
            "Disable root login (PermitRootLogin no)",
            "Use non-standard SSH port",
            "Implement rate limiting on SSH port"
        ]

        # Incident type display name
        type_display = {
            'ssh_bruteforce': 'SSH Brute-Force Attack',
            'ssh_invalid_user': 'SSH Invalid User Enumeration',
            'ssh_root_login_attempt': 'SSH Root Login Attempt',
        }.get(incident_type, 'SSH Attack')

        raw_logs = [e.raw_line for e in entries[-20:]]

        return IncidentReport(
            incident_type=type_display,
            severity=severity,
            attacker_ip=ip,
            targeted_usernames=usernames,
            timeline=timeline,
            total_attempts=len(all_failed) + len(all_invalid) + len(all_root),
            successful=successful,
            recommended_mitigation=mitigations,
            confidence=0.7,
            raw_logs=raw_logs
        )

    def check_ollama_health(self) -> bool:
        """Check if Ollama is reachable and model is available."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return any(self.model in m.get('name', '') for m in models)
        except Exception:
            pass
        return False


def get_analyzer() -> OllamaAnalyzer:
    """Get singleton analyzer instance."""
    if not hasattr(get_analyzer, '_instance'):
        get_analyzer._instance = OllamaAnalyzer()
    return get_analyzer._instance