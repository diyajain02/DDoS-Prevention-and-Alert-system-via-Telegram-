"""Alerting System for Light-SOC.

Supports multiple notification channels:
- Webhook (generic HTTP POST)
- Email (SMTP)
- Telegram Bot
- Extensible for other channels
"""

import logging
import smtplib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Callable, Any
import json
import requests

from src.config_loader import get_config
from src.ddos_detector import DDoSIncident, DDoSAttackType, DDoSSeverity

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Alert data structure."""
    id: str
    title: str
    message: str
    severity: str
    source: str
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None


class AlertManager:
    """Manages alerting across multiple channels."""

    def __init__(self):
        self.config = get_config()
        alerting_config = self.config.get('alerting', {})
        self.enabled = alerting_config.get('enabled', True)

        # Channel configs
        self.webhook_config = alerting_config.get('webhook', {})
        self.email_config = alerting_config.get('email', {})
        self.telegram_config = alerting_config.get('telegram', {})

        # Alert thresholds
        self.min_severity = alerting_config.get('min_severity', 'MEDIUM')
        self.cooldown_seconds = alerting_config.get('cooldown_seconds', 300)

        # Severity order for comparison
        self.severity_order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

        # Cooldown tracking (ip+type -> last_alert_time)
        self.alert_cooldown: Dict[str, datetime] = {}
        self.cooldown_lock = threading.Lock()

        # Alert history
        self.alert_history: List[Alert] = []
        self.history_lock = threading.Lock()
        self.max_history = 10000

        # Callbacks
        self.on_alert_callback: Optional[Callable[[Alert], None]] = None

        # Background thread for cooldown cleanup
        self.running = False
        self.cleanup_thread: Optional[threading.Thread] = None

    def start(self):
        """Start the alert manager."""
        if self.running:
            return

        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        logger.info("Alert Manager started")

    def stop(self):
        """Stop the alert manager."""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        logger.info("Alert Manager stopped")

    def _cleanup_loop(self):
        """Clean up old cooldown entries."""
        while self.running:
            time.sleep(60)
            if not self.running:
                break

            now = datetime.now()
            cutoff = now - timedelta(seconds=self.cooldown_seconds * 2)

            with self.cooldown_lock:
                to_remove = [
                    key for key, last_time in self.alert_cooldown.items()
                    if last_time < cutoff
                ]
                for key in to_remove:
                    del self.alert_cooldown[key]

    def _should_alert(self, severity: str) -> bool:
        """Check if severity meets minimum threshold."""
        return self.severity_order.get(severity, 0) >= self.severity_order.get(self.min_severity, 2)

    def _check_cooldown(self, key: str) -> bool:
        """Check if alert is in cooldown."""
        with self.cooldown_lock:
            if key in self.alert_cooldown:
                elapsed = (datetime.now() - self.alert_cooldown[key]).total_seconds()
                if elapsed < self.cooldown_seconds:
                    return False
            self.alert_cooldown[key] = datetime.now()
            return True

    def send_ddos_alert(self, incident: DDoSIncident):
        """Send alert for a DDoS incident."""
        if not self.enabled:
            return

        if not self._should_alert(incident.severity.value):
            return

        # Create cooldown key
        cooldown_key = f"ddos_{incident.attacker_ip}_{incident.attack_type.value}"
        if not self._check_cooldown(cooldown_key):
            logger.debug(f"Alert for {cooldown_key} in cooldown, skipping")
            return

        # Build alert
        alert = Alert(
            id=f"ddos_{incident.attacker_ip}_{incident.attack_type.value}_{int(time.time())}",
            title=f"DDoS Attack Detected: {incident.attack_type.value.replace('_', ' ').title()}",
            message=self._format_ddos_message(incident),
            severity=incident.severity.value,
            source="ddos_detector",
            timestamp=datetime.now(),
            details={
                'attacker_ip': incident.attacker_ip,
                'attack_type': incident.attack_type.value,
                'peak_pps': incident.peak_pps,
                'peak_bps': incident.peak_bps,
                'total_packets': incident.total_packets,
                'total_bytes': incident.total_bytes,
                'blocked': incident.blocked,
                'confidence': incident.confidence,
                'details': incident.details,
            }
        )

        self._send_alert(alert)

    def _format_ddos_message(self, incident: DDoSIncident) -> str:
        """Format DDoS incident into human-readable message."""
        blocked_status = "✅ BLOCKED" if incident.blocked else "⚠️ NOT BLOCKED"
        confidence_pct = f"{incident.confidence:.0%}"

        message = f"""🚨 <b>DDoS Attack Detected</b> 🚨

<b>Attack Type:</b> {incident.attack_type.value.replace('_', ' ').title()}
<b>Attacker IP:</b> <code>{incident.attacker_ip}</code>
<b>Severity:</b> {incident.severity.value}
<b>Status:</b> {blocked_status}
<b>Confidence:</b> {confidence_pct}

<b>Peak Traffic:</b>
  • Packets/sec: {incident.peak_pps:,}
  • Bandwidth: {self._format_bytes(incident.peak_bps)}/s

<b>Total Volume:</b>
  • Packets: {incident.total_packets:,}
  • Data: {self._format_bytes(incident.total_bytes)}

<b>Started:</b> {incident.started_at.strftime('%Y-%m-%d %H:%M:%S')}
<b>Last Seen:</b> {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S')}"""

        if incident.details:
            message += "\n\n<b>Details:</b>"
            for key, value in incident.details.items():
                message += f"\n  • {key}: {value}"

        return message

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes into human readable."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} PB"

    def _send_alert(self, alert: Alert):
        """Send alert through all enabled channels."""
        # Store in history
        with self.history_lock:
            self.alert_history.append(alert)
            if len(self.alert_history) > self.max_history:
                self.alert_history = self.alert_history[-self.max_history:]

        # Send via webhook
        if self.webhook_config.get('enabled', False):
            self._send_webhook(alert)

        # Send via email
        if self.email_config.get('enabled', False):
            self._send_email(alert)

        # Send via Telegram
        if self.telegram_config.get('enabled', False):
            self._send_telegram(alert)

        # Trigger callback
        if self.on_alert_callback:
            try:
                self.on_alert_callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _send_webhook(self, alert: Alert):
        """Send alert via webhook."""
        url = self.webhook_config.get('url')
        if not url:
            return

        timeout = self.webhook_config.get('timeout', 10)
        retry_count = self.webhook_config.get('retry_count', 3)

        payload = {
            'id': alert.id,
            'title': alert.title,
            'message': alert.message,
            'severity': alert.severity,
            'source': alert.source,
            'timestamp': alert.timestamp.isoformat(),
            'details': alert.details,
        }

        for attempt in range(retry_count):
            try:
                response = requests.post(
                    url,
                    json=payload,
                    timeout=timeout,
                    headers={'Content-Type': 'application/json'}
                )
                response.raise_for_status()
                logger.info(f"Webhook alert sent successfully: {alert.id}")
                return
            except Exception as e:
                logger.warning(f"Webhook attempt {attempt + 1} failed: {e}")
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff

        logger.error(f"Failed to send webhook alert after {retry_count} attempts: {alert.id}")

    def _send_email(self, alert: Alert):
        """Send alert via email."""
        smtp_host = self.email_config.get('smtp_host')
        smtp_port = self.email_config.get('smtp_port', 587)
        username = self.email_config.get('username')
        password = self.email_config.get('password')
        from_email = self.email_config.get('from_email')
        to_emails = self.email_config.get('to_emails', [])
        use_tls = self.email_config.get('use_tls', True)

        if not all([smtp_host, username, password, from_email, to_emails]):
            logger.warning("Email config incomplete, skipping email alert")
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ', '.join(to_emails)
            msg['Subject'] = f"[{alert.severity}] {alert.title}"

            # HTML body
            html_body = f"""
            <html>
            <body>
                <h2 style="color: {'red' if alert.severity in ('HIGH', 'CRITICAL') else 'orange'};">{alert.title}</h2>
                <p><strong>Severity:</strong> {alert.severity}</p>
                <p><strong>Source:</strong> {alert.source}</p>
                <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                <pre>{alert.message}</pre>
                <hr>
                <p><small>Alert ID: {alert.id}</small></p>
            </body>
            </html>
            """
            msg.attach(MIMEText(html_body, 'html'))

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if use_tls:
                    server.starttls()
                server.login(username, password)
                server.send_message(msg)

            logger.info(f"Email alert sent: {alert.id}")

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def _send_telegram(self, alert: Alert):
        """Send alert via Telegram bot."""
        bot_token = self.telegram_config.get('bot_token')
        chat_id = self.telegram_config.get('chat_id')
        parse_mode = self.telegram_config.get('parse_mode', 'HTML')

        if not bot_token or not chat_id:
            logger.warning("Telegram config incomplete, skipping Telegram alert")
            return

        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

            # Escape HTML for Telegram
            message = alert.message.replace('<', '<').replace('>', '>')
            # Re-add our intentional HTML tags
            message = message.replace('<b>', '<b>').replace('</b>', '</b>')
            message = message.replace('<code>', '<code>').replace('</code>', '</code>')
            message = message.replace('<pre>', '<pre>').replace('</pre>', '</pre>')

            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': parse_mode,
                'disable_web_page_preview': True,
            }

            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()

            logger.info(f"Telegram alert sent: {alert.id}")

        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")

    def send_custom_alert(self, title: str, message: str, severity: str,
                          source: str = "custom", details: Dict = None):
        """Send a custom alert."""
        if not self.enabled:
            return

        if not self._should_alert(severity):
            return

        alert = Alert(
            id=f"custom_{source}_{int(time.time())}",
            title=title,
            message=message,
            severity=severity,
            source=source,
            timestamp=datetime.now(),
            details=details or {},
        )

        self._send_alert(alert)

    def get_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> List[Alert]:
        """Get recent alerts."""
        with self.history_lock:
            alerts = list(self.alert_history)
            if unacknowledged_only:
                alerts = [a for a in alerts if not a.acknowledged]
            return alerts[-limit:]

    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        with self.history_lock:
            for alert in self.alert_history:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    alert.acknowledged_by = user
                    alert.acknowledged_at = datetime.now()
                    return True
        return False

    def get_stats(self) -> Dict:
        """Get alerting statistics."""
        with self.history_lock:
            total = len(self.alert_history)
            unacked = len([a for a in self.alert_history if not a.acknowledged])
            by_severity = {}
            for alert in self.alert_history:
                by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

        return {
            'total_alerts': total,
            'unacknowledged': unacked,
            'by_severity': by_severity,
            'channels': {
                'webhook': self.webhook_config.get('enabled', False),
                'email': self.email_config.get('enabled', False),
                'telegram': self.telegram_config.get('enabled', False),
            },
            'min_severity': self.min_severity,
            'cooldown_seconds': self.cooldown_seconds,
        }

    def set_alert_callback(self, callback: Callable[[Alert], None]):
        """Set callback for alert notifications."""
        self.on_alert_callback = callback


def get_alert_manager() -> AlertManager:
    """Get singleton alert manager instance."""
    if not hasattr(get_alert_manager, '_instance'):
        get_alert_manager._instance = AlertManager()
    return get_alert_manager._instance