"""Report generator for Light-SOC - outputs markdown, JSON, and HTML reports."""
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from src.models import IncidentReport, BlockedIP
from src.config_loader import get_config


class ReportGenerator:
    """Generates incident reports in multiple formats."""

    def __init__(self):
        self.config = get_config()
        report_config = self.config.get('reporting', {})
        self.enabled = report_config.get('enabled', True)
        self.formats = report_config.get('formats', ['markdown', 'json'])
        self.reports_dir = Path(self.config['general']['reports_dir'])
        self.retention_days = report_config.get('retention_days', 30)
        self.include_raw_logs = report_config.get('include_raw_logs', True)
        self.max_log_lines = report_config.get('max_log_lines_per_report', 50)

        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, report: IncidentReport) -> Dict[str, str]:
        """Generate report in all configured formats, return paths."""
        if not self.enabled:
            return {}

        timestamp = report.created_at.strftime("%Y%m%d_%H%M%S")
        base_name = f"incident_{report.attacker_ip.replace('.', '_')}_{timestamp}"
        paths = {}

        for fmt in self.formats:
            if fmt == 'markdown':
                paths['markdown'] = self._write_markdown(report, base_name)
            elif fmt == 'json':
                paths['json'] = self._write_json(report, base_name)
            elif fmt == 'html':
                paths['html'] = self._write_html(report, base_name)

        return paths

    def _write_markdown(self, report: IncidentReport, base_name: str) -> str:
        """Write markdown report."""
        filepath = self.reports_dir / f"{base_name}.md"
        content = report.to_markdown()
        filepath.write_text(content)
        return str(filepath)

    def _write_json(self, report: IncidentReport, base_name: str) -> str:
        """Write JSON report."""
        filepath = self.reports_dir / f"{base_name}.json"
        filepath.write_text(report.to_json())
        return str(filepath)

    def _write_html(self, report: IncidentReport, base_name: str) -> str:
        """Write HTML report."""
        filepath = self.reports_dir / f"{base_name}.html"

        severity_colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545',
        }
        color = severity_colors.get(report.severity, '#6c757d')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident Report: {report.incident_type}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .container {{ background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 30px; }}
        .header {{ border-bottom: 2px solid {color}; padding-bottom: 20px; margin-bottom: 20px; }}
        .title {{ font-size: 28px; font-weight: 600; color: #333; margin: 0; }}
        .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px; }}
        .meta-item {{ background: #f8f9fa; padding: 15px; border-radius: 6px; }}
        .meta-label {{ font-size: 12px; text-transform: uppercase; color: #6c757d; font-weight: 600; }}
        .meta-value {{ font-size: 16px; color: #333; margin-top: 4px; }}
        .severity-badge {{ display: inline-block; background: {color}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: 600; font-size: 14px; }}
        .section {{ margin-top: 30px; }}
        .section-title {{ font-size: 18px; font-weight: 600; color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
        .timeline {{ list-style: none; padding: 0; }}
        .timeline-item {{ display: flex; padding: 12px 0; border-bottom: 1px solid #f0f0f0; }}
        .timeline-time {{ min-width: 180px; color: #6c757d; font-family: monospace; font-size: 13px; }}
        .timeline-event {{ font-weight: 600; color: #333; flex: 1; }}
        .timeline-details {{ color: #6c757d; }}
        .mitigation-list {{ padding-left: 20px; }}
        .mitigation-list li {{ margin: 8px 0; color: #333; }}
        .raw-logs {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #6c757d; font-size: 12px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">Incident Report: {report.incident_type}</h1>
            <span class="severity-badge">{report.severity}</span>
        </div>

        <div class="meta">
            <div class="meta-item">
                <div class="meta-label">Attacker IP</div>
                <div class="meta-value">{report.attacker_ip}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Total Attempts</div>
                <div class="meta-value">{report.total_attempts}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Successful</div>
                <div class="meta-value">{'Yes' if report.successful else 'No'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Confidence</div>
                <div class="meta-value">{report.confidence:.0%}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Generated</div>
                <div class="meta-value">{report.created_at.isoformat()}</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Targeted Usernames</h2>
            <p>{', '.join(report.targeted_usernames) if report.targeted_usernames else 'None'}</p>
        </div>

        <div class="section">
            <h2 class="section-title">Timeline of Events</h2>
            <ul class="timeline">
"""

        for t in report.timeline:
            html += f"""                <li class="timeline-item">
                    <span class="timeline-time">{t.timestamp}</span>
                    <span class="timeline-event">{t.event}</span>
                    <span class="timeline-details">{t.details}</span>
                </li>
"""

        html += """            </ul>
        </div>

        <div class="section">
            <h2 class="section-title">Recommended Mitigation</h2>
            <ul class="mitigation-list">
"""

        for m in report.recommended_mitigation:
            html += f"                <li>{m}</li>\n"

        html += """            </ul>
        </div>
"""

        if report.raw_logs and self.include_raw_logs:
            html += f"""        <div class="section">
            <h2 class="section-title">Raw Log Snippets</h2>
            <div class="raw-logs">{"".join(report.raw_logs)}</div>
        </div>
"""

        html += f"""        <div class="footer">
            Generated by Light-SOC — {datetime.now().isoformat()}
        </div>
    </div>
</body>
</html>"""

        filepath.write_text(html)
        return str(filepath)

    def generate_summary_report(self, blocked_ips: List[BlockedIP], incidents: List[IncidentReport]) -> str:
        """Generate a summary report of all blocked IPs and incidents."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = self.reports_dir / f"summary_{timestamp}.md"

        content = f"""# Light-SOC Summary Report

**Generated:** {datetime.now().isoformat()}
**Active Blocks:** {len([b for b in blocked_ips if b.active])}
**Total Incidents:** {len(incidents)}

## Currently Blocked IPs

| IP | Reason | Blocked At | Expires At | Status |
|----|--------|------------|------------|--------|
"""

        for blocked in blocked_ips:
            if blocked.active:
                expires = blocked.expires_at.strftime("%Y-%m-%d %H:%M:%S") if blocked.expires_at else "Permanent"
                content += f"| {blocked.ip} | {blocked.reason} | {blocked.blocked_at.strftime('%Y-%m-%d %H:%M:%S')} | {expires} | Active |\n"

        content += "\n## Recent Incidents\n\n"

        for inc in incidents[-10:]:  # Last 10 incidents
            content += f"### {inc.incident_type} — {inc.attacker_ip}\n"
            content += f"- **Severity:** {inc.severity}\n"
            content += f"- **Attempts:** {inc.total_attempts}\n"
            content += f"- **Successful:** {'Yes' if inc.successful else 'No'}\n"
            content += f"- **Time:** {inc.created_at.isoformat()}\n\n"

        filepath.write_text(content)
        return str(filepath)

    def cleanup_old_reports(self):
        """Remove reports older than retention period."""
        cutoff = datetime.now().timestamp() - (self.retention_days * 86400)
        for report_file in self.reports_dir.glob("*"):
            if report_file.stat().st_mtime < cutoff:
                report_file.unlink()
                print(f"Removed old report: {report_file}")


def get_report_generator() -> ReportGenerator:
    """Get singleton report generator instance."""
    if not hasattr(get_report_generator, '_instance'):
        get_report_generator._instance = ReportGenerator()
    return get_report_generator._instance