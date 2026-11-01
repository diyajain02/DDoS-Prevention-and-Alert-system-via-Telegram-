"""Main Light-SOC daemon - orchestrates log parsing, detection, AI analysis, blocking, and reporting."""
import json
import signal
import sys
import time
import threading
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

from src.config_loader import load_config
from src.log_parser import parse_log_file, tail_log_file, parse_ssh_log_line
from src.detection_engine import DetectionEngine
from src.ai_analyzer import OllamaAnalyzer, get_analyzer
from src.blocker import IPBlocker, get_blocker
from src.report_generator import ReportGenerator, get_report_generator
from src.fim import get_fim_monitor
from src.vulnerability_detector import get_vuln_detector
from src.sca import get_sca_scanner
from src.network_inspection import get_network_monitor
from src.threat_intel import get_threat_intel_manager
from src.ddos_detector import get_ddos_detector, DDoSIncident
from src.alerting import get_alert_manager
from src.models import LogEntry, IncidentReport


class LightSOC:
    """Main Light-SOC daemon."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = load_config(config_path)
        self.running = False
        self.log_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None
        self.module_threads: list[threading.Thread] = []

        # Initialize core components
        self.detection_engine = DetectionEngine()
        self.analyzer = get_analyzer()
        self.report_generator = get_report_generator()

        # Initialize blocker with error handling
        try:
            self.blocker = get_blocker()
        except Exception as e:
            print(f"Warning: Blocker initialization failed: {e}")
            self.blocker = None

        # Initialize extended modules (lazy - only if enabled in config)
        self.fim_monitor = None
        self.vuln_detector = None
        self.sca_scanner = None
        self.network_monitor = None
        self.threat_intel = None
        self.ddos_detector = None
        self.alert_manager = None
        self._init_extended_modules()

        # State
        self.incidents: list[IncidentReport] = []
        self.incidents_lock = threading.Lock()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _init_extended_modules(self):
        """Initialize extended modules based on config."""
        # File Integrity Monitoring
        if self.config.get('fim', {}).get('enabled', True):
            try:
                self.fim_monitor = get_fim_monitor()
                print("FIM module initialized")
            except Exception as e:
                print(f"Warning: FIM initialization failed: {e}")

        # Vulnerability Detection
        if self.config.get('vulnerability_detection', {}).get('enabled', True):
            try:
                self.vuln_detector = get_vuln_detector()
                print("Vulnerability Detection module initialized")
            except Exception as e:
                print(f"Warning: Vulnerability Detection initialization failed: {e}")

        # Security Configuration Assessment
        if self.config.get('sca', {}).get('enabled', True):
            try:
                self.sca_scanner = get_sca_scanner()
                print("SCA module initialized")
            except Exception as e:
                print(f"Warning: SCA initialization failed: {e}")

        # Network Inspection / IPS
        if self.config.get('network_inspection', {}).get('enabled', False):
            try:
                self.network_monitor = get_network_monitor()
                print("Network Inspection/IPS module initialized")
            except Exception as e:
                print(f"Warning: Network Inspection initialization failed: {e}")

        # Threat Intelligence
        if self.config.get('threat_intelligence', {}).get('enabled', True):
            try:
                self.threat_intel = get_threat_intel_manager()
                print("Threat Intelligence module initialized")
            except Exception as e:
                print(f"Warning: Threat Intelligence initialization failed: {e}")

        # DDoS Detection
        if self.config.get('ddos', {}).get('enabled', True):
            try:
                self.ddos_detector = get_ddos_detector()
                # Set up callbacks
                self.ddos_detector.set_incident_callback(self._on_ddos_incident)
                self.ddos_detector.set_block_callback(self._on_ddos_block)
                print("DDoS Detection module initialized")
            except Exception as e:
                print(f"Warning: DDoS Detection initialization failed: {e}")

        # Alerting
        if self.config.get('alerting', {}).get('enabled', True):
            try:
                self.alert_manager = get_alert_manager()
                print("Alerting module initialized")
            except Exception as e:
                print(f"Warning: Alerting initialization failed: {e}")

    def _signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.stop()

    def start(self):
        """Start the Light-SOC daemon."""
        print("Starting Light-SOC...")
        print(f"Config: {self.config['general']['data_dir']}")

        # Check Ollama health
        if self.analyzer.check_ollama_health():
            print(f"Ollama connected: {self.analyzer.model}")
        else:
            print("Warning: Ollama not available, using fallback analysis")

        # Initialize threat intel blocklists in blocker
        self._sync_threat_intel_to_blocker()

        # Initial parse of existing log file
        self._initial_log_parse()

        # Start extended module background threads
        self._start_extended_modules()

        # Start log tailing thread
        self.running = True
        self.log_thread = threading.Thread(target=self._log_tail_loop, daemon=True)
        self.log_thread.start()

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        print("Light-SOC started. Monitoring SSH auth.log...")
        print("Press Ctrl+C to stop.")

        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def _sync_threat_intel_to_blocker(self):
        """Sync threat intelligence blocklists to the IP blocker."""
        if not self.threat_intel or not self.blocker:
            return

        try:
            blocklists = self.threat_intel.get_blocklist_for_blocker()
            ips = blocklists.get('ips', [])
            print(f"Syncing {len(ips)} threat intelligence IPs to blocker...")
            for ip in ips:
                if not self.blocker.is_blocked(ip):
                    self.blocker.block_ip(ip, "Threat Intelligence blocklist", 86400)  # 24 hours
        except Exception as e:
            print(f"Warning: Failed to sync threat intel to blocker: {e}")

    def _start_extended_modules(self):
        """Start background threads for extended modules."""
        # FIM
        if self.fim_monitor:
            # Initialize baseline on first run
            if not self.fim_monitor.baselines:
                print("Initializing FIM baseline...")
                self.fim_monitor.initialize_baseline()
            self.fim_monitor.start()
            self.module_threads.append(threading.Thread(target=self._fim_loop, daemon=True))

        # Vulnerability Detection
        if self.vuln_detector:
            self.vuln_detector.start()
            self.module_threads.append(threading.Thread(target=self._vuln_loop, daemon=True))

        # SCA
        if self.sca_scanner:
            self.sca_scanner.start()
            self.module_threads.append(threading.Thread(target=self._sca_loop, daemon=True))

        # Network Inspection
        if self.network_monitor:
            self.network_monitor.start()
            # Note: Real packet capture would need a separate thread with raw sockets

        # Threat Intelligence
        if self.threat_intel:
            self.threat_intel.start()

        # DDoS Detection
        if self.ddos_detector:
            self.ddos_detector.start()
            self.module_threads.append(threading.Thread(target=self._ddos_loop, daemon=True))

        # Alerting
        if self.alert_manager:
            self.alert_manager.start()

        # Start all module threads
        for t in self.module_threads:
            t.start()

    def _fim_loop(self):
        """Background loop to process FIM alerts."""
        while self.running:
            time.sleep(60)  # Check every minute
            if not self.running or not self.fim_monitor:
                break

            try:
                if self.config.get('integration', {}).get('fim_to_detection', True):
                    alerts = self.fim_monitor.get_alerts_as_log_entries()
                    for entry in alerts:
                        self._process_entry(entry)
            except Exception as e:
                print(f"FIM loop error: {e}")

    def _vuln_loop(self):
        """Background loop to process vulnerability alerts."""
        while self.running:
            time.sleep(3600)  # Check every hour
            if not self.running or not self.vuln_detector:
                break

            try:
                if self.config.get('integration', {}).get('vuln_to_detection', True):
                    alerts = self.vuln_detector.get_vuln_alerts_as_log_entries()
                    for entry in alerts:
                        self._process_entry(entry)
            except Exception as e:
                print(f"Vuln loop error: {e}")

    def _sca_loop(self):
        """Background loop to process SCA alerts."""
        while self.running:
            time.sleep(3600)  # Check every hour
            if not self.running or not self.sca_scanner:
                break

            try:
                if self.config.get('integration', {}).get('sca_to_detection', True):
                    alerts = self.sca_scanner.get_sca_alerts_as_log_entries()
                    for entry in alerts:
                        self._process_entry(entry)
            except Exception as e:
                print(f"SCA loop error: {e}")

    def _ddos_loop(self):
        """Background loop to monitor DDoS detector status."""
        while self.running:
            time.sleep(30)  # Check every 30 seconds
            if not self.running or not self.ddos_detector:
                break

            try:
                stats = self.ddos_detector.get_stats()
                if stats['active_incidents'] > 0:
                    print(f"[DDoS] Active incidents: {stats['active_incidents']}, "
                          f"Blocked IPs: {stats['ips_blocked']}")
            except Exception as e:
                print(f"DDoS loop error: {e}")

    def _on_ddos_incident(self, incident: DDoSIncident):
        """Callback when DDoS incident is detected."""
        print(f"\n{'='*60}")
        print(f"DDoS INCIDENT: {incident.attack_type.value}")
        print(f"{'='*60}")
        print(f"Attacker IP: {incident.attacker_ip}")
        print(f"Severity: {incident.severity.value}")
        print(f"Peak PPS: {incident.peak_pps:,}")
        print(f"Peak BPS: {incident.peak_bps:,} bytes/s")
        print(f"Confidence: {incident.confidence:.0%}")
        print(f"Blocked: {'Yes' if incident.blocked else 'No'}")
        print(f"{'='*60}\n")

        # Send alert via alert manager
        if self.alert_manager:
            self.alert_manager.send_ddos_alert(incident)

    def _on_ddos_block(self, ip: str, reason: str):
        """Callback when DDoS attacker is blocked."""
        print(f"[DDoS] Auto-blocked IP: {ip} - {reason}")

    def _initial_log_parse(self):
        """Parse existing log file for historical incidents."""
        log_sources = self.config.get('log_sources', [])
        for source in log_sources:
            if not source.get('enabled', True):
                continue
            if source['parser'] == 'ssh_auth':
                filepath = source['path']
                print(f"Parsing existing log file: {filepath}")
                # Parse last 24 hours
                since = datetime.now() - timedelta(hours=24)
                entries = parse_log_file(filepath, since=since)
                print(f"Parsed {len(entries)} log entries")
                for entry in entries:
                    self._process_entry(entry)

    def _log_tail_loop(self):
        """Tail log file and process new entries."""
        log_sources = self.config.get('log_sources', [])
        ssh_source = next((s for s in log_sources if s['parser'] == 'ssh_auth'), None)

        if not ssh_source:
            print("No SSH auth log source configured")
            return

        filepath = ssh_source['path']
        print(f"Tailing log file: {filepath}")

        def callback(entry: LogEntry):
            self._process_entry(entry)

        try:
            tail_log_file(filepath, callback)
        except Exception as e:
            print(f"Log tail error: {e}")

    def _process_entry(self, entry: LogEntry):
        """Process a single log entry through detection pipeline."""
        if not entry.source_ip:
            return

        # Run detection
        triggered_rules = self.detection_engine.process_entry(entry)

        for rule_name in triggered_rules:
            print(f"\n[ALERT] Rule triggered: {rule_name} from {entry.source_ip}")
            self._handle_incident(entry.source_ip, rule_name)

    def _handle_incident(self, ip: str, incident_type: str):
        """Handle a detected incident: analyze, block, report."""
        # Gather incident data
        incident_data = self.detection_engine.get_incident_data(ip, incident_type)
        if not incident_data:
            return

        # AI Analysis
        print(f"Analyzing incident with AI...")
        report = self.analyzer.analyze(incident_data)

        if report:
            # Store incident
            with self.incidents_lock:
                self.incidents.append(report)

            # Generate reports
            paths = self.report_generator.generate_report(report)
            for fmt, path in paths.items():
                print(f"Report generated: {path}")

            # Block the IP
            if self.blocker:
                block_duration = incident_data.get('config', {}).get('block_duration_seconds', 3600)
                self.blocker.block_ip(ip, report.incident_type, block_duration)
                blocked_msg = f"Blocked: Yes (duration: {block_duration}s)"
            else:
                blocked_msg = "Blocked: No (blocker unavailable)"

            # Print summary
            print(f"\n{'='*60}")
            print(f"INCIDENT DETECTED: {report.incident_type}")
            print(f"{'='*60}")
            print(f"Attacker IP: {report.attacker_ip}")
            print(f"Severity: {report.severity}")
            print(f"Total Attempts: {report.total_attempts}")
            print(f"Successful: {'Yes' if report.successful else 'No'}")
            print(f"Targeted Users: {', '.join(report.targeted_usernames)}")
            print(blocked_msg)
            print(f"Reports: {', '.join(paths.values())}")
            print(f"{'='*60}\n")

    def _cleanup_loop(self):
        """Periodic cleanup: expired blocks, old activities, old reports."""
        while self.running:
            time.sleep(300)  # Every 5 minutes
            if not self.running:
                break

            try:
                # Check expired blocks
                if self.blocker:
                    self.blocker.check_expired_blocks()

                # Cleanup old detection engine activities
                self.detection_engine.cleanup_old_activities()

                # Cleanup old reports
                self.report_generator.cleanup_old_reports()

                # Sync threat intel to blocker periodically
                if self.threat_intel and self.blocker:
                    self._sync_threat_intel_to_blocker()

            except Exception as e:
                print(f"Cleanup error: {e}")

    def stop(self):
        """Stop the daemon."""
        print("Stopping Light-SOC...")
        self.running = False

        # Stop extended modules
        if self.fim_monitor:
            self.fim_monitor.stop()
        if self.vuln_detector:
            self.vuln_detector.stop()
        if self.sca_scanner:
            self.sca_scanner.stop()
        if self.network_monitor:
            self.network_monitor.stop()
        if self.threat_intel:
            self.threat_intel.stop()
        if self.ddos_detector:
            self.ddos_detector.stop()
        if self.alert_manager:
            self.alert_manager.stop()

        # Wait for threads
        for t in self.module_threads:
            t.join(timeout=5)

        if self.log_thread:
            self.log_thread.join(timeout=5)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)

        print("Light-SOC stopped.")

    def get_status(self) -> dict:
        """Get current status."""
        blocked_count = 0
        if self.blocker:
            blocked_count = len(self.blocker.get_blocked_ips())

        status = {
            'running': self.running,
            'blocked_ips': blocked_count,
            'total_incidents': len(self.incidents),
            'ollama_healthy': self.analyzer.check_ollama_health(),
            'modules': {
                'fim': self.fim_monitor is not None,
                'vulnerability_detection': self.vuln_detector is not None,
                'sca': self.sca_scanner is not None,
                'network_inspection': self.network_monitor is not None,
                'threat_intelligence': self.threat_intel is not None,
                'ddos_detection': self.ddos_detector is not None,
                'alerting': self.alert_manager is not None,
            }
        }

        # Add module-specific stats
        if self.fim_monitor:
            status['fim_baseline_files'] = len(self.fim_monitor.baselines)
            status['fim_alerts'] = len(self.fim_monitor.alerts)

        if self.vuln_detector:
            last_scan = self.vuln_detector.get_last_scan()
            if last_scan:
                status['vuln_total_packages'] = last_scan.total_packages
                status['vuln_vulnerable_packages'] = last_scan.vulnerable_packages
                status['vuln_total_cves'] = last_scan.total_cves

        if self.sca_scanner:
            last_scan = self.sca_scanner.get_last_scan()
            if last_scan:
                status['sca_total_checks'] = last_scan.total_checks
                status['sca_passed'] = last_scan.passed
                status['sca_failed'] = last_scan.failed

        if self.threat_intel:
            status['threat_intel_indicators'] = self.threat_intel.stats['total_indicators']
            status['threat_intel_feeds'] = self.threat_intel.stats['feeds_active']

        if self.ddos_detector:
            ddos_stats = self.ddos_detector.get_stats()
            status['ddos_active_incidents'] = ddos_stats['active_incidents']
            status['ddos_ips_blocked'] = ddos_stats['ips_blocked']
            status['ddos_packets_analyzed'] = ddos_stats['packets_analyzed']

        if self.alert_manager:
            alert_stats = self.alert_manager.get_stats()
            status['alerts_total'] = alert_stats['total_alerts']
            status['alerts_unacknowledged'] = alert_stats['unacknowledged']

        return status

    def manual_block(self, ip: str, reason: str, duration: int = 3600):
        """Manually block an IP."""
        if self.blocker:
            return self.blocker.block_ip(ip, reason, duration)
        print("Blocker not available")
        return False

    def manual_unblock(self, ip: str):
        """Manually unblock an IP."""
        if self.blocker:
            return self.blocker.unblock_ip(ip)
        print("Blocker not available")
        return False

    def list_blocked(self):
        """List all blocked IPs."""
        if self.blocker:
            return self.blocker.get_all_blocks()
        return []

    def list_incidents(self):
        """List all incidents."""
        with self.incidents_lock:
            return list(self.incidents)

    # Extended module CLI methods
    def fim_scan(self):
        """Trigger manual FIM scan."""
        if self.fim_monitor:
            self.fim_monitor.scan()
            return self.fim_monitor.get_alerts()
        print("FIM not enabled")
        return []

    def vuln_scan(self):
        """Trigger manual vulnerability scan."""
        if self.vuln_detector:
            return self.vuln_detector.scan()
        print("Vulnerability Detection not enabled")
        return None

    def sca_scan(self):
        """Trigger manual SCA scan."""
        if self.sca_scanner:
            return self.sca_scanner.scan()
        print("SCA not enabled")
        return None

    def threat_intel_update(self):
        """Trigger manual threat intel update."""
        if self.threat_intel:
            self.threat_intel.update_all_feeds()
            return self.threat_intel.get_feed_status()
        print("Threat Intelligence not enabled")
        return []

    def threat_intel_check_ip(self, ip: str):
        """Check an IP against threat intelligence."""
        if self.threat_intel:
            return self.threat_intel.check_ip(ip)
        print("Threat Intelligence not enabled")
        return []

    def threat_intel_check_domain(self, domain: str):
        """Check a domain against threat intelligence."""
        if self.threat_intel:
            return self.threat_intel.check_domain(domain)
        print("Threat Intelligence not enabled")
        return []

    # DDoS specific methods
    def ddos_status(self):
        """Get DDoS detector status."""
        if self.ddos_detector:
            return self.ddos_detector.get_stats()
        return {}

    def ddos_incidents(self, limit: int = 100):
        """Get DDoS incidents."""
        if self.ddos_detector:
            return self.ddos_detector.get_incidents(limit=limit)
        return []

    def ddos_ip_stats(self, ip: str):
        """Get DDoS stats for specific IP."""
        if self.ddos_detector:
            return self.ddos_detector.get_ip_stats(ip)
        return None

    def alert_status(self):
        """Get alert manager status."""
        if self.alert_manager:
            return self.alert_manager.get_stats()
        return {}

    def alert_list(self, limit: int = 100):
        """Get recent alerts."""
        if self.alert_manager:
            return self.alert_manager.get_alerts(limit=limit)
        return []


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Light-SOC: Lightweight SOC with NGFW + AI')
    parser.add_argument('-c', '--config', help='Config file path')
    parser.add_argument('--status', action='store_true', help='Show status and exit')
    parser.add_argument('--block', help='Manually block an IP')
    parser.add_argument('--unblock', help='Manually unblock an IP')
    parser.add_argument('--reason', default='Manual block', help='Reason for manual block')
    parser.add_argument('--duration', type=int, default=3600, help='Block duration in seconds')
    parser.add_argument('--list-blocked', action='store_true', help='List blocked IPs')
    parser.add_argument('--list-incidents', action='store_true', help='List incidents')
    parser.add_argument('--test-parse', help='Test parse a log file')

    # Extended module commands
    parser.add_argument('--fim-scan', action='store_true', help='Run FIM scan')
    parser.add_argument('--vuln-scan', action='store_true', help='Run vulnerability scan')
    parser.add_argument('--sca-scan', action='store_true', help='Run SCA scan')
    parser.add_argument('--threat-intel-update', action='store_true', help='Update threat intel feeds')
    parser.add_argument('--threat-intel-check-ip', help='Check IP against threat intel')
    parser.add_argument('--threat-intel-check-domain', help='Check domain against threat intel')

    # DDoS commands
    parser.add_argument('--ddos-status', action='store_true', help='Show DDoS detector status')
    parser.add_argument('--ddos-incidents', action='store_true', help='List DDoS incidents')
    parser.add_argument('--ddos-ip', help='Get DDoS stats for specific IP')

    # Alerting commands
    parser.add_argument('--alert-status', action='store_true', help='Show alert manager status')
    parser.add_argument('--alert-list', action='store_true', help='List recent alerts')

    args = parser.parse_args()

    soc = LightSOC(args.config)

    if args.status:
        status = soc.get_status()
        print(json.dumps(status, indent=2, default=str))
        return

    if args.block:
        success = soc.manual_block(args.block, args.reason, args.duration)
        print(f"Block {'successful' if success else 'failed'}: {args.block}")
        return

    if args.unblock:
        success = soc.manual_unblock(args.unblock)
        print(f"Unblock {'successful' if success else 'failed'}: {args.unblock}")
        return

    if args.list_blocked:
        blocked = soc.list_blocked()
        for b in blocked:
            status = "ACTIVE" if b.active else "EXPIRED"
            expires = b.expires_at.strftime("%Y-%m-%d %H:%M:%S") if b.expires_at else "Never"
            print(f"{b.ip:15} | {status:7} | {b.reason:30} | Expires: {expires}")
        return

    if args.list_incidents:
        incidents = soc.list_incidents()
        for inc in incidents:
            print(f"{inc.created_at.isoformat()} | {inc.severity:8} | {inc.attacker_ip:15} | {inc.incident_type} | Attempts: {inc.total_attempts}")
        return

    if args.test_parse:
        entries = parse_log_file(args.test_parse)
        for e in entries:
            print(f"{e.timestamp} | {e.source_ip:15} | {e.username or 'N/A':15} | {e.event_type}")
        return

    # Extended module commands
    if args.fim_scan:
        alerts = soc.fim_scan()
        print(f"FIM scan completed. Alerts: {len(alerts)}")
        for alert in alerts:
            print(f"  {alert.alert_type.upper()}: {alert.path}")
        return

    if args.vuln_scan:
        result = soc.vuln_scan()
        if result:
            print(f"Vulnerability scan completed:")
            print(f"  Total packages: {result.total_packages}")
            print(f"  Vulnerable packages: {result.vulnerable_packages}")
            print(f"  Total CVEs: {result.total_cves}")
            print(f"  Critical: {result.critical_count}, High: {result.high_count}, Medium: {result.medium_count}, Low: {result.low_count}")
        return

    if args.sca_scan:
        result = soc.sca_scan()
        if result:
            print(f"SCA scan completed:")
            print(f"  Total checks: {result.total_checks}")
            print(f"  Passed: {result.passed}, Failed: {result.failed}, Errors: {result.errors}")
            print(f"  Critical failures: {result.critical_failures}, High: {result.high_failures}")
        return

    if args.threat_intel_update:
        feeds = soc.threat_intel_update()
        print(f"Threat intel update completed. Active feeds: {len([f for f in feeds if f['enabled'] and not f['last_error']])}")
        for feed in feeds:
            status = "OK" if not feed['last_error'] else f"ERROR: {feed['last_error']}"
            print(f"  {feed['name']}: {feed['indicator_count']} indicators - {status}")
        return

    if args.threat_intel_check_ip:
        matches = soc.threat_intel_check_ip(args.threat_intel_check_ip)
        if matches:
            print(f"IP {args.threat_intel_check_ip} matches {len(matches)} threat indicators:")
            for m in matches:
                print(f"  {m.indicator_type}: {m.value} (confidence: {m.confidence}, severity: {m.severity}) - {m.source}")
        else:
            print(f"IP {args.threat_intel_check_ip} not found in threat intelligence")
        return

    if args.threat_intel_check_domain:
        matches = soc.threat_intel_check_domain(args.threat_intel_check_domain)
        if matches:
            print(f"Domain {args.threat_intel_check_domain} matches {len(matches)} threat indicators:")
            for m in matches:
                print(f"  {m.indicator_type}: {m.value} (confidence: {m.confidence}, severity: {m.severity}) - {m.source}")
        else:
            print(f"Domain {args.threat_intel_check_domain} not found in threat intelligence")
        return

    # DDoS commands
    if args.ddos_status:
        status = soc.ddos_status()
        print(json.dumps(status, indent=2, default=str))
        return

    if args.ddos_incidents:
        incidents = soc.ddos_incidents()
        for inc in incidents:
            print(f"{inc.started_at} | {inc.severity.value:8} | {inc.attacker_ip:15} | {inc.attack_type.value} | PPS: {inc.peak_pps} | Blocked: {inc.blocked}")
        return

    if args.ddos_ip:
        stats = soc.ddos_ip_stats(args.ddos_ip)
        if stats:
            print(json.dumps(stats, indent=2, default=str))
        else:
            print(f"No DDoS data for IP: {args.ddos_ip}")
        return

    # Alerting commands
    if args.alert_status:
        status = soc.alert_status()
        print(json.dumps(status, indent=2, default=str))
        return

    if args.alert_list:
        alerts = soc.alert_list()
        for alert in alerts:
            ack = "✓" if alert.acknowledged else "✗"
            print(f"{alert.timestamp} | {ack} | {alert.severity:8} | {alert.title}")
        return

    # Default: run daemon
    soc.start()


if __name__ == '__main__':
    main()