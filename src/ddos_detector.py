"""DDoS Detection and Prevention Module for Light-SOC.

Provides comprehensive DDoS detection including:
- Volumetric attacks (bandwidth flooding)
- Protocol attacks (SYN flood, UDP flood, ICMP flood)
- Application-layer attacks (HTTP flood, Slowloris, DNS amplification)
- Connection exhaustion attacks
- Rate limiting with adaptive thresholds
"""

import logging
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
import json

from src.config_loader import get_config
from src.models import LogEntry
from src.blocker import get_blocker

logger = logging.getLogger(__name__)


class DDoSAttackType(str, Enum):
    """Types of DDoS attacks detected."""
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    HTTP_FLOOD = "http_flood"
    SLOWLORIS = "slowloris"
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    SSDP_AMPLIFICATION = "ssdp_amplification"
    CONNECTION_EXHAUSTION = "connection_exhaustion"
    VOLUMETRIC = "volumetric"
    APPLICATION_LAYER = "application_layer"
    FRAGMENTATION = "fragmentation"
    UNKNOWN = "unknown"


class DDoSSeverity(str, Enum):
    """Severity levels for DDoS incidents."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DDoSRule:
    """DDoS detection rule configuration."""
    attack_type: DDoSAttackType
    enabled: bool = True
    # Rate thresholds
    packets_per_second: int = 1000
    bytes_per_second: int = 10_000_000  # 10 MB/s
    connections_per_second: int = 100
    concurrent_connections: int = 1000
    # Time windows
    detection_window_seconds: int = 10
    analysis_window_seconds: int = 60
    block_duration_seconds: int = 3600
    # Thresholds
    syn_packet_threshold: int = 100
    udp_packet_threshold: int = 500
    icmp_packet_threshold: int = 200
    http_request_threshold: int = 200
    slowloris_connection_threshold: int = 50
    slowloris_timeout_seconds: int = 30
    dns_query_threshold: int = 500
    fragmentation_threshold: int = 100
    # Whitelist
    whitelist_ips: List[str] = field(default_factory=list)
    whitelist_cidrs: List[str] = field(default_factory=list)
    # Actions
    auto_block: bool = True
    alert_only: bool = False
    severity: str = "HIGH"


@dataclass
class TrafficStats:
    """Traffic statistics for an IP."""
    ip: str
    timestamp: datetime
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    syn_packets: int = 0
    synack_packets: int = 0
    ack_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    http_requests: int = 0
    dns_queries: int = 0
    ntp_requests: int = 0
    ssdp_requests: int = 0
    fragmented_packets: int = 0
    new_connections: int = 0
    active_connections: int = 0
    half_open_connections: int = 0
    slowloris_candidates: int = 0
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class DDoSIncident:
    """Detected DDoS incident."""
    attack_type: DDoSAttackType
    attacker_ip: str
    severity: DDoSSeverity
    started_at: datetime
    last_seen: datetime
    peak_pps: int = 0
    peak_bps: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    rule_triggered: str = ""
    confidence: float = 0.0


class DDoSDetector:
    """Main DDoS detection engine."""

    def __init__(self):
        self.config = get_config()
        ddos_config = self.config.get('ddos', {})
        self.enabled = ddos_config.get('enabled', True)

        # Load rules
        self.rules: Dict[DDoSAttackType, DDoSRule] = {}
        self._load_rules(ddos_config)

        # Traffic tracking per IP
        self.traffic_stats: Dict[str, TrafficStats] = {}
        self.stats_lock = threading.RLock()

        # Historical data for trend analysis
        self.history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=3600))  # 1 hour at 1s resolution
        self.history_lock = threading.RLock()

        # Detected incidents
        self.incidents: List[DDoSIncident] = []
        self.incidents_lock = threading.RLock()

        # Rate limiters (token bucket per IP)
        self.rate_limiters: Dict[str, 'TokenBucket'] = {}
        self.rate_limiter_lock = threading.RLock()

        # Connection tracking
        self.connections: Dict[str, Dict[Tuple[str, int], Dict]] = defaultdict(dict)  # ip -> (dst_ip, dst_port) -> conn_info
        self.connections_lock = threading.RLock()

        # Slowloris tracking
        self.slowloris_tracker: Dict[str, Dict] = defaultdict(dict)  # ip -> {conn_id: {start_time, headers_sent}}

        # Threading
        self.running = False
        self.analysis_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'incidents_detected': 0,
            'ips_blocked': 0,
            'false_positives': 0,
        }

        # Callbacks
        self.on_incident_callback: Optional[Callable[[DDoSIncident], None]] = None
        self.on_block_callback: Optional[Callable[[str, str], None]] = None

    def _load_rules(self, ddos_config: Dict):
        """Load DDoS detection rules from config."""
        rule_configs = ddos_config.get('rules', {})

        default_rules = {
            DDoSAttackType.SYN_FLOOD: DDoSRule(
                attack_type=DDoSAttackType.SYN_FLOOD,
                enabled=rule_configs.get('syn_flood', {}).get('enabled', True),
                packets_per_second=rule_configs.get('syn_flood', {}).get('pps_threshold', 100),
                syn_packet_threshold=rule_configs.get('syn_flood', {}).get('syn_threshold', 100),
                detection_window_seconds=rule_configs.get('syn_flood', {}).get('window', 10),
                block_duration_seconds=rule_configs.get('syn_flood', {}).get('block_duration', 3600),
                auto_block=rule_configs.get('syn_flood', {}).get('auto_block', True),
                severity=rule_configs.get('syn_flood', {}).get('severity', 'HIGH'),
            ),
            DDoSAttackType.UDP_FLOOD: DDoSRule(
                attack_type=DDoSAttackType.UDP_FLOOD,
                enabled=rule_configs.get('udp_flood', {}).get('enabled', True),
                packets_per_second=rule_configs.get('udp_flood', {}).get('pps_threshold', 500),
                udp_packet_threshold=rule_configs.get('udp_flood', {}).get('udp_threshold', 500),
                detection_window_seconds=rule_configs.get('udp_flood', {}).get('window', 10),
                block_duration_seconds=rule_configs.get('udp_flood', {}).get('block_duration', 3600),
                auto_block=rule_configs.get('udp_flood', {}).get('auto_block', True),
                severity=rule_configs.get('udp_flood', {}).get('severity', 'HIGH'),
            ),
            DDoSAttackType.ICMP_FLOOD: DDoSRule(
                attack_type=DDoSAttackType.ICMP_FLOOD,
                enabled=rule_configs.get('icmp_flood', {}).get('enabled', True),
                packets_per_second=rule_configs.get('icmp_flood', {}).get('pps_threshold', 200),
                icmp_packet_threshold=rule_configs.get('icmp_flood', {}).get('icmp_threshold', 200),
                detection_window_seconds=rule_configs.get('icmp_flood', {}).get('window', 10),
                block_duration_seconds=rule_configs.get('icmp_flood', {}).get('block_duration', 3600),
                auto_block=rule_configs.get('icmp_flood', {}).get('auto_block', True),
                severity=rule_configs.get('icmp_flood', {}).get('severity', 'MEDIUM'),
            ),
            DDoSAttackType.HTTP_FLOOD: DDoSRule(
                attack_type=DDoSAttackType.HTTP_FLOOD,
                enabled=rule_configs.get('http_flood', {}).get('enabled', True),
                http_request_threshold=rule_configs.get('http_flood', {}).get('req_threshold', 200),
                connections_per_second=rule_configs.get('http_flood', {}).get('cps_threshold', 50),
                concurrent_connections=rule_configs.get('http_flood', {}).get('concurrent_threshold', 500),
                detection_window_seconds=rule_configs.get('http_flood', {}).get('window', 10),
                block_duration_seconds=rule_configs.get('http_flood', {}).get('block_duration', 3600),
                auto_block=rule_configs.get('http_flood', {}).get('auto_block', True),
                severity=rule_configs.get('http_flood', {}).get('severity', 'HIGH'),
            ),
            DDoSAttackType.SLOWLORIS: DDoSRule(
                attack_type=DDoSAttackType.SLOWLORIS,
                enabled=rule_configs.get('slowloris', {}).get('enabled', True),
                slowloris_connection_threshold=rule_configs.get('slowloris', {}).get('conn_threshold', 50),
                slowloris_timeout_seconds=rule_configs.get('slowloris', {}).get('timeout', 30),
                concurrent_connections=rule_configs.get('slowloris', {}).get('concurrent_threshold', 100),
                detection_window_seconds=rule_configs.get('slowloris', {}).get('window', 60),
                block_duration_seconds=rule_configs.get('slowloris', {}).get('block_duration', 7200),
                auto_block=rule_configs.get('slowloris', {}).get('auto_block', True),
                severity=rule_configs.get('slowloris', {}).get('severity', 'HIGH'),
            ),
            DDoSAttackType.DNS_AMPLIFICATION: DDoSRule(
                attack_type=DDoSAttackType.DNS_AMPLIFICATION,
                enabled=rule_configs.get('dns_amplification', {}).get('enabled', True),
                dns_query_threshold=rule_configs.get('dns_amplification', {}).get('query_threshold', 500),
                bytes_per_second=rule_configs.get('dns_amplification', {}).get('bps_threshold', 50_000_000),
                detection_window_seconds=rule_configs.get('dns_amplification', {}).get('window', 10),
                block_duration_seconds=rule_configs.get('dns_amplification', {}).get('block_duration', 3600),
                auto_block=rule_configs.get('dns_amplification', {}).get('auto_block', True),
                severity=rule_configs.get('dns_amplification', {}).get('severity', 'HIGH'),
            ),
            DDoSAttackType.VOLUMETRIC: DDoSRule(
                attack_type=DDoSAttackType.VOLUMETRIC,
                enabled=rule_configs.get('volumetric', {}).get('enabled', True),
                bytes_per_second=rule_configs.get('volumetric', {}).get('bps_threshold', 100_000_000),
                packets_per_second=rule_configs.get('volumetric', {}).get('pps_threshold', 10000),
                detection_window_seconds=rule_configs.get('volumetric', {}).get('window', 10),
                block_duration_seconds=rule_configs.get('volumetric', {}).get('block_duration', 3600),
                auto_block=rule_configs.get('volumetric', {}).get('auto_block', True),
                severity=rule_configs.get('volumetric', {}).get('severity', 'CRITICAL'),
            ),
            DDoSAttackType.CONNECTION_EXHAUSTION: DDoSRule(
                attack_type=DDoSAttackType.CONNECTION_EXHAUSTION,
                enabled=rule_configs.get('connection_exhaustion', {}).get('enabled', True),
                concurrent_connections=rule_configs.get('connection_exhaustion', {}).get('concurrent_threshold', 1000),
                connections_per_second=rule_configs.get('connection_exhaustion', {}).get('cps_threshold', 200),
                detection_window_seconds=rule_configs.get('connection_exhaustion', {}).get('window', 60),
                block_duration_seconds=rule_configs.get('connection_exhaustion', {}).get('block_duration', 3600),
                auto_block=rule_configs.get('connection_exhaustion', {}).get('auto_block', True),
                severity=rule_configs.get('connection_exhaustion', {}).get('severity', 'HIGH'),
            ),
        }

        # Merge with any custom rules from config
        for attack_type, default_rule in default_rules.items():
            if attack_type.value in rule_configs:
                custom = rule_configs[attack_type.value]
                # Update only provided fields
                for key, value in custom.items():
                    if hasattr(default_rule, key):
                        setattr(default_rule, key, value)
            self.rules[attack_type] = default_rule

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.rules.get(DDoSAttackType.SYN_FLOOD, DDoSRule(DDoSAttackType.SYN_FLOOD)).whitelist_cidrs:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except ValueError:
            pass
        return False

    def start(self):
        """Start the DDoS detection engine."""
        if self.running:
            return

        self.running = True
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()

        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        logger.info("DDoS Detector started")

    def stop(self):
        """Stop the DDoS detection engine."""
        self.running = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        logger.info("DDoS Detector stopped")

    def process_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       protocol: str, flags: Set[str] = None, payload: bytes = b'',
                       length: int = 0, direction: str = "inbound"):
        """Process a network packet for DDoS detection."""
        if not self.enabled or self._is_whitelisted(src_ip):
            return

        now = datetime.now()

        with self.stats_lock:
            self.stats['packets_analyzed'] += 1

        with self.traffic_lock(src_ip) as stats:
            if not stats:
                stats = TrafficStats(ip=src_ip, timestamp=now)
                self.traffic_stats[src_ip] = stats

            stats.last_seen = now
            stats.packets_in += 1
            stats.bytes_in += length

            # Protocol-specific counting
            proto_lower = protocol.lower()
            if proto_lower == 'tcp':
                if flags and 'SYN' in flags and 'ACK' not in flags:
                    stats.syn_packets += 1
                elif flags and 'SYN' in flags and 'ACK' in flags:
                    stats.synack_packets += 1
                elif flags and 'ACK' in flags:
                    stats.ack_packets += 1

                # Track connections
                self._track_connection(src_ip, dst_ip, dst_port, flags, direction)

            elif proto_lower == 'udp':
                stats.udp_packets += 1
                # Check for DNS/NTP/SSDP amplification
                if dst_port == 53:
                    stats.dns_queries += 1
                elif dst_port == 123:
                    stats.ntp_requests += 1
                elif dst_port == 1900:
                    stats.ssdp_requests += 1

            elif proto_lower == 'icmp':
                stats.icmp_packets += 1

            # Check for fragmentation
            if flags and 'FRAG' in flags:
                stats.fragmented_packets += 1

            # Store in history for trend analysis
            with self.history_lock:
                self.history[src_ip].append({
                    'timestamp': now,
                    'packets': 1,
                    'bytes': length,
                    'syn': 1 if (flags and 'SYN' in flags and 'ACK' not in flags) else 0,
                    'udp': 1 if proto_lower == 'udp' else 0,
                    'icmp': 1 if proto_lower == 'icmp' else 0,
                })

    def _track_connection(self, src_ip: str, dst_ip: str, dst_port: int,
                          flags: Set[str], direction: str):
        """Track TCP connections for connection exhaustion detection."""
        conn_key = (dst_ip, dst_port)
        now = datetime.now()

        with self.connections_lock:
            if conn_key not in self.connections[src_ip]:
                self.connections[src_ip][conn_key] = {
                    'start_time': now,
                    'last_seen': now,
                    'state': 'SYN_SENT' if flags and 'SYN' in flags else 'ESTABLISHED',
                    'half_open': True if flags and 'SYN' in flags and 'ACK' not in flags else False,
                    'bytes_sent': 0,
                    'bytes_received': 0,
                }
            else:
                conn = self.connections[src_ip][conn_key]
                conn['last_seen'] = now
                if flags and 'ACK' in flags and conn['state'] == 'SYN_SENT':
                    conn['state'] = 'ESTABLISHED'
                    conn['half_open'] = False

            # Update traffic stats
            with self.stats_lock:
                stats = self.traffic_stats.get(src_ip)
                if stats:
                    stats.new_connections += 1
                    stats.active_connections = len([
                        c for c in self.connections[src_ip].values()
                        if c['state'] == 'ESTABLISHED'
                    ])
                    stats.half_open_connections = len([
                        c for c in self.connections[src_ip].values()
                        if c['half_open']
                    ])

    def _analysis_loop(self):
        """Main analysis loop - runs every detection window."""
        while self.running:
            time.sleep(5)  # Check every 5 seconds
            if not self.running:
                break

            try:
                self._analyze_traffic()
            except Exception as e:
                logger.error(f"DDoS analysis error: {e}")

    def _analyze_traffic(self):
        """Analyze traffic patterns for DDoS detection."""
        now = datetime.now()

        with self.traffic_lock():
            ips_to_check = list(self.traffic_stats.keys())

        for ip in ips_to_check:
            if self._is_whitelisted(ip):
                continue

            with self.traffic_lock(ip) as stats:
                if not stats:
                    continue

                # Calculate rates over detection window
                window = 10  # seconds
                cutoff = now - timedelta(seconds=window)

                with self.history_lock:
                    history = self.history.get(ip, deque())
                    recent = [h for h in history if h['timestamp'] >= cutoff]

                if not recent:
                    continue

                pps = len(recent)
                bps = sum(h['bytes'] for h in recent)
                syn_count = sum(h['syn'] for h in recent)
                udp_count = sum(h['udp'] for h in recent)
                icmp_count = sum(h['icmp'] for h in recent)

                # Check each rule
                for attack_type, rule in self.rules.items():
                    if not rule.enabled:
                        continue

                    triggered = False
                    confidence = 0.0
                    details = {}

                    if attack_type == DDoSAttackType.SYN_FLOOD:
                        triggered, confidence, details = self._check_syn_flood(
                            ip, stats, pps, syn_count, rule
                        )
                    elif attack_type == DDoSAttackType.UDP_FLOOD:
                        triggered, confidence, details = self._check_udp_flood(
                            ip, stats, pps, udp_count, rule
                        )
                    elif attack_type == DDoSAttackType.ICMP_FLOOD:
                        triggered, confidence, details = self._check_icmp_flood(
                            ip, stats, pps, icmp_count, rule
                        )
                    elif attack_type == DDoSAttackType.HTTP_FLOOD:
                        triggered, confidence, details = self._check_http_flood(
                            ip, stats, rule
                        )
                    elif attack_type == DDoSAttackType.SLOWLORIS:
                        triggered, confidence, details = self._check_slowloris(
                            ip, stats, rule
                        )
                    elif attack_type == DDoSAttackType.DNS_AMPLIFICATION:
                        triggered, confidence, details = self._check_dns_amplification(
                            ip, stats, bps, rule
                        )
                    elif attack_type == DDoSAttackType.VOLUMETRIC:
                        triggered, confidence, details = self._check_volumetric(
                            ip, stats, pps, bps, rule
                        )
                    elif attack_type == DDoSAttackType.CONNECTION_EXHAUSTION:
                        triggered, confidence, details = self._check_connection_exhaustion(
                            ip, stats, rule
                        )

                    if triggered:
                        self._handle_incident(ip, attack_type, rule, confidence, details,
                                            pps, bps, stats)

    def _check_syn_flood(self, ip: str, stats: TrafficStats, pps: int,
                         syn_count: int, rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for SYN flood attack."""
        if syn_count >= rule.syn_packet_threshold:
            # Check SYN/ACK ratio (low ratio indicates flood)
            synack = stats.synack_packets
            ratio = synack / syn_count if syn_count > 0 else 0

            confidence = min(1.0, syn_count / rule.syn_packet_threshold * 1.5)
            if ratio < 0.1:  # Very few SYN-ACKs
                confidence = min(1.0, confidence * 1.5)

            return True, confidence, {
                'syn_packets': syn_count,
                'synack_packets': synack,
                'syn_ack_ratio': ratio,
                'threshold': rule.syn_packet_threshold,
            }
        return False, 0.0, {}

    def _check_udp_flood(self, ip: str, stats: TrafficStats, pps: int,
                         udp_count: int, rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for UDP flood attack."""
        if udp_count >= rule.udp_packet_threshold:
            confidence = min(1.0, udp_count / rule.udp_packet_threshold * 1.2)
            return True, confidence, {
                'udp_packets': udp_count,
                'threshold': rule.udp_packet_threshold,
                'dns_queries': stats.dns_queries,
                'ntp_requests': stats.ntp_requests,
                'ssdp_requests': stats.ssdp_requests,
            }
        return False, 0.0, {}

    def _check_icmp_flood(self, ip: str, stats: TrafficStats, pps: int,
                          icmp_count: int, rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for ICMP flood attack."""
        if icmp_count >= rule.icmp_packet_threshold:
            confidence = min(1.0, icmp_count / rule.icmp_packet_threshold * 1.2)
            return True, confidence, {
                'icmp_packets': icmp_count,
                'threshold': rule.icmp_packet_threshold,
            }
        return False, 0.0, {}

    def _check_http_flood(self, ip: str, stats: TrafficStats,
                          rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for HTTP flood attack."""
        # This would need HTTP inspection integration
        # For now, check connection rate
        if stats.new_connections >= rule.connections_per_second:
            confidence = min(1.0, stats.new_connections / rule.connections_per_second)
            return True, confidence, {
                'new_connections': stats.new_connections,
                'concurrent_connections': stats.active_connections,
                'cps_threshold': rule.connections_per_second,
                'concurrent_threshold': rule.concurrent_connections,
            }
        return False, 0.0, {}

    def _check_slowloris(self, ip: str, stats: TrafficStats,
                         rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for Slowloris attack (many half-open connections)."""
        half_open = stats.half_open_connections
        if half_open >= rule.slowloris_connection_threshold:
            confidence = min(1.0, half_open / rule.slowloris_connection_threshold * 1.5)
            return True, confidence, {
                'half_open_connections': half_open,
                'threshold': rule.slowloris_connection_threshold,
                'timeout_seconds': rule.slowloris_timeout_seconds,
            }
        return False, 0.0, {}

    def _check_dns_amplification(self, ip: str, stats: TrafficStats,
                                  bps: int, rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for DNS amplification attack."""
        if stats.dns_queries >= rule.dns_query_threshold and bps >= rule.bytes_per_second:
            confidence = min(1.0, (stats.dns_queries / rule.dns_query_threshold +
                                  bps / rule.bytes_per_second) / 2)
            return True, confidence, {
                'dns_queries': stats.dns_queries,
                'bps': bps,
                'query_threshold': rule.dns_query_threshold,
                'bps_threshold': rule.bytes_per_second,
            }
        return False, 0.0, {}

    def _check_volumetric(self, ip: str, stats: TrafficStats, pps: int,
                          bps: int, rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for volumetric attack."""
        triggered = False
        confidence = 0.0
        details = {'pps': pps, 'bps': bps}

        if pps >= rule.packets_per_second:
            triggered = True
            confidence = max(confidence, min(1.0, pps / rule.packets_per_second))
            details['pps_threshold'] = rule.packets_per_second

        if bps >= rule.bytes_per_second:
            triggered = True
            confidence = max(confidence, min(1.0, bps / rule.bytes_per_second))
            details['bps_threshold'] = rule.bytes_per_second

        return triggered, confidence, details

    def _check_connection_exhaustion(self, ip: str, stats: TrafficStats,
                                      rule: DDoSRule) -> Tuple[bool, float, Dict]:
        """Check for connection exhaustion attack."""
        if stats.active_connections >= rule.concurrent_connections:
            confidence = min(1.0, stats.active_connections / rule.concurrent_connections * 1.2)
            return True, confidence, {
                'active_connections': stats.active_connections,
                'threshold': rule.concurrent_connections,
                'new_connections_per_sec': stats.new_connections,
            }
        return False, 0.0, {}

    def _handle_incident(self, ip: str, attack_type: DDoSAttackType, rule: DDoSRule,
                         confidence: float, details: Dict, pps: int, bps: int,
                         stats: TrafficStats):
        """Handle a detected DDoS incident."""
        # Check if we already have an active incident for this IP and type
        with self.incidents_lock:
            existing = next((
                inc for inc in self.incidents
                if inc.attacker_ip == ip and inc.attack_type == attack_type
                and not inc.blocked and (datetime.now() - inc.last_seen).seconds < 300
            ), None)

            if existing:
                # Update existing incident
                existing.last_seen = datetime.now()
                existing.peak_pps = max(existing.peak_pps, pps)
                existing.peak_bps = max(existing.peak_bps, bps)
                existing.total_packets += pps * 5  # approximate
                existing.total_bytes += bps * 5
                existing.confidence = max(existing.confidence, confidence)
                return

            # Create new incident
            severity = DDoSSeverity(rule.severity)
            if confidence > 0.8:
                severity = DDoSSeverity.CRITICAL if severity != DDoSSeverity.CRITICAL else severity

            incident = DDoSIncident(
                attack_type=attack_type,
                attacker_ip=ip,
                severity=severity,
                started_at=datetime.now(),
                last_seen=datetime.now(),
                peak_pps=pps,
                peak_bps=bps,
                total_packets=pps * 5,
                total_bytes=bps * 5,
                details=details,
                confidence=confidence,
                rule_triggered=attack_type.value,
            )

            self.incidents.append(incident)
            self.stats['incidents_detected'] += 1

            logger.warning(f"DDoS Detected: {attack_type.value} from {ip} "
                          f"(confidence: {confidence:.2f}, severity: {severity})")

            # Trigger callbacks
            if self.on_incident_callback:
                try:
                    self.on_incident_callback(incident)
                except Exception as e:
                    logger.error(f"Incident callback error: {e}")

            # Auto-block if enabled
            if rule.auto_block and not rule.alert_only:
                self._block_attacker(ip, attack_type, rule.block_duration_seconds, incident)

    def _block_attacker(self, ip: str, attack_type: DDoSAttackType,
                        duration: int, incident: DDoSIncident):
        """Block the attacking IP."""
        try:
            blocker = get_blocker()
            reason = f"DDoS: {attack_type.value} (confidence: {incident.confidence:.0%})"
            if blocker.block_ip(ip, reason, duration):
                incident.blocked = True
                self.stats['ips_blocked'] += 1
                logger.info(f"Blocked DDoS attacker: {ip} for {duration}s")

                if self.on_block_callback:
                    try:
                        self.on_block_callback(ip, reason)
                    except Exception as e:
                        logger.error(f"Block callback error: {e}")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")

    def _cleanup_loop(self):
        """Cleanup old data periodically."""
        while self.running:
            time.sleep(60)  # Every minute
            if not self.running:
                break

            try:
                now = datetime.now()
                cutoff = now - timedelta(seconds=300)  # 5 minutes

                # Clean old traffic stats
                with self.traffic_lock():
                    to_remove = [
                        ip for ip, stats in self.traffic_stats.items()
                        if stats.last_seen < cutoff
                    ]
                    for ip in to_remove:
                        del self.traffic_stats[ip]

                # Clean old connections
                with self.connections_lock:
                    for ip in list(self.connections.keys()):
                        conns = self.connections[ip]
                        to_remove_conns = [
                            key for key, conn in conns.items()
                            if conn['last_seen'] < cutoff
                        ]
                        for key in to_remove_conns:
                            del conns[key]
                        if not conns:
                            del self.connections[ip]

                # Clean old slowloris tracker
                for ip in list(self.slowloris_tracker.keys()):
                    tracker = self.slowloris_tracker[ip]
                    to_remove = [
                        cid for cid, data in tracker.items()
                        if data.get('start_time', now) < cutoff
                    ]
                    for cid in to_remove:
                        del tracker[cid]
                    if not tracker:
                        del self.slowloris_tracker[ip]

                # Clean old incidents (keep last 1000)
                with self.incidents_lock:
                    if len(self.incidents) > 1000:
                        self.incidents = self.incidents[-1000:]

            except Exception as e:
                logger.error(f"DDoS cleanup error: {e}")

    def traffic_lock(self, ip: str = None):
        """Context manager for traffic stats lock."""
        if ip:
            return _TrafficLock(self.stats_lock, self.traffic_stats, ip)
        return _TrafficLock(self.stats_lock, self.traffic_stats)

    def connections_lock(self):
        """Context manager for connections lock."""
        return _ConnectionsLock(self.connections_lock, self.connections)

    def get_incidents(self, limit: int = 100, active_only: bool = False) -> List[DDoSIncident]:
        """Get recent DDoS incidents."""
        with self.incidents_lock:
            incidents = list(self.incidents)
            if active_only:
                cutoff = datetime.now() - timedelta(minutes=10)
                incidents = [i for i in incidents if i.last_seen > cutoff]
            return incidents[-limit:]

    def get_stats(self) -> Dict:
        """Get detector statistics."""
        with self.traffic_lock():
            active_ips = len(self.traffic_stats)
        with self.incidents_lock:
            active_incidents = len([i for i in self.incidents
                                   if (datetime.now() - i.last_seen).seconds < 300])

        return {
            **self.stats,
            'active_ips_tracked': active_ips,
            'active_incidents': active_incidents,
            'total_incidents': len(self.incidents),
            'rules_loaded': len(self.rules),
        }

    def get_ip_stats(self, ip: str) -> Optional[Dict]:
        """Get detailed stats for a specific IP."""
        with self.traffic_lock(ip) as stats:
            if not stats:
                return None

            with self.connections_lock:
                conns = self.connections.get(ip, {})
                active = len([c for c in conns.values() if c['state'] == 'ESTABLISHED'])
                half_open = len([c for c in conns.values() if c['half_open']])

            return {
                'ip': ip,
                'packets_in': stats.packets_in,
                'packets_out': stats.packets_out,
                'bytes_in': stats.bytes_in,
                'bytes_out': stats.bytes_out,
                'syn_packets': stats.syn_packets,
                'synack_packets': stats.synack_packets,
                'udp_packets': stats.udp_packets,
                'icmp_packets': stats.icmp_packets,
                'http_requests': stats.http_requests,
                'dns_queries': stats.dns_queries,
                'active_connections': active,
                'half_open_connections': half_open,
                'fragmented_packets': stats.fragmented_packets,
                'first_seen': stats.timestamp.isoformat() if stats.timestamp else None,
                'last_seen': stats.last_seen.isoformat() if stats.last_seen else None,
            }

    def set_incident_callback(self, callback: Callable[[DDoSIncident], None]):
        """Set callback for incident notifications."""
        self.on_incident_callback = callback

    def set_block_callback(self, callback: Callable[[str, str], None]):
        """Set callback for block notifications."""
        self.on_block_callback = callback

    def simulate_traffic(self, ip: str, packets: int = 100, protocol: str = 'tcp',
                         flags: Set[str] = None, length: int = 64):
        """Simulate traffic for testing."""
        for _ in range(packets):
            self.process_packet(
                src_ip=ip,
                dst_ip='192.168.1.100',
                src_port=12345,
                dst_port=80 if protocol == 'tcp' else 53,
                protocol=protocol,
                flags=flags or set(),
                payload=b'X' * length,
                length=length,
            )


class _TrafficLock:
    """Context manager for thread-safe traffic stats access."""

    def __init__(self, lock: threading.RLock, stats_dict: Dict, ip: str = None):
        self.lock = lock
        self.stats_dict = stats_dict
        self.ip = ip
        self.stats = None

    def __enter__(self):
        self.lock.__enter__()
        if self.ip:
            self.stats = self.stats_dict.get(self.ip)
        return self.stats

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.__exit__(exc_type, exc_val, exc_tb)


class _ConnectionsLock:
    """Context manager for thread-safe connections access."""

    def __init__(self, lock: threading.RLock, conns_dict: Dict):
        self.lock = lock
        self.conns_dict = conns_dict

    def __enter__(self):
        self.lock.__enter__()
        return self.conns_dict

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.__exit__(exc_type, exc_val, exc_tb)


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, rate: int, burst: int):
        self.rate = rate  # tokens per second
        self.burst = burst  # max tokens
        self.tokens = burst
        self.last_update = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens."""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def available(self) -> float:
        """Get available tokens."""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            return min(self.burst, self.tokens + elapsed * self.rate)


def get_ddos_detector() -> DDoSDetector:
    """Get singleton DDoS detector instance."""
    if not hasattr(get_ddos_detector, '_instance'):
        get_ddos_detector._instance = DDoSDetector()
    return get_ddos_detector._instance