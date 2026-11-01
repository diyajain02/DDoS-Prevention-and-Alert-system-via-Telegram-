"""Light-SOC: Lightweight SOC with NGFW capabilities and AI-powered reporting."""
__version__ = "0.1.0"
__author__ = "Light-SOC Team"

from src.models import (
    LogEntry,
    IncidentReport,
    BlockedIP,
    Severity,
    IncidentType,
    TimelineEvent,
)

from src.config_loader import load_config, get_config, reload_config
from src.log_parser import parse_ssh_log_line, parse_log_file, tail_log_file
from src.detection_engine import DetectionEngine
from src.ai_analyzer import OllamaAnalyzer, get_analyzer
from src.blocker import IPBlocker, get_blocker
from src.report_generator import ReportGenerator, get_report_generator
from src.fim import FIMMonitor, FileBaseline, FIMAlert, get_fim_monitor
from src.vulnerability_detector import (
    VulnerabilityDetector,
    SoftwarePackage,
    Vulnerability,
    VulnScanResult,
    PackageManager,
    CVEChecker,
    get_vuln_detector,
)
from src.sca import (
    SCAScanner,
    SCARule,
    SCACheckResult,
    SCAScanResult,
    SCARuleSet,
    SCACheckEngine,
    get_sca_scanner,
)
from src.agent import (
    Agent,
    AgentManager,
    AgentInfo,
    AgentMessage,
    MessageType,
    AgentStatus,
    get_agent_manager,
)
from src.network_inspection import (
    NetworkMonitor,
    IPSRule,
    IPSAlert,
    NetworkFlow,
    Protocol,
    Action,
    Direction,
    ApplicationDetector,
    TLSInspector,
    HTTPInspector,
    DNSInspector,
    get_network_monitor,
)
from src.threat_intel import (
    ThreatIntelManager,
    ThreatFeed,
    ThreatIndicator,
    FeedType,
    FeedFormat,
    FeedParser,
    get_threat_intel_manager,
)
from src.main import LightSOC

__all__ = [
    # Core models
    'LogEntry',
    'IncidentReport',
    'BlockedIP',
    'Severity',
    'IncidentType',
    'TimelineEvent',
    # Config
    'load_config',
    'get_config',
    'reload_config',
    # Log parsing
    'parse_ssh_log_line',
    'parse_log_file',
    'tail_log_file',
    # Detection
    'DetectionEngine',
    # AI
    'OllamaAnalyzer',
    'get_analyzer',
    # Blocking
    'IPBlocker',
    'get_blocker',
    # Reporting
    'ReportGenerator',
    'get_report_generator',
    # FIM
    'FIMMonitor',
    'FileBaseline',
    'FIMAlert',
    'get_fim_monitor',
    # Vulnerability Detection
    'VulnerabilityDetector',
    'SoftwarePackage',
    'Vulnerability',
    'VulnScanResult',
    'PackageManager',
    'CVEChecker',
    'get_vuln_detector',
    # SCA
    'SCAScanner',
    'SCARule',
    'SCACheckResult',
    'SCAScanResult',
    'SCARuleSet',
    'SCACheckEngine',
    'get_sca_scanner',
    # Agent
    'Agent',
    'AgentManager',
    'AgentInfo',
    'AgentMessage',
    'MessageType',
    'AgentStatus',
    'get_agent_manager',
    # Network Inspection / IPS
    'NetworkMonitor',
    'IPSRule',
    'IPSAlert',
    'NetworkFlow',
    'Protocol',
    'Action',
    'Direction',
    'ApplicationDetector',
    'TLSInspector',
    'HTTPInspector',
    'DNSInspector',
    'get_network_monitor',
    # Threat Intelligence
    'ThreatIntelManager',
    'ThreatFeed',
    'ThreatIndicator',
    'FeedType',
    'FeedFormat',
    'FeedParser',
    'get_threat_intel_manager',
    # Main
    'LightSOC',
]