"""Threat Intelligence Feed Integration for Light-SOC.
Fetches and processes threat intelligence from multiple sources."""
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import ipaddress

from src.config_loader import get_config
from src.models import LogEntry
from collections import defaultdict


logger = logging.getLogger(__name__)


class FeedType(str, Enum):
    IP_BLOCKLIST = "ip_blocklist"
    DOMAIN_BLOCKLIST = "domain_blocklist"
    URL_BLOCKLIST = "url_blocklist"
    MALWARE_HASHES = "malware_hashes"
    CVE_FEED = "cve_feed"
    THREAT_ACTOR = "threat_actor"
    IOA = "ioa"  # Indicators of Attack


class FeedFormat(str, Enum):
    TXT = "txt"
    CSV = "csv"
    JSON = "json"
    STIX = "stix"
    OPENIOC = "openioc"
    MISP = "misp"


@dataclass
class ThreatFeed:
    """Configuration for a threat intelligence feed."""
    id: str
    name: str
    url: str
    feed_type: FeedType
    format: FeedFormat = FeedFormat.TXT
    enabled: bool = True
    update_interval_hours: int = 24
    headers: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Dict[str, str]] = None  # For API keys, etc.
    parser_config: Dict[str, Any] = field(default_factory=dict)
    last_updated: Optional[datetime] = None
    last_error: Optional[str] = None
    indicator_count: int = 0


@dataclass
class ThreatIndicator:
    """A single threat intelligence indicator."""
    id: str
    feed_id: str
    indicator_type: str  # ip, domain, url, hash, cve, email, etc.
    value: str
    confidence: int = 50  # 0-100
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    source: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if indicator has expired."""
        if self.expires_at:
            return datetime.now() > self.expires_at
        return False

    def matches_ip(self, ip: str) -> bool:
        """Check if this indicator matches an IP (supports CIDR)."""
        if self.indicator_type != 'ip':
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            if '/' in self.value:
                return ip_obj in ipaddress.ip_network(self.value)
            return ip_obj == ipaddress.ip_address(self.value)
        except ValueError:
            return False

    def matches_domain(self, domain: str) -> bool:
        """Check if this indicator matches a domain."""
        if self.indicator_type != 'domain':
            return False
        domain_lower = domain.lower()
        value_lower = self.value.lower()
        if value_lower.startswith('*.'):
            # Wildcard subdomain
            return domain_lower.endswith(value_lower[1:]) or domain_lower == value_lower[2:]
        return domain_lower == value_lower

    def matches_url(self, url: str) -> bool:
        """Check if this indicator matches a URL."""
        if self.indicator_type != 'url':
            return False
        return self.value in url

    def matches_hash(self, hash_value: str) -> bool:
        """Check if this indicator matches a file hash."""
        if self.indicator_type not in ('md5', 'sha1', 'sha256', 'hash'):
            return False
        return self.value.lower() == hash_value.lower()


class FeedParser:
    """Parses different threat intelligence feed formats."""

    @staticmethod
    def parse_txt(content: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse plain text feed (one indicator per line)."""
        indicators = []
        parser_config = feed.parser_config
        indicator_type = parser_config.get('indicator_type', 'ip')
        default_confidence = parser_config.get('confidence', 75)
        default_severity = parser_config.get('severity', 'MEDIUM')
        comment_char = parser_config.get('comment_char', '#')
        delimiter = parser_config.get('delimiter', None)
        
        for line_num, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith(comment_char):
                continue
            
            value = line
            if delimiter and delimiter in line:
                parts = line.split(delimiter)
                value = parts[0].strip()
            
            # Validate based on type
            if indicator_type == 'ip':
                try:
                    ipaddress.ip_network(value, strict=False) if '/' in value else ipaddress.ip_address(value)
                except ValueError:
                    continue
            
            indicators.append(ThreatIndicator(
                id=hashlib.sha256(f"{feed.id}:{value}".encode()).hexdigest()[:16],
                feed_id=feed.id,
                indicator_type=indicator_type,
                value=value,
                confidence=default_confidence,
                severity=default_severity,
                source=feed.name,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            ))
        
        return indicators

    @staticmethod
    def parse_csv(content: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse CSV feed."""
        import csv
        indicators = []
        parser_config = feed.parser_config
        value_column = parser_config.get('value_column', 0)
        type_column = parser_config.get('type_column', None)
        confidence_column = parser_config.get('confidence_column', None)
        severity_column = parser_config.get('severity_column', None)
        description_column = parser_config.get('description_column', None)
        skip_header = parser_config.get('skip_header', True)
        
        reader = csv.reader(content.split('\n'))
        rows = list(reader)
        
        start_row = 1 if skip_header and rows else 0
        
        for row in rows[start_row:]:
            if not row or len(row) <= value_column:
                continue
            
            value = row[value_column].strip()
            if not value:
                continue
            
            indicator_type = 'ip'  # default
            if type_column is not None and len(row) > type_column:
                indicator_type = row[type_column].strip().lower()
            
            confidence = 75
            if confidence_column is not None and len(row) > confidence_column:
                try:
                    confidence = int(row[confidence_column])
                except ValueError:
                    pass
            
            severity = 'MEDIUM'
            if severity_column is not None and len(row) > severity_column:
                severity = row[severity_column].strip().upper()
            
            description = ''
            if description_column is not None and len(row) > description_column:
                description = row[description_column].strip()
            
            indicators.append(ThreatIndicator(
                id=hashlib.sha256(f"{feed.id}:{value}".encode()).hexdigest()[:16],
                feed_id=feed.id,
                indicator_type=indicator_type,
                value=value,
                confidence=confidence,
                severity=severity,
                description=description,
                source=feed.name,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            ))
        
        return indicators

    @staticmethod
    def parse_json(content: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse JSON feed."""
        indicators = []
        parser_config = feed.parser_config
        data = json.loads(content)
        
        # Handle different JSON structures
        items = data
        if isinstance(data, dict):
            # Try common keys
            for key in ['indicators', 'data', 'results', 'objects', 'iocs']:
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    break
            if isinstance(items, dict):
                items = [items]
        
        if not isinstance(items, list):
            return indicators
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            # Extract value
            value = None
            for key in ['value', 'indicator', 'ip', 'domain', 'url', 'hash', 'ioc']:
                if key in item:
                    value = str(item[key]).strip()
                    break
            
            if not value:
                continue
            
            # Extract type
            indicator_type = item.get('type', item.get('indicator_type', 'ip')).lower()
            
            # Extract other fields
            confidence = item.get('confidence', item.get('score', 75))
            if isinstance(confidence, str):
                try:
                    confidence = int(confidence)
                except ValueError:
                    confidence = 75
            
            severity = item.get('severity', item.get('risk', 'MEDIUM')).upper()
            description = item.get('description', item.get('comment', ''))
            tags = item.get('tags', item.get('labels', []))
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',')]
            
            references = item.get('references', item.get('source', []))
            if isinstance(references, str):
                references = [references]
            
            first_seen = None
            if 'first_seen' in item:
                try:
                    first_seen = datetime.fromisoformat(item['first_seen'].replace('Z', '+00:00'))
                except Exception:
                    pass
            
            last_seen = None
            if 'last_seen' in item:
                try:
                    last_seen = datetime.fromisoformat(item['last_seen'].replace('Z', '+00:00'))
                except Exception:
                    pass
            
            expires_at = None
            if 'expires' in item or 'valid_until' in item:
                try:
                    exp_str = item.get('expires') or item.get('valid_until')
                    expires_at = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
                except Exception:
                    pass
            
            indicators.append(ThreatIndicator(
                id=hashlib.sha256(f"{feed.id}:{value}".encode()).hexdigest()[:16],
                feed_id=feed.id,
                indicator_type=indicator_type,
                value=value,
                confidence=confidence,
                severity=severity,
                tags=tags,
                description=description,
                first_seen=first_seen or datetime.now(),
                last_seen=last_seen or datetime.now(),
                expires_at=expires_at,
                source=feed.name,
                references=references,
            ))
        
        return indicators

    @staticmethod
    def parse_stix(content: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse STIX/STIX2 feed (simplified)."""
        indicators = []
        try:
            data = json.loads(content)
            
            # STIX 2.x bundle
            if isinstance(data, dict) and data.get('type') == 'bundle':
                objects = data.get('objects', [])
            elif isinstance(data, list):
                objects = data
            else:
                objects = [data]
            
            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                
                obj_type = obj.get('type', '')
                
                # Indicator objects
                if obj_type == 'indicator':
                    pattern = obj.get('pattern', '')
                    # Parse STIX pattern (simplified)
                    # e.g., "[ipv4-addr:value = '192.168.1.1']"
                    import re
                    match = re.search(r"(\w+):\w+\s*=\s*['\"]([^'\"]+)['\"]", pattern)
                    if match:
                        stix_type, value = match.groups()
                        type_map = {
                            'ipv4-addr': 'ip',
                            'ipv6-addr': 'ip',
                            'domain-name': 'domain',
                            'url': 'url',
                            'file': 'hash',  # would need hashes
                        }
                        indicator_type = type_map.get(stix_type, 'unknown')
                        
                        indicators.append(ThreatIndicator(
                            id=obj.get('id', hashlib.sha256(f"{feed.id}:{value}".encode()).hexdigest()[:16]),
                            feed_id=feed.id,
                            indicator_type=indicator_type,
                            value=value,
                            confidence=obj.get('confidence', 75),
                            severity=obj.get('labels', ['MEDIUM'])[0].upper() if obj.get('labels') else 'MEDIUM',
                            description=obj.get('description', ''),
                            tags=obj.get('labels', []),
                            source=feed.name,
                            references=[obj.get('external_references', [{}])[0].get('url', '')] if obj.get('external_references') else [],
                            first_seen=datetime.fromisoformat(obj['created'].replace('Z', '+00:00')) if obj.get('created') else datetime.now(),
                            last_seen=datetime.fromisoformat(obj['modified'].replace('Z', '+00:00')) if obj.get('modified') else datetime.now(),
                        ))
                
                # Observable objects (STIX 1.x style)
                elif obj_type in ('ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'file'):
                    value = obj.get('value', '')
                    if value:
                        type_map = {
                            'ipv4-addr': 'ip',
                            'ipv6-addr': 'ip',
                            'domain-name': 'domain',
                            'url': 'url',
                            'file': 'hash',
                        }
                        indicators.append(ThreatIndicator(
                            id=obj.get('id', hashlib.sha256(f"{feed.id}:{value}".encode()).hexdigest()[:16]),
                            feed_id=feed.id,
                            indicator_type=type_map.get(obj_type, 'unknown'),
                            value=value,
                            confidence=75,
                            severity='MEDIUM',
                            source=feed.name,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                        ))
        
        except Exception as e:
            logger.error(f"STIX parsing error: {e}")
        
        return indicators


class ThreatIntelManager:
    """Manages threat intelligence feeds and indicators."""

    def __init__(self):
        self.config = get_config()
        ti_config = self.config.get('threat_intelligence', {})
        self.enabled = ti_config.get('enabled', True)
        self.cache_dir = Path(self.config['general']['data_dir']) / 'threat_intel'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.feeds: Dict[str, ThreatFeed] = {}
        self.indicators: Dict[str, ThreatIndicator] = {}  # key = "type:value"
        self.indicators_by_type: Dict[str, Set[str]] = defaultdict(set)  # type -> set of values
        
        self.lock = threading.RLock()
        self.running = False
        self.update_thread: Optional[threading.Thread] = None
        
        self.stats = {
            'feeds_configured': 0,
            'feeds_active': 0,
            'total_indicators': 0,
            'last_update': None,
            'update_errors': 0,
        }
        
        self._load_default_feeds()
        self._load_cached_indicators()

    def _load_default_feeds(self):
        """Load default threat intelligence feeds."""
        default_feeds = [
            # AbuseIPDB - requires API key (free tier available)
            ThreatFeed(
                id="abuseipdb",
                name="AbuseIPDB",
                url="https://api.abuseipdb.com/api/v2/blacklist",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.JSON,
                enabled=False,  # Requires API key
                update_interval_hours=12,
                auth={"type": "apikey", "header": "Key"},
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 80,
                    "severity": "HIGH",
                }
            ),
            
            # AlienVault OTX - requires API key
            ThreatFeed(
                id="alienvault_otx",
                name="AlienVault OTX",
                url="https://otx.alienvault.com/api/v1/pulses/subscribed",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.JSON,
                enabled=False,  # Requires API key
                update_interval_hours=12,
                auth={"type": "apikey", "header": "X-OTX-API-KEY"},
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 85,
                    "severity": "HIGH",
                }
            ),
            
            # Spamhaus DROP list (no auth required)
            ThreatFeed(
                id="spamhaus_drop",
                name="Spamhaus DROP List",
                url="https://www.spamhaus.org/drop/drop.txt",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=24,
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 90,
                    "severity": "HIGH",
                    "comment_char": ";",
                    "delimiter": ";",
                }
            ),
            
            # Spamhaus EDROP list
            ThreatFeed(
                id="spamhaus_edrop",
                name="Spamhaus EDROP List",
                url="https://www.spamhaus.org/drop/edrop.txt",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=24,
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 90,
                    "severity": "HIGH",
                    "comment_char": ";",
                    "delimiter": ";",
                }
            ),
            
            # Emerging Threats blocklist
            ThreatFeed(
                id="emerging_threats",
                name="Emerging Threats Blocklist",
                url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=12,
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 85,
                    "severity": "HIGH",
                    "comment_char": "#",
                }
            ),
            
            # FireHOL blocklist
            ThreatFeed(
                id="firehol_level1",
                name="FireHOL Level 1",
                url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=24,
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 80,
                    "severity": "MEDIUM",
                    "comment_char": "#",
                }
            ),
            
            # FireHOL Level 2
            ThreatFeed(
                id="firehol_level2",
                name="FireHOL Level 2",
                url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=24,
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 70,
                    "severity": "MEDIUM",
                    "comment_char": "#",
                }
            ),
            
            # FeodoTracker (C2 IPs)
            ThreatFeed(
                id="feodotracker",
                name="FeodoTracker C2 IPs",
                url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=6,
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 95,
                    "severity": "CRITICAL",
                    "comment_char": "#",
                }
            ),
            
            # SSLBL (SSL Blacklist - C2)
            ThreatFeed(
                id="sslbl",
                name="SSLBL C2 IPs",
                url="https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
                feed_type=FeedType.IP_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=6,
                parser_config={
                    "indicator_type": "ip",
                    "confidence": 90,
                    "severity": "CRITICAL",
                    "comment_char": "#",
                }
            ),
            
            # URLHaus (malware URLs)
            ThreatFeed(
                id="urlhaus",
                name="URLHaus Malware URLs",
                url="https://urlhaus.abuse.ch/downloads/text/",
                feed_type=FeedType.URL_BLOCKLIST,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=6,
                parser_config={
                    "indicator_type": "url",
                    "confidence": 95,
                    "severity": "CRITICAL",
                    "comment_char": "#",
                }
            ),
            
            # MalwareBazaar recent hashes
            ThreatFeed(
                id="malwarebazaar",
                name="MalwareBazaar Recent Hashes",
                url="https://bazaar.abuse.ch/export/txt/sha256/recent/",
                feed_type=FeedType.MALWARE_HASHES,
                format=FeedFormat.TXT,
                enabled=True,
                update_interval_hours=12,
                parser_config={
                    "indicator_type": "sha256",
                    "confidence": 90,
                    "severity": "HIGH",
                    "comment_char": "#",
                }
            ),
        ]
        
        for feed in default_feeds:
            self.feeds[feed.id] = feed
        
        self.stats['feeds_configured'] = len(self.feeds)

    def _load_cached_indicators(self):
        """Load cached indicators from disk."""
        cache_file = self.cache_dir / 'indicators.json'
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                loaded = 0
                for key, ind_data in data.items():
                    # Check expiration
                    if ind_data.get('expires_at'):
                        exp = datetime.fromisoformat(ind_data['expires_at'])
                        if datetime.now() > exp:
                            continue
                    
                    indicator = ThreatIndicator(
                        id=ind_data['id'],
                        feed_id=ind_data['feed_id'],
                        indicator_type=ind_data['indicator_type'],
                        value=ind_data['value'],
                        confidence=ind_data['confidence'],
                        severity=ind_data['severity'],
                        tags=ind_data.get('tags', []),
                        description=ind_data.get('description', ''),
                        first_seen=datetime.fromisoformat(ind_data['first_seen']) if ind_data.get('first_seen') else None,
                        last_seen=datetime.fromisoformat(ind_data['last_seen']) if ind_data.get('last_seen') else None,
                        expires_at=datetime.fromisoformat(ind_data['expires_at']) if ind_data.get('expires_at') else None,
                        source=ind_data.get('source', ''),
                        references=ind_data.get('references', []),
                        metadata=ind_data.get('metadata', {}),
                    )
                    
                    self.indicators[key] = indicator
                    self.indicators_by_type[indicator.indicator_type].add(key)
                    loaded += 1
                
                self.stats['total_indicators'] = loaded
                logger.info(f"Loaded {loaded} cached threat indicators")
            except Exception as e:
                logger.error(f"Failed to load cached indicators: {e}")

    def _save_cached_indicators(self):
        """Save indicators to disk."""
        cache_file = self.cache_dir / 'indicators.json'
        try:
            data = {}
            for key, indicator in self.indicators.items():
                if indicator.is_expired():
                    continue
                data[key] = {
                    'id': indicator.id,
                    'feed_id': indicator.feed_id,
                    'indicator_type': indicator.indicator_type,
                    'value': indicator.value,
                    'confidence': indicator.confidence,
                    'severity': indicator.severity,
                    'tags': indicator.tags,
                    'description': indicator.description,
                    'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None,
                    'last_seen': indicator.last_seen.isoformat() if indicator.last_seen else None,
                    'expires_at': indicator.expires_at.isoformat() if indicator.expires_at else None,
                    'source': indicator.source,
                    'references': indicator.references,
                    'metadata': indicator.metadata,
                }
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(data)} threat indicators to cache")
        except Exception as e:
            logger.error(f"Failed to save indicators cache: {e}")

    def add_feed(self, feed: ThreatFeed):
        """Add a custom threat feed."""
        self.feeds[feed.id] = feed
        self.stats['feeds_configured'] = len(self.feeds)

    def remove_feed(self, feed_id: str) -> bool:
        """Remove a feed and its indicators."""
        if feed_id not in self.feeds:
            return False
        
        # Remove indicators from this feed
        with self.lock:
            keys_to_remove = [k for k, ind in self.indicators.items() if ind.feed_id == feed_id]
            for key in keys_to_remove:
                ind = self.indicators.pop(key)
                self.indicators_by_type[ind.indicator_type].discard(key)
            
            del self.feeds[feed_id]
            self.stats['feeds_configured'] = len(self.feeds)
            self.stats['total_indicators'] = len(self.indicators)
        
        return True

    def enable_feed(self, feed_id: str, enabled: bool = True) -> bool:
        """Enable or disable a feed."""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = enabled
            return True
        return False

    def update_feed(self, feed_id: str) -> bool:
        """Update a specific feed."""
        if feed_id not in self.feeds:
            return False
        
        feed = self.feeds[feed_id]
        if not feed.enabled:
            return False
        
        try:
            logger.info(f"Updating threat feed: {feed.name}")
            
            import requests
            headers = feed.headers.copy()
            
            # Handle authentication
            if feed.auth:
                auth_type = feed.auth.get('type')
                if auth_type == 'apikey':
                    header_name = feed.auth.get('header', 'Authorization')
                    api_key = feed.auth.get('key', '')
                    if api_key:
                        headers[header_name] = api_key
            
            response = requests.get(feed.url, headers=headers, timeout=60)
            response.raise_for_status()
            
            # Parse based on format
            indicators = []
            if feed.format == FeedFormat.TXT:
                indicators = FeedParser.parse_txt(response.text, feed)
            elif feed.format == FeedFormat.CSV:
                indicators = FeedParser.parse_csv(response.text, feed)
            elif feed.format == FeedFormat.JSON:
                indicators = FeedParser.parse_json(response.text, feed)
            elif feed.format == FeedFormat.STIX:
                indicators = FeedParser.parse_stix(response.text, feed)
            
            # Add indicators
            added = 0
            with self.lock:
                for indicator in indicators:
                    key = f"{indicator.indicator_type}:{indicator.value}"
                    
                    # Check if exists and update
                    if key in self.indicators:
                        existing = self.indicators[key]
                        # Keep highest confidence
                        if indicator.confidence > existing.confidence:
                            existing.confidence = indicator.confidence
                        # Update last_seen
                        existing.last_seen = datetime.now()
                        if indicator.expires_at:
                            existing.expires_at = indicator.expires_at
                    else:
                        self.indicators[key] = indicator
                        self.indicators_by_type[indicator.indicator_type].add(key)
                        added += 1
            
            feed.last_updated = datetime.now()
            feed.last_error = None
            feed.indicator_count = len([i for i in self.indicators.values() if i.feed_id == feed_id])
            self.stats['total_indicators'] = len(self.indicators)
            self.stats['last_update'] = datetime.now().isoformat()
            
            logger.info(f"Feed {feed.name} updated: {added} new indicators, {feed.indicator_count} total")
            
            self._save_cached_indicators()
            return True
            
        except Exception as e:
            feed.last_error = str(e)
            self.stats['update_errors'] += 1
            logger.error(f"Failed to update feed {feed.name}: {e}")
            return False

    def update_all_feeds(self):
        """Update all enabled feeds."""
        logger.info("Updating all threat intelligence feeds")
        for feed_id, feed in self.feeds.items():
            if feed.enabled:
                self.update_feed(feed_id)
        
        self.stats['feeds_active'] = sum(1 for f in self.feeds.values() if f.enabled and f.last_error is None)

    def check_ip(self, ip: str) -> List[ThreatIndicator]:
        """Check if an IP matches any threat indicators."""
        matches = []
        with self.lock:
            for key in self.indicators_by_type.get('ip', set()):
                indicator = self.indicators.get(key)
                if indicator and not indicator.is_expired() and indicator.matches_ip(ip):
                    matches.append(indicator)
        return matches

    def check_domain(self, domain: str) -> List[ThreatIndicator]:
        """Check if a domain matches any threat indicators."""
        matches = []
        with self.lock:
            for key in self.indicators_by_type.get('domain', set()):
                indicator = self.indicators.get(key)
                if indicator and not indicator.is_expired() and indicator.matches_domain(domain):
                    matches.append(indicator)
        return matches

    def check_url(self, url: str) -> List[ThreatIndicator]:
        """Check if a URL matches any threat indicators."""
        matches = []
        with self.lock:
            for key in self.indicators_by_type.get('url', set()):
                indicator = self.indicators.get(key)
                if indicator and not indicator.is_expired() and indicator.matches_url(url):
                    matches.append(indicator)
        return matches

    def check_hash(self, hash_value: str) -> List[ThreatIndicator]:
        """Check if a file hash matches any threat indicators."""
        matches = []
        with self.lock:
            for ind_type in ('md5', 'sha1', 'sha256', 'hash'):
                for key in self.indicators_by_type.get(ind_type, set()):
                    indicator = self.indicators.get(key)
                    if indicator and not indicator.is_expired() and indicator.matches_hash(hash_value):
                        matches.append(indicator)
        return matches

    def get_indicator_stats(self) -> Dict[str, int]:
        """Get indicator counts by type."""
        with self.lock:
            return {itype: len(values) for itype, values in self.indicators_by_type.items()}

    def get_feed_status(self) -> List[Dict]:
        """Get status of all feeds."""
        with self.lock:
            return [
                {
                    'id': feed.id,
                    'name': feed.name,
                    'enabled': feed.enabled,
                    'feed_type': feed.feed_type.value,
                    'indicator_count': feed.indicator_count,
                    'last_updated': feed.last_updated.isoformat() if feed.last_updated else None,
                    'last_error': feed.last_error,
                }
                for feed in self.feeds.values()
            ]

    def start(self):
        """Start background feed updates."""
        if self.running:
            return
        
        self.running = True
        
        # Initial update
        self.update_all_feeds()
        
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        
        logger.info("Threat Intelligence Manager started")

    def stop(self):
        """Stop background updates."""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=10)
        logger.info("Threat Intelligence Manager stopped")

    def _update_loop(self):
        """Background update loop."""
        while self.running:
            # Sleep in small increments
            for _ in range(3600):  # Check every hour
                if not self.running:
                    break
                time.sleep(1)
            
            if self.running:
                # Update feeds that are due
                now = datetime.now()
                for feed_id, feed in self.feeds.items():
                    if not feed.enabled:
                        continue
                    if feed.last_updated:
                        next_update = feed.last_updated + timedelta(hours=feed.update_interval_hours)
                        if now >= next_update:
                            self.update_feed(feed_id)
                    else:
                        self.update_feed(feed_id)

    def get_blocklist_for_blocker(self) -> Dict[str, List[str]]:
        """Get blocklists formatted for the IP blocker."""
        with self.lock:
            ips = []
            for key in self.indicators_by_type.get('ip', set()):
                indicator = self.indicators.get(key)
                if indicator and not indicator.is_expired() and indicator.confidence >= 70:
                    ips.append(indicator.value)
            
            # Deduplicate
            unique_ips = list(set(ips))
        
        return {'ips': unique_ips}


def get_threat_intel_manager() -> ThreatIntelManager:
    """Get singleton threat intelligence manager instance."""
    if not hasattr(get_threat_intel_manager, '_instance'):
        get_threat_intel_manager._instance = ThreatIntelManager()
    return get_threat_intel_manager._instance