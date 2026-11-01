"""File Integrity Monitoring (FIM) module for Light-SOC.
Monitors critical files for unauthorized changes using cryptographic hashes."""
import hashlib
import json
import os
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import logging

from src.config_loader import get_config
from src.models import LogEntry


logger = logging.getLogger(__name__)


@dataclass
class FileBaseline:
    """Cryptographic baseline for a monitored file."""
    path: str
    sha256: str
    size: int
    mtime: float
    mode: int
    owner: int
    group: int
    created_at: datetime = field(default_factory=datetime.now)
    last_checked: Optional[datetime] = None
    alert_count: int = 0


@dataclass
class FIMAlert:
    """Alert generated when a monitored file changes."""
    path: str
    alert_type: str  # modified, deleted, created, permissions, ownership
    old_baseline: Optional[FileBaseline]
    new_hash: Optional[str]
    new_size: Optional[int]
    new_mtime: Optional[float]
    new_mode: Optional[int]
    new_owner: Optional[int]
    new_group: Optional[int]
    timestamp: datetime = field(default_factory=datetime.now)
    severity: str = "HIGH"

    def to_log_entry(self) -> LogEntry:
        """Convert to LogEntry for processing through detection engine."""
        details = {
            'alert_type': self.alert_type,
            'path': self.path,
            'severity': self.severity,
        }
        if self.old_baseline:
            details['old_sha256'] = self.old_baseline.sha256
        if self.new_hash:
            details['new_sha256'] = self.new_hash

        return LogEntry(
            timestamp=self.timestamp,
            raw_line=f"FIM Alert: {self.alert_type.upper()} - {self.path}",
            source_ip="127.0.0.1",  # localhost for internal alerts
            username="system",
            event_type="fim_alert",
            details=details,
        )


class FIMMonitor:
    """File Integrity Monitor - tracks file changes via cryptographic hashes."""

    def __init__(self):
        self.config = get_config()
        fim_config = self.config.get('fim', {})
        self.enabled = fim_config.get('enabled', True)
        self.scan_interval = fim_config.get('scan_interval_seconds', 300)  # 5 min
        self.baseline_file = Path(self.config['general']['data_dir']) / 'fim_baseline.json'
        self.monitored_paths: List[str] = fim_config.get('monitored_paths', [])
        self.excluded_paths: Set[str] = set(fim_config.get('excluded_paths', []))
        self.recursive = fim_config.get('recursive', True)
        self.follow_symlinks = fim_config.get('follow_symlinks', False)
        self.alert_on_permissions = fim_config.get('alert_on_permissions', True)
        self.alert_on_ownership = fim_config.get('alert_on_ownership', True)

        self.baselines: Dict[str, FileBaseline] = {}
        self.alerts: List[FIMAlert] = []
        self.lock = threading.RLock()
        self.running = False
        self.scan_thread: Optional[threading.Thread] = None

        # Default monitored paths for Linux
        if not self.monitored_paths:
            self.monitored_paths = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/group',
                '/etc/sudoers',
                '/etc/ssh/sshd_config',
                '/etc/crontab',
                '/etc/hosts',
                '/etc/fstab',
                '/boot/grub/grub.cfg',
                '/bin',
                '/sbin',
                '/usr/bin',
                '/usr/sbin',
                '/lib',
                '/lib64',
            ]

        self._load_baseline()

    def _load_baseline(self):
        """Load existing baseline from disk."""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, 'r') as f:
                    data = json.load(f)
                for path, baseline_data in data.items():
                    self.baselines[path] = FileBaseline(
                        path=baseline_data['path'],
                        sha256=baseline_data['sha256'],
                        size=baseline_data['size'],
                        mtime=baseline_data['mtime'],
                        mode=baseline_data['mode'],
                        owner=baseline_data['owner'],
                        group=baseline_data['group'],
                        created_at=datetime.fromisoformat(baseline_data['created_at']),
                        last_checked=datetime.fromisoformat(baseline_data['last_checked']) if baseline_data.get('last_checked') else None,
                        alert_count=baseline_data.get('alert_count', 0),
                    )
                logger.info(f"Loaded FIM baseline with {len(self.baselines)} files")
            except Exception as e:
                logger.error(f"Failed to load FIM baseline: {e}")

    def _save_baseline(self):
        """Save baseline to disk."""
        try:
            data = {}
            for path, baseline in self.baselines.items():
                data[path] = {
                    'path': baseline.path,
                    'sha256': baseline.sha256,
                    'size': baseline.size,
                    'mtime': baseline.mtime,
                    'mode': baseline.mode,
                    'owner': baseline.owner,
                    'group': baseline.group,
                    'created_at': baseline.created_at.isoformat(),
                    'last_checked': baseline.last_checked.isoformat() if baseline.last_checked else None,
                    'alert_count': baseline.alert_count,
                }
            with open(self.baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save FIM baseline: {e}")

    def _compute_hash(self, filepath: Path) -> Optional[str]:
        """Compute SHA256 hash of a file."""
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, IOError):
            return None

    def _get_file_stat(self, filepath: Path) -> Optional[os.stat_result]:
        """Get file stat, handling symlinks."""
        try:
            if self.follow_symlinks:
                return filepath.stat()
            else:
                return filepath.lstat()
        except (OSError, IOError):
            return None

    def _should_monitor(self, filepath: Path) -> bool:
        """Check if a file should be monitored."""
        path_str = str(filepath)
        
        # Check exclusions
        for excluded in self.excluded_paths:
            if path_str.startswith(excluded):
                return False
        
        # Check if it's in monitored paths
        for monitored in self.monitored_paths:
            if path_str.startswith(monitored):
                return True
        
        return False

    def _scan_path(self, path: str):
        """Scan a single path (file or directory)."""
        filepath = Path(path)
        if not filepath.exists():
            return

        if filepath.is_file():
            if self._should_monitor(filepath):
                self._check_file(filepath)
        elif filepath.is_dir() and self.recursive:
            try:
                for root, dirs, files in os.walk(filepath, followlinks=self.follow_symlinks):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if self._should_monitor(Path(root) / d)]
                    
                    for file in files:
                        full_path = Path(root) / file
                        if self._should_monitor(full_path):
                            self._check_file(full_path)
            except (OSError, IOError) as e:
                logger.warning(f"Error scanning directory {path}: {e}")

    def _check_file(self, filepath: Path):
        """Check a single file against baseline."""
        stat = self._get_file_stat(filepath)
        if not stat:
            return

        path_str = str(filepath)
        current_hash = self._compute_hash(filepath)
        
        with self.lock:
            if path_str not in self.baselines:
                # New file - create baseline
                if current_hash:
                    self.baselines[path_str] = FileBaseline(
                        path=path_str,
                        sha256=current_hash,
                        size=stat.st_size,
                        mtime=stat.st_mtime,
                        mode=stat.st_mode,
                        owner=stat.st_uid,
                        group=stat.st_gid,
                    )
                    logger.debug(f"FIM: New baseline created for {path_str}")
                return

            baseline = self.baselines[path_str]
            baseline.last_checked = datetime.now()
            alerts = []

            # Check hash (content modification)
            if current_hash and current_hash != baseline.sha256:
                alerts.append(FIMAlert(
                    path=path_str,
                    alert_type='modified',
                    old_baseline=baseline,
                    new_hash=current_hash,
                    new_size=stat.st_size,
                    new_mtime=stat.st_mtime,
                    new_mode=stat.st_mode,
                    new_owner=stat.st_uid,
                    new_group=stat.st_gid,
                    severity='HIGH',
                ))
                baseline.sha256 = current_hash
                baseline.size = stat.st_size
                baseline.mtime = stat.st_mtime
                baseline.alert_count += 1

            # Check permissions
            if self.alert_on_permissions and stat.st_mode != baseline.mode:
                alerts.append(FIMAlert(
                    path=path_str,
                    alert_type='permissions',
                    old_baseline=baseline,
                    new_hash=current_hash,
                    new_size=stat.st_size,
                    new_mtime=stat.st_mtime,
                    new_mode=stat.st_mode,
                    new_owner=stat.st_uid,
                    new_group=stat.st_gid,
                    severity='MEDIUM',
                ))
                baseline.mode = stat.st_mode
                baseline.alert_count += 1

            # Check ownership
            if self.alert_on_ownership and (stat.st_uid != baseline.owner or stat.st_gid != baseline.group):
                alerts.append(FIMAlert(
                    path=path_str,
                    alert_type='ownership',
                    old_baseline=baseline,
                    new_hash=current_hash,
                    new_size=stat.st_size,
                    new_mtime=stat.st_mtime,
                    new_mode=stat.st_mode,
                    new_owner=stat.st_uid,
                    new_group=stat.st_gid,
                    severity='MEDIUM',
                ))
                baseline.owner = stat.st_uid
                baseline.group = stat.st_gid
                baseline.alert_count += 1

            # Add alerts
            for alert in alerts:
                self.alerts.append(alert)
                logger.warning(f"FIM Alert: {alert.alert_type.upper()} - {path_str}")

    def _check_deleted_files(self):
        """Check for deleted files in baseline."""
        with self.lock:
            deleted = []
            for path_str, baseline in self.baselines.items():
                if not Path(path_str).exists():
                    deleted.append(path_str)
                    self.alerts.append(FIMAlert(
                        path=path_str,
                        alert_type='deleted',
                        old_baseline=baseline,
                        new_hash=None,
                        new_size=None,
                        new_mtime=None,
                        new_mode=None,
                        new_owner=None,
                        new_group=None,
                        severity='CRITICAL',
                    ))
                    logger.warning(f"FIM Alert: DELETED - {path_str}")
            
            # Remove deleted files from baseline
            for path_str in deleted:
                del self.baselines[path_str]

    def scan(self):
        """Perform a full scan of all monitored paths."""
        logger.info("FIM: Starting scan")
        start_time = time.time()
        
        with self.lock:
            self.alerts.clear()

        # Scan monitored paths
        for path in self.monitored_paths:
            self._scan_path(path)

        # Check for deleted files
        self._check_deleted_files()

        # Save updated baseline
        self._save_baseline()

        elapsed = time.time() - start_time
        logger.info(f"FIM: Scan completed in {elapsed:.2f}s, {len(self.alerts)} alerts generated")

    def get_alerts(self) -> List[FIMAlert]:
        """Get alerts from last scan."""
        with self.lock:
            return list(self.alerts)

    def get_alerts_as_log_entries(self) -> List[LogEntry]:
        """Get alerts as LogEntry objects for detection engine."""
        with self.lock:
            return [alert.to_log_entry() for alert in self.alerts]

    def start(self):
        """Start background monitoring thread."""
        if self.running:
            return
        
        self.running = True
        self.scan_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.scan_thread.start()
        logger.info("FIM: Background monitoring started")

    def stop(self):
        """Stop background monitoring thread."""
        self.running = False
        if self.scan_thread:
            self.scan_thread.join(timeout=10)
        logger.info("FIM: Background monitoring stopped")

    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                self.scan()
            except Exception as e:
                logger.error(f"FIM scan error: {e}")
            
            # Sleep in small increments to allow quick shutdown
            for _ in range(self.scan_interval):
                if not self.running:
                    break
                time.sleep(1)

    def initialize_baseline(self):
        """Create initial baseline (run once on first setup)."""
        logger.info("FIM: Initializing baseline...")
        with self.lock:
            self.baselines.clear()
            self.alerts.clear()
        self.scan()
        logger.info(f"FIM: Baseline initialized with {len(self.baselines)} files")


def get_fim_monitor() -> FIMMonitor:
    """Get singleton FIM monitor instance."""
    if not hasattr(get_fim_monitor, '_instance'):
        get_fim_monitor._instance = FIMMonitor()
    return get_fim_monitor._instance