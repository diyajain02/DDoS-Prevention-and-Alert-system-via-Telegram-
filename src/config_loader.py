"""Configuration loader for Light-SOC."""
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import threading


_config: Optional[Dict[str, Any]] = None
_config_lock = threading.Lock()


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    global _config
    with _config_lock:
        if _config is not None:
            return _config

        if config_path is None:
            config_path = "/opt/data/light-soc/config/config.yaml"

        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(path, 'r') as f:
            _config = yaml.safe_load(f)

        # Resolve paths relative to config file directory
        base_dir = path.parent.parent
        if 'general' in _config:
            for key in ['data_dir', 'reports_dir', 'blocked_ips_dir', 'logs_dir']:
                if key in _config['general']:
                    val = _config['general'][key]
                    if not Path(val).is_absolute():
                        _config['general'][key] = str(base_dir / val)

        return _config


def get_config() -> Dict[str, Any]:
    """Get cached config, loading if necessary."""
    if _config is None:
        return load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Force reload configuration."""
    global _config
    with _config_lock:
        _config = None
        return load_config(config_path)