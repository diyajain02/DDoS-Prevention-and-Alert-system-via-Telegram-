# Light-SOC

**Lightweight SOC with NGFW capabilities and AI-powered incident reporting**

A simpler alternative to Wazuh that combines:
- **Log ingestion** - SSH auth.log parsing (extensible to other sources)
- **Detection engine** - Correlation rules for brute-force, invalid user enumeration, root login attempts
- **AI Analysis** - Local LLM (Ollama) powered incident analysis and report generation
- **NGFW Blocking** - Automatic IP blocking via nftables/iptables
- **Multi-format Reports** - Markdown, JSON, HTML incident reports

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  auth.log   │────▶│ Log Parser   │────▶│ Detection   │────▶│ AI Analyzer  │
│  (SSH)      │     │ (regex)      │     │ Engine      │     │ (Ollama)     │
└─────────────┘     └──────────────┘     └──────┬──────┘     └──────┬───────┘
                                                 │                   │
                                    ┌────────────┴────────────┐      │
                                    ▼                         ▼      ▼
                              ┌───────────┐           ┌────────────┐ ┌──────────┐
                              │  Blocker  │           │  Reporter  │ │  Alerts  │
                              │ (nftables)│           │ (MD/JSON/  │ │ (webhook)│
                              └───────────┘           │  HTML)     │ └──────────┘
                                                      └────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| **SSH Brute-Force Detection** | Configurable thresholds (default: 5 failures in 5 min) |
| **Invalid User Enumeration** | Detects username enumeration attempts |
| **Root Login Attempts** | High-severity alert on root login attempts |
| **AI-Powered Analysis** | Local Ollama LLM generates structured incident reports |
| **Auto-Blocking** | nftables/iptables integration with whitelist support |
| **Multi-Format Reports** | Markdown, JSON, HTML output |
| **Persistence** | Survives restarts - blocks reapplied on startup |
| **CLI Management** | Manual block/unblock/status commands |

## Requirements

- Python 3.10+
- Linux with nftables (preferred) or iptables
- Ollama running locally with a model (llama3.1:8b, mistral, codellama, etc.)
- Root privileges for firewall management

## Installation

```bash
# Clone and install
git clone https://github.com/yourusername/light-soc
cd light-soc

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .[dev]

# Install Ollama and pull a model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b
```

## Configuration

Edit `/opt/data/light-soc/config/config.yaml` (created on first run):

```yaml
general:
  log_level: "INFO"
  data_dir: "/opt/data/light-soc"

log_sources:
  - name: "ssh-auth"
    type: "file"
    path: "/var/log/auth.log"
    parser: "ssh_auth"
    enabled: true

rules:
  ssh_bruteforce:
    enabled: true
    max_failures: 5
    time_window_seconds: 300
    block_duration_seconds: 3600
    severity: "HIGH"

ai_analyzer:
  enabled: true
  provider: "ollama"
  model: "llama3.1:8b"
  base_url: "http://localhost:11434"

blocker:
  enabled: true
  backend: "nftables"
  whitelist:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
```

## Usage

### Run as Daemon (requires root)

```bash
sudo .venv/bin/light-soc -c /opt/data/light-soc/config/config.yaml
```

### CLI Commands

```bash
# Show status
light-soc --status

# Manually block an IP
light-soc --block 192.168.1.100 --reason "Suspicious activity" --duration 7200

# Unblock an IP
light-soc --unblock 192.168.1.100

# List blocked IPs
light-soc --list-blocked

# List incidents
light-soc --list-incidents

# Test parse a log file
light-soc --test-parse /var/log/auth.log
```

## Sample Report Output

### Markdown Report (`reports/incident_192_168_1_100_20240115_143022.md`)

```markdown
# Incident Report: SSH Brute-Force Attack

**Severity:** HIGH  
**Attacker IP:** 192.168.1.100  
**Total Attempts:** 47  
**Successful:** No  
**Confidence:** 85%  
**Generated:** 2024-01-15T14:30:22.123456

## Targeted Usernames
root, admin, ubuntu, test, user

## Timeline of Events
- **2024-01-15T14:25:10** — Failed login attempt: User: root
- **2024-01-15T14:25:15** — Failed login attempt: User: admin
- **2024-01-15T14:25:20** — Failed login attempt: User: ubuntu
...

## Recommended Mitigation
- Block IP 192.168.1.100 at firewall (nftables/iptables)
- Enable fail2ban for SSH protection
- Enforce SSH key-based authentication only
- Disable root login (PermitRootLogin no)
```

## Extending Log Sources

Add new parsers in `src/log_parser.py` and register in config:

```yaml
log_sources:
  - name: "nginx-access"
    type: "file"
    path: "/var/log/nginx/access.log"
    parser: "nginx_access"
    enabled: true
```

## Systemd Service

Create `/etc/systemd/system/light-soc.service`:

```ini
[Unit]
Description=Light-SOC Daemon
After=network.target ollama.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/data/light-soc
ExecStart=/opt/data/light-soc/.venv/bin/light-soc -c /opt/data/light-soc/config/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now light-soc
```

## License

MIT