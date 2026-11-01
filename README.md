# Light-SOC

**Lightweight SOC with NGFW capabilities, DDoS prevention, and AI-powered incident reporting**

A simpler alternative to Wazuh that combines:
- **Log ingestion** - SSH auth.log parsing (extensible to other sources)
- **Detection engine** - Correlation rules for brute-force, invalid user enumeration, root login attempts
- **DDoS Detection** - 8 attack types with real-time analysis and auto-blocking
- **AI Analysis** - Local LLM (Ollama) powered incident analysis and report generation
- **NGFW Blocking** - Automatic IP blocking via nftables/iptables
- **Multi-format Reports** - Markdown, JSON, HTML incident reports
- **Alerting** - Telegram, Webhook, Email notifications
- **Web Dashboard** - Real-time monitoring UI (FastAPI + Tailwind + WebSocket)

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
                              │ (nftables)│           │ (MD/JSON/  │ │Telegram/ │
                              └───────────┘           │  HTML)     │ │ Webhook  │
                                                      └────────────┘ └──────────┘

┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Network    │────▶│ DDoS Detector│────▶│  Blocker    │
│  Traffic    │     │ (8 types)    │     │ (auto)      │
└─────────────┘     └──────────────┘     └─────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| **SSH Brute-Force Detection** | Configurable thresholds (default: 5 failures in 5 min) |
| **Invalid User Enumeration** | Detects username enumeration attempts |
| **Root Login Attempts** | High-severity alert on root login attempts |
| **DDoS Detection** | 8 attack types: SYN/UDP/ICMP/HTTP flood, Slowloris, DNS amplification, Volumetric, Connection exhaustion |
| **AI-Powered Analysis** | Local Ollama LLM generates structured incident reports |
| **Auto-Blocking** | nftables/iptables integration with whitelist support |
| **Multi-Format Reports** | Markdown, JSON, HTML output |
| **Telegram Alerts** | Real-time notifications via Bot API |
| **Webhook/Email Alerts** | Slack, Discord, Teams, PagerDuty, custom endpoints |
| **Persistence** | Survives restarts - blocks reapplied on startup |
| **CLI Management** | Manual block/unblock/status commands |
| **Web Dashboard** | Real-time monitoring at `http://localhost:8080` |

## Requirements

- Python 3.10+
- Linux with nftables (preferred) or iptables
- Ollama running locally with a model (llama3.1:8b, mistral, codellama, etc.)
- Root privileges for firewall management
- Telegram bot (optional, for alerts)

## Installation

```bash
# Clone and install
git clone https://github.com/diyajain02/DDoS-Prevention-and-Alert-system-via-Telegram-.git
cd DDoS-Prevention-and-Alert-system-via-Telegram-

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .

# Install Ollama and pull a model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b
```

## Configuration

1. **Copy the template:**
   ```bash
   cp config/config.yaml.template config/config.yaml
   ```

2. **Edit `config/config.yaml`** with your values:
   ```yaml
   alerting:
     telegram:
       enabled: true
       bot_token: "YOUR_BOT_TOKEN_FROM_BOTFATHER"
       chat_id: "YOUR_CHAT_ID_FROM_USERINFOBOT"
   
   blocker:
     whitelist:
       - "127.0.0.1/32"
       - "10.0.0.0/8"
       - "192.168.0.0/16"
   
   ddos:
     rules:
       syn_flood:
         pps_threshold: 100
         block_duration: 3600
   ```

3. **Start Ollama:**
   ```bash
   ollama serve
   ```

## Usage

### Run as Daemon (requires root for firewall)

```bash
sudo .venv/bin/light-soc -c config/config.yaml
```

### CLI Commands

```bash
# Show status (all modules)
light-soc --status

# DDoS specific commands
light-soc --ddos-status          # DDoS detector stats
light-soc --ddos-incidents       # List DDoS incidents
light-soc --ddos-ip 1.2.3.4      # Stats for specific IP

# Alerting commands
light-soc --alert-status         # Alert manager stats
light-soc --alert-list           # Recent alerts

# Manual IP management
light-soc --block 192.168.1.100 --reason "Suspicious activity" --duration 7200
light-soc --unblock 192.168.1.100
light-soc --list-blocked
light-soc --list-incidents

# Extended modules
light-soc --fim-scan
light-soc --vuln-scan
light-soc --sca-scan
light-soc --threat-intel-update
light-soc --threat-intel-check-ip 1.2.3.4

# Test parsing
light-soc --test-parse /var/log/auth.log
```

### Web Dashboard

Start the dashboard separately:

```bash
# Terminal 1: Main daemon
sudo .venv/bin/light-soc

# Terminal 2: Dashboard (no root needed)
DASHBOARD_PORT=8080 .venv/bin/python -m src.dashboard
```

Open `http://localhost:8080` - login with default credentials (change in config):
- Username: `admin`
- Password: `light-soc-admin`

Dashboard features:
- Real-time incident feed via WebSocket
- Blocked IP management
- Threat intelligence lookup
- DDoS incident monitoring
- System status panels

## Telegram Bot Setup (2 minutes)

1. Message `@BotFather` → `/newbot` → name it → copy **bot_token**
2. Message your bot → `/start`
3. Visit `https://api.telegram.org/bot<TOKEN>/getUpdates` → find `"chat":{"id":123456789}`
4. Add to `config.yaml`:
   ```yaml
   alerting:
     telegram:
       enabled: true
       bot_token: "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
       chat_id: "123456789"
   ```

## DDoS Attack Types Detected

| Type | Threshold | Default Block |
|------|-----------|---------------|
| SYN Flood | 100 SYN/s | 1 hour |
| UDP Flood | 500 UDP/s | 1 hour |
| ICMP Flood | 200 ICMP/s | 1 hour |
| HTTP Flood | 200 req/s, 50 conn/s | 1 hour |
| Slowloris | 50 half-open conns | 2 hours |
| DNS Amplification | 500 queries/s + 50 MB/s | 1 hour |
| Volumetric | 10K pps / 100 MB/s | 1 hour |
| Connection Exhaustion | 1000 concurrent / 200 conn/s | 1 hour |

All thresholds configurable in `config.yaml` under `ddos.rules`.

## Sample Report Output

### Markdown Report (`reports/incident_<IP>_<timestamp>.md`)

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
...

## Recommended Mitigation
- Block IP 192.168.1.100 at firewall (nftables/iptables)
- Enable fail2ban for SSH protection
- Enforce SSH key-based authentication only
- Disable root login (PermitRootLogin no)
```

### Telegram Alert Example

```
🚨 DDoS Attack Detected: Syn Flood 🚨

Attack Type: Syn Flood
Attacker IP: 203.0.113.50
Severity: CRITICAL
Status: ✅ BLOCKED
Confidence: 95%

Peak Traffic:
  • Packets/sec: 5,000
  • Bandwidth: 50.0 MB/s

Total Volume:
  • Packets: 50,000
  • Data: 500.0 MB

Started: 2024-01-15 14:30:22
Last Seen: 2024-01-15 14:30:27
```

## Systemd Service (Production)

Create `/etc/systemd/system/light-soc.service`:

```ini
[Unit]
Description=Light-SOC Daemon
After=network.target ollama.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/light-soc
ExecStart=/opt/light-soc/.venv/bin/light-soc -c /opt/light-soc/config/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now light-soc
```

Dashboard service (`/etc/systemd/system/light-soc-dashboard.service`):

```ini
[Unit]
Description=Light-SOC Dashboard
After=network.target

[Service]
Type=simple
User=light-soc
WorkingDirectory=/opt/light-soc
Environment=DASHBOARD_PORT=8080
ExecStart=/opt/light-soc/.venv/bin/python -m src.dashboard
Restart=always

[Install]
WantedBy=multi-user.target
```

## Extending

### Add New Log Parser

1. Add regex patterns in `src/log_parser.py`
2. Register in config:
   ```yaml
   log_sources:
     - name: "nginx-access"
       type: "file"
       path: "/var/log/nginx/access.log"
       parser: "nginx_access"
       enabled: true
   ```

### Add Custom DDoS Rule

```python
from src.ddos_detector import get_ddos_detector, DDoSRule, DDoSAttackType

detector = get_ddos_detector()
detector.add_rule(DDoSRule(
    attack_type=DDoSAttackType.CUSTOM,
    enabled=True,
    packets_per_second=500,
    block_duration_seconds=1800,
    severity="HIGH"
))
```

### Add Webhook Alert Channel

```yaml
alerting:
  webhook:
    enabled: true
    url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    timeout: 10
    retry_count: 3
```

## Project Structure

```
light-soc/
├── config/
│   ├── config.yaml.template    # Template (commit this)
│   └── config.yaml             # Your config (gitignored)
├── src/
│   ├── main.py                 # Daemon entry point
│   ├── ddos_detector.py        # DDoS detection engine
│   ├── alerting.py             # Telegram/Webhook/Email
│   ├── detection_engine.py     # SSH log correlation
│   ├── blocker.py              # nftables/iptables
│   ├── ai_analyzer.py          # Ollama integration
│   ├── report_generator.py     # MD/JSON/HTML reports
│   ├── log_parser.py           # SSH auth.log parser
│   ├── network_inspection.py   # IPS/DPI engine
│   ├── threat_intel.py         # Threat feeds
│   ├── fim.py                  # File integrity monitoring
│   ├── vulnerability_detector.py # CVE scanning
│   ├── sca.py                  # CIS benchmarks
│   ├── dashboard.py            # FastAPI web UI
│   ├── static/                 # Dashboard assets
│   ├── models.py               # Data models
│   └── config_loader.py        # YAML config
├── tests/
├── pyproject.toml
├── .gitignore
└── README.md
```

## Security Notes

- **Never commit `config/config.yaml`** - contains secrets (bot tokens, SMTP passwords)
- **Run as root** for firewall management (nftables/iptables)
- **Whitelist your networks** in `blocker.whitelist` to prevent lockout
- **Change dashboard credentials** in config before exposing to network
- **Use HTTPS** for webhook endpoints in production

## License

MIT