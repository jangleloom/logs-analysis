# Security Log Analysis Project

A cybersecurity log analysis toolkit for detecting SSH brute force attacks and suspicious sudo command usage, with Power BI integration for SOC-style dashboards.

## Project Structure

```
logs-analysis/
├── src/                   # Core detection scripts
│   ├── detect_ssh.py     # SSH brute force detection
│   ├── detect_sudo.py    # Sudo command analysis
│   └── monitor.py        # Real-time SSH monitoring
│
├── utils/                 # Utility scripts
│   ├── extract.py        # Main export pipeline (CSV/SQLite)
│   ├── generate_ssh_logs.py   # Generate SSH test data
│   ├── generate_sudo_logs.py  # Generate sudo test data
│   └── expand_logs.py    # Log expansion utility
│
├── data/                  # Log files
│   ├── samples/          # Original small sample logs
│   └── generated/        # Generated test data
│
├── output/               # Exported data for Power BI
│   ├── security_events.csv
│   └── security_events.db
│
└── docs/                 # Documentation
    ├── README.md         # Detailed documentation
    └── CLAUDE.md         # Claude Code instructions

```

## Quick Start

### 1. Generate Test Data
```bash
cd utils
python generate_ssh_logs.py
python generate_sudo_logs.py
```

### 2. Run Detection and Export
```bash
cd utils
python extract.py
```

This will analyze logs and export to:
- `../output/security_events.csv` - CSV for Power BI
- `../output/security_events.db` - SQLite with star schema

### 3. Connect to Power BI
- Open Power BI Desktop
- Get Data > CSV or SQLite Database
- Use files from `output/` directory
- Use the `vw_security_dashboard` view for pre-joined data

## Core Scripts

### Detection Scripts (`src/`)
- **detect_ssh.py**: Detects SSH brute force attacks using sliding window algorithm
- **detect_sudo.py**: Identifies suspicious sudo commands and burst patterns
- **monitor.py**: Real-time monitoring of SSH authentication logs

### Utility Scripts (`utils/`)
- **extract.py**: Main pipeline - collects, normalizes, and exports security events
- **generate_ssh_logs.py**: Creates synthetic SSH attack logs (200 unique IPs)
- **generate_sudo_logs.py**: Creates sudo logs with burst patterns (30 users)

## Data Schema

### SecurityEvent (Canonical Format)
All events are normalized to this schema:
- `timestamp`, `event_type`, `severity`
- `username`, `source_ip`, `secondary_user`
- `command`, `threat_category`
- `event_count`, `window_start`, `window_end`

### Star Schema (SQLite)
- **Fact**: `fact_security_events`
- **Dimensions**: `dim_severity`, `dim_event_type`, `dim_threat_category`
- **View**: `vw_security_dashboard` (Power BI ready)

## Event Types
- `ssh_failed_login` - SSH brute force attempts
- `sudo_suspicious_command` - Dangerous sudo commands
- `sudo_burst` - Rapid privilege escalation attempts

## Threat Categories (MITRE ATT&CK)
- Brute Force (T1110)
- Credential Access (T1003)
- Persistence (T1053)
- Download and Execute (T1059)
- Privilege Escalation (T1548)

## Documentation
See [docs/README.md](docs/README.md) for detailed documentation.
