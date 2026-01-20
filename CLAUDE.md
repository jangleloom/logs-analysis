# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cybersecurity log analysis toolkit for detecting security threats in Linux system logs. The project focuses on analyzing authentication and sudo logs to identify brute force attacks, suspicious privilege escalation, and other security anomalies.

## Running Scripts

All scripts are standalone Python modules with no external dependencies (only standard library).

**SSH Brute Force Detection (batch analysis):**
```bash
python detect_ssh.py
```
- Analyzes `sample_auth.log` for SSH brute force attempts
- Uses sliding window algorithm (default: 3 attempts in 120 seconds)
- Outputs alerts with severity levels (Low, Medium, High, Critical)

**Sudo Command Monitoring:**
```bash
python detect_sudo.py
```
- Analyzes `sudo_sample.log` for suspicious sudo activity
- Two detection modes: command-based (credential access, persistence, download/execute) and frequency-based (burst detection)
- Categorizes threats and assigns severity levels

**Real-time SSH Monitoring:**
```bash
python monitor.py
```
- Continuously monitors log file for new entries (file tail mode)
- Alerts on brute force attempts in real-time
- Press Ctrl+C to stop

**Utility - Log Expansion:**
```bash
python expand_logs.py
```
- Duplicates `ssh_sample.csv` 100 times into `ssh_big_sample.csv` for performance testing

## Architecture

### Core Pattern: Event-Driven Detection Engine

All detection scripts follow the same architectural pattern:

1. **Regex-based Log Parsing**: Each script defines regex patterns to extract structured data from unstructured syslog entries
2. **Event Normalization**: Raw log lines are parsed into dictionaries with normalized fields (timestamp, user, IP, etc.)
3. **Detection Algorithms**:
   - **Sliding window** (detect_ssh.py, monitor.py): Uses `defaultdict(deque)` to track events within time windows
   - **Pattern matching** (detect_sudo.py): Rule-based threat categorization
   - **Frequency analysis** (detect_sudo.py): Burst detection using sliding windows
4. **Severity Scoring**: Count-based or pattern-based severity assignment
5. **Alert Generation**: Structured alert dictionaries with relevant IOCs

### Shared Components Across Scripts

**Timestamp Parsing:**
- All scripts parse syslog timestamps: `MMM DD HH:MM:SS` format
- Convert to Python `datetime` objects using the `MONTHS` dictionary
- Require a `year` parameter (defaults to 2026) since syslog format lacks year

**Sliding Window Algorithm:**
Used in [detect_ssh.py](detect_ssh.py) and [monitor.py](monitor.py):
```python
# Pattern: defaultdict(deque) to group events by key (IP or user)
ip_events = defaultdict(deque)
ip_events[ip].append(current_time)

# Remove events outside the time window
while ip_events[ip] and (current_time - ip_events[ip][0]).total_seconds() > window_seconds:
    ip_events[ip].popleft()

# Trigger alert when threshold reached
if len(ip_events[ip]) == threshold:
    # Generate alert (only once per key to avoid duplicates)
```

**Severity Calculation:**
- **Count-based** (SSH brute force): `>=20=Critical, >=10=High, >=5=Medium, <5=Low`
- **Pattern-based** (sudo commands): Matches against threat categories (Credential Access, Persistence, Download/Execute)

### Script-Specific Details

**detect_ssh.py:**
- Regex: `FAILED_LOGIN` matches both "invalid user" and valid user failed logins
- IOCs extracted: timestamp, username, source IP
- Function `detect_failed_logins()` is the main analysis engine
- Returns list of alert dictionaries

**detect_sudo.py:**
- Regex: `SUDO_USED` captures invoking user and key-value blob
- Parses semicolon-delimited sudo log details into structured dict
- Two detection functions:
  - `detect_sus_command()`: Event-based threat detection
  - `detect_sudo_burst()`: Frequency-based anomaly detection
- `severity_commands()` uses pattern matching against threat rule list
- `main()` combines both detection modes into unified alert stream

**monitor.py:**
- Real-time variant of detect_ssh.py
- Uses `f.seek(0, 2)` to start at end of file
- Continuous `readline()` loop with 0.5s sleep
- Tracks `alerted_ips` set to prevent duplicate alerts for same IP

### Data Files

**Sample Logs:**
- `sample_auth.log`: SSH authentication log samples (syslog format)
- `sudo_sample.log`: Sudo command logs
- `ssh_sample.csv`: CSV-formatted SSH data
- `ssh_big_sample.csv`: 100x expanded version for testing

Note: `*.log` files are gitignored (see .gitignore), but samples are committed for testing.

## Key Design Decisions

**No External Dependencies**: Pure Python stdlib for portability and ease of deployment

**Log Format Support**: Designed for Linux syslog format (tested on auth.log and sudo logs)

**Stateful vs Stateless**:
- Batch scripts ([detect_ssh.py](detect_ssh.py), [detect_sudo.py](detect_sudo.py)) are stateless
- Monitor script ([monitor.py](monitor.py)) maintains in-memory state with `alerted_ips` tracking

**Alert Deduplication**:
- Batch: Trigger only when `len(ip_events[ip]) == threshold` (exact match)
- Monitor: Track alerted IPs in set to prevent re-alerting

**Timestamp Handling**: Year must be provided as parameter since syslog doesn't include it
