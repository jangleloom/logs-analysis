## SYSLOG SECURITY MONITOR
A python-based tool for analyzing Linux authentication logs to detect security threats like brute-force attacks and suspicious sudo usage

## Features 
1. SSH brute-force detection: Identify multiple failed login attempts from same IP
2. Sudo command monitoring: Track sudo usage patterns and privilege escalation attempts 
3. Real time monitoring  (monitor.py): Continuously watch files for suspicious activity
4. Security classification -- ie. critical, high, medium risk levels, helps to reduce noise
5. Adjustable threshold levels and time window for frequency-based detection
6. Detailed reports/alerts -- timestamp, user information, IP tracking

## Requirements
- Python 3.10+
- Standard library only (no external dependencies)

## Installation
```bash
git clone https://github.com/jangleloom/ssh-bruteforce-detector.git
cd ssh-bruteforce-detector
```

## Usage
### SSH Brute Force Detection (Batch)
Analyze authentication logs for failed SSH login patterns:
```bash
python detect_ssh.py
```Customize parameters:
```python
detect_failed_logins(
    file_path="sample_auth.log",  # Path to log file
    threshold=3,                    # Failed attempts to trigger alert
    window_seconds=120,             # Time window in seconds
    year=2026                       # Log year
)
```

### Real-time SSH Monitoring
Monitor log files continuously for new attacks:
```bash
python monitor.py
```

### Sudo Command Analysis
Track sudo usage and detect suspicious privilege escalation:
```bash
python detect_sudo.py
```
## How each tool works 

### SSH Brute Force Detection
1. **Parse Logs**: Extracts failed SSH login attempts using regex patterns
2. **Sliding Window**: Tracks attempts per IP within a configurable time window
3. **Threshold Detection**: Alerts when attempts exceed threshold
4. **Severity Assessment**: Categorizes attacks based on attempt count:
   - **Low**: 3-4 attempts
   - **Medium**: 5-9 attempts
   - **High**: 10-19 attempts
   - **Critical**: 20+ attempts

### Sudo Monitoring
- Tracks all sudo command executions
- Identifies users and commands executed with elevated privileges
- Monitors for unusual patterns or suspicious commands

## Example Output

### SSH Brute Force Alert
```
Found 1 brute force attempts:

IP: 203.0.113.5
  Failed attempts: 3
  Severity: Low
  First attempt: 2026-01-10 12:00:01
  Last attempt: 2026-01-10 12:00:20
```

### Real-time Monitoring
```
Starting real-time monitoring of sample_auth.log
Threshold: 3 attempts within 120 seconds

ALERT: Brute force detected!
IP: 203.0.113.5
Failed attempts: 3
Severity: Low
First attempt: 2026-01-10 12:00:01
Last attempt: 2026-01-10 12:00:20
--------------------------------------------------
```

## Supported Log Formats

### SSH kogs (syslog format)
```
Jan 10 12:00:01 server sshd[1001]: Failed password for invalid user admin from 203.0.113.5 port 53421 ssh2
```

### Sudo logs
```
Jan 10 14:30:15 server sudo: username : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/cat /etc/shadow
```

## Configuration

Each script can be configured by modifying parameters:

- `file_path`: Path to the log file to analyze
- `threshold`: Number of failed attempts to trigger an alert (default: 3)
- `window_seconds`: Time window for counting attempts (default: 120)
- `year`: Year for parsing logs (default: 2026)

## File structure

```
.
├── detect_ssh.py       # Batch analysis for SSH brute force attacks
├── monitor.py          # Real-time SSH monitoring
├── detect_sudo.py      # Sudo command analysis
├── sample_auth.log     # Sample SSH authentication log
├── sudo_sample.log     # Sample sudo log
└── README.md           # This file
```

## Future improvements

- [ ] Email/Slack notifications on detection
- [ ] Automatic IP blocking via firewall integration
- [ ] Log rotation handling
- [ ] State persistence across script restarts
- [ ] Failed sudo attempt detection
- [ ] Port scan detection
- [ ] Support for systemd journal logs
- [ ] Geolocation lookup for suspicious IPs

## Use Cases

- **Security Monitoring**: Detect ongoing attacks in real-time
- **Incident Response**: Analyze historical logs after a breach
- **Compliance**: Track privileged access for audit requirements
- **Threat Hunting**: Identify patterns of suspicious behavior
