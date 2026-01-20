from datetime import datetime
from typing import List, Optional, Dict
import csv
import sqlite3

'''Functions and classes needed to extract and normalize security events from various log formats.:
- SecurityEvent class to represent normalized events.
- convert_ssh_alerts() -- convert raw SSH events to SecurityEvent instances
- convert_sudo_command_alerts() -- convert raw sudo command events to SecurityEvent instances
- convert_sudo_burst_alerts() -- convert sudo burst events to SecurityEvent instances
- export_to_csv() -- export a list of SecurityEvent instances to a CSV file
- export_to_sqlite() -- export a list of SecurityEvent instances to a SQLite database
- create_powerbi_view() -- create a Power BI view from a list of SecurityEvent instances
- '''

class SecurityEvent:
    """Normalized security event - all detection scripts convert to this format."""
    
    def __init__(
        self,
        timestamp: datetime,
        event_type: str,           # 'ssh_failed_login', 'sudo_command', etc.
        severity: str,             # 'Low', 'Medium', 'High', 'Critical'
        username: str,
        source_ip: Optional[str] = None,
        secondary_user: Optional[str] = None,  # For sudo
        command: Optional[str] = None,
        threat_category: Optional[str] = None,
        event_count: int = 1,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        raw_log_line: Optional[str] = None
    ):
        # Initialize all attributes
        self.timestamp = timestamp
        self.event_type = event_type
        self.severity = severity
        self.username = username
        self.source_ip = source_ip
        self.secondary_user = secondary_user
        self.command = command
        self.threat_category = threat_category
        self.event_count = event_count
        self.window_start = window_start or timestamp
        self.window_end = window_end or timestamp
        self.raw_log_line = raw_log_line
    
    def to_dict(self) -> Dict:
        # Convert the SecurityEvent to a dictionary for exporting
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'username': self.username,
            'secondary_user': self.secondary_user,
            'command': self.command,
            'threat_category': self.threat_category,
            'event_count': self.event_count,
            'window_start': self.window_start.isoformat(),
            'window_end': self.window_end.isoformat(),
            'raw_log_line': self.raw_log_line
        }

def convert_ssh_alerts(alerts: List[Dict]) -> List[SecurityEvent]:
    """Convert detect_ssh.py alerts to canonical format."""
    events = []
    for alert in alerts:
        event = SecurityEvent(
            timestamp=alert['last_attempt'],
            event_type='ssh_failed_login',
            severity=alert['severity'],
            username='unknown',  # Note: you may need to track this
            source_ip=alert['ip'],
            event_count=alert['count'],
            window_start=alert['first_attempt'],
            window_end=alert['last_attempt'],
            threat_category='Brute Force'
        )
        events.append(event)
    return events


def convert_sudo_command_alerts(alerts: List[Dict]) -> List[SecurityEvent]:
    """Convert detect_sudo.py command alerts."""
    events = []
    for alert in alerts:
        event = SecurityEvent(
            timestamp=alert['time_accessed'],
            event_type='sudo_suspicious_command',
            severity=alert['severity_level'],
            username=alert['invoking_user'],
            secondary_user=alert['target_user'],
            command=alert['command'],
            threat_category=alert['category']
        )
        events.append(event)
    return events


def convert_sudo_burst_alerts(alerts: List[Dict]) -> List[SecurityEvent]:
    """Convert detect_sudo.py burst alerts."""
    events = []
    for alert in alerts:
        event = SecurityEvent(
            timestamp=alert['last_attempt'],
            event_type='sudo_burst',
            severity=alert['severity'],
            username=alert['invoking_user'],
            event_count=alert['count'],
            window_start=alert['first_attempt'],
            window_end=alert['last_attempt'],
            threat_category='Privilege Escalation'
        )
        events.append(event)
    return events

def export_to_csv(events: List[SecurityEvent], output_file: str = 'security_events.csv'):
    # Export to CSV for Power BI 
    
    fieldnames = [
        'timestamp', 'event_type', 'severity', 'source_ip',
        'username', 'secondary_user', 'command', 'threat_category',
        'event_count', 'window_start', 'window_end'
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow(event.to_dict())

    print(f"Exported {len(events)} events to {output_file}")

