from datetime import datetime
from typing import Optional, Dict

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
