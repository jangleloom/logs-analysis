from datetime import datetime
from typing import List, Optional, Dict
import csv
import sqlite3
import sys
import os

# Add src directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
sys.path.insert(0, os.path.join(project_root, 'src'))

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
        raw_log_line: Optional[str] = None,
        # Geolocation fields
        country: Optional[str] = None,
        city: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None
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
        # Geolocation
        self.country = country
        self.city = city
        self.latitude = latitude
        self.longitude = longitude
    
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
            'raw_log_line': self.raw_log_line,
            'country': self.country,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude
        }

def get_ip_location(ip_address: str) -> Dict[str, any]:
    """
    Get geolocation data for an IP address using ip-api.com (free, no API key needed).
    Returns dict with country, city, latitude, longitude.
    """
    if not ip_address:
        return {'country': None, 'city': None, 'latitude': None, 'longitude': None}

    try:
        import requests
        # Using ip-api.com free tier (45 requests/minute limit)
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=2)

        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon')
                }
    except Exception as e:
        print(f"Warning: Could not geolocate IP {ip_address}: {e}")

    return {'country': None, 'city': None, 'latitude': None, 'longitude': None}

def convert_ssh_alerts(alerts: List[Dict], enrich_geo=True) -> List[SecurityEvent]:
    """Convert detect_ssh.py alerts to canonical format with optional geolocation."""
    events = []
    for i, alert in enumerate(alerts):
        # Get geolocation data if enabled
        geo_data = {}
        if enrich_geo and alert.get('ip'):
            print(f"  Geolocating IP {i+1}/{len(alerts)}: {alert['ip']}", end='\r')
            geo_data = get_ip_location(alert['ip'])

        event = SecurityEvent(
            timestamp=alert['last_attempt'],
            event_type='ssh_failed_login',
            severity=alert['severity'],
            username='unknown',  # Note: you may need to track this
            source_ip=alert['ip'],
            event_count=alert['count'],
            window_start=alert['first_attempt'],
            window_end=alert['last_attempt'],
            threat_category='Brute Force',
            **geo_data  # Unpack country, city, latitude, longitude
        )
        events.append(event)

    if enrich_geo:
        print()  # New line after progress indicator

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
        'event_count', 'window_start', 'window_end', 'raw_log_line',
        'country', 'city', 'latitude', 'longitude'
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow(event.to_dict())

    print(f"Exported {len(events)} events to {output_file}")

def export_to_sqlite(events: List[SecurityEvent], db_file: str = 'security_events.db'):
    # Export to SQLite with star schema
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Create dimension tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dim_severity (
            severity_id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity_name TEXT UNIQUE NOT NULL,
            severity_score INTEGER,
            color_code TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dim_event_type (
            event_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type_name TEXT UNIQUE NOT NULL,
            event_category TEXT,
            description TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dim_threat_category (
            threat_category_id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_name TEXT UNIQUE NOT NULL,
            mitre_technique TEXT,
            description TEXT
        )
    ''')
    
    # Create fact table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fact_security_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            username TEXT,
            secondary_user TEXT,
            command TEXT,
            threat_category TEXT,
            event_count INTEGER DEFAULT 1,
            window_start TIMESTAMP,
            window_end TIMESTAMP,
            raw_log_line TEXT,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON fact_security_events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON fact_security_events(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON fact_security_events(source_ip)')
    
    # Populate dimension tables
    severities = [
        ('Low', 1, '#28a745'),
        ('Medium', 2, '#ffc107'),
        ('High', 3, '#fd7e14'),
        ('Critical', 4, '#dc3545')
    ]
    cursor.executemany('''
        INSERT OR IGNORE INTO dim_severity (severity_name, severity_score, color_code)
        VALUES (?, ?, ?)
    ''', severities)
    
    event_types = [
        ('ssh_failed_login', 'Authentication', 'SSH failed login attempt'),
        ('sudo_suspicious_command', 'Privilege Escalation', 'Suspicious sudo command'),
        ('sudo_burst', 'Privilege Escalation', 'Rapid sudo command burst')
    ]
    cursor.executemany('''
        INSERT OR IGNORE INTO dim_event_type (event_type_name, event_category, description)
        VALUES (?, ?, ?)
    ''', event_types)
    
    threat_categories = [
        ('Brute Force', 'T1110', 'Brute force authentication'),
        ('Credential Access', 'T1003', 'Accessing credential stores'),
        ('Persistence', 'T1053', 'Establishing persistence'),
        ('Download and Execute', 'T1059', 'Downloading payloads'),
        ('Privilege Escalation', 'T1548', 'Abusing elevation controls')
    ]
    cursor.executemany('''
        INSERT OR IGNORE INTO dim_threat_category (category_name, mitre_technique, description)
        VALUES (?, ?, ?)
    ''', threat_categories)
    
    # Insert fact records
    for event in events:
        cursor.execute('''
            INSERT INTO fact_security_events (
                timestamp, event_type, severity, source_ip, username,
                secondary_user, command, threat_category, event_count,
                window_start, window_end, country, city, latitude, longitude
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.event_type,
            event.severity,
            event.source_ip,
            event.username,
            event.secondary_user,
            event.command,
            event.threat_category,
            event.event_count,
            event.window_start.isoformat(),
            event.window_end.isoformat(),
            event.country,
            event.city,
            event.latitude,
            event.longitude
        ))
    
    conn.commit()
    conn.close()
    
    print(f"Exported {len(events)} events to {db_file}")

def create_powerbi_view(db_file: str = 'security_events.db'):
    # Create a Power BI view in SQLite database
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    cursor.execute('DROP VIEW IF EXISTS vw_security_dashboard')

    cursor.execute('''
        CREATE VIEW vw_security_dashboard AS
        SELECT
            f.event_id,
            f.timestamp,
            f.event_type,
            et.event_category,
            f.severity,
            s.severity_score,
            s.color_code,
            f.source_ip,
            f.username,
            f.secondary_user,
            f.command,
            f.threat_category,
            tc.mitre_technique,
            f.event_count,
            f.window_start,
            f.window_end,
            -- Geolocation
            f.country,
            f.city,
            f.latitude,
            f.longitude,
            -- Time dimensions for Power BI
            strftime('%Y-%m-%d', f.timestamp) as date,
            strftime('%H', f.timestamp) as hour,
            strftime('%w', f.timestamp) as day_of_week,
            CASE
                WHEN CAST(strftime('%w', f.timestamp) AS INTEGER) IN (0, 6)
                THEN 'Weekend'
                ELSE 'Weekday'
            END as day_type,
            CASE
                WHEN CAST(strftime('%H', f.timestamp) AS INTEGER) BETWEEN 9 AND 17
                THEN 'Business Hours'
                ELSE 'After Hours'
            END as time_period
        FROM fact_security_events f
        LEFT JOIN dim_severity s ON f.severity = s.severity_name
        LEFT JOIN dim_event_type et ON f.event_type = et.event_type_name
        LEFT JOIN dim_threat_category tc ON f.threat_category = tc.category_name
    ''')
    
    conn.commit()
    conn.close()



if __name__ == "__main__":
    # Main pipeline execution -- collect, normalize, and export security events
    # Import detection modules
    from detect_ssh import detect_failed_logins
    from detect_sudo import detect_sus_command, detect_sudo_burst, parse_sudo_event

    print("=== Security Event Export Pipeline ===\n")

    # Collect all events from different sources
    all_events = []

    # 1. SSH Brute Force Detection
    print("1. Analyzing SSH logs...")
    ssh_log_path = os.path.join(project_root, "data", "generated", "ssh_diverse_sample.log")
    ssh_alerts = detect_failed_logins(ssh_log_path, threshold=3, window_seconds=120)
    ssh_events = convert_ssh_alerts(ssh_alerts)
    all_events.extend(ssh_events)
    print(f"   Found {len(ssh_events)} SSH brute force events")
    
    # 2. Sudo Command Detection
    print("2. Analyzing sudo logs...")
    sudo_events_raw = []
    sudo_log_path = os.path.join(project_root, "data", "generated", "sudo_diverse_sample.log")
    with open(sudo_log_path) as f:
        for line in f:
            event = parse_sudo_event(line, 2026)
            if event:
                sudo_events_raw.append(event)

    # 2a. Suspicious commands
    sudo_cmd_alerts = detect_sus_command(sudo_events_raw)
    sudo_cmd_events = convert_sudo_command_alerts(sudo_cmd_alerts)
    all_events.extend(sudo_cmd_events)
    print(f"   Found {len(sudo_cmd_events)} suspicious sudo commands")

    # 2b. Sudo bursts
    sudo_burst_alerts = detect_sudo_burst(sudo_log_path, threshold=3, window_seconds=120)
    sudo_burst_events = convert_sudo_burst_alerts(sudo_burst_alerts)
    all_events.extend(sudo_burst_events)
    print(f"   Found {len(sudo_burst_events)} sudo burst events")

    # 3. Export to CSV
    print("\n3. Exporting data...")
    csv_output_path = os.path.join(project_root, "output", "security_events.csv")
    export_to_csv(all_events, csv_output_path)

    # 4. Export to SQLite
    db_output_path = os.path.join(project_root, "output", "security_events.db")
    export_to_sqlite(all_events, db_output_path)

    # 5. Create Power BI view
    create_powerbi_view(db_output_path)
    
    print(f"\nPipeline complete!")
    print(f"  Total SSH events: {len(ssh_events)}")
    print(f"  Total sudo command events: {len(sudo_cmd_events)}")
    print(f"  Total sudo burst events: {len(sudo_burst_events)}")
    print(f"  Total events: {len(all_events)}")
    print(f"\nReady for Power BI:")
    print(f"   - CSV: {csv_output_path}")
    print(f"   - SQLite: {db_output_path}")
