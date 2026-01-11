import time
import re
from datetime import datetime
from collections import deque, defaultdict
from pathlib import Path

# Reuse the same regex and parsing from detect.py
FAILED_LOGIN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd(?:\[\d+\]): Failed password for (?:invalid user )?(?P<user>\S+).*from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)

MONTHS = { 
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, 
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_failed_event(line: str, year: int) -> dict | None:
    match = FAILED_LOGIN.match(line)
    if match:
        month_str = match.group('month')
        month = MONTHS[month_str]
        day = int(match.group('day'))

        time_str = match.group('time')
        hour, minute, second = map(int, time_str.split(':'))
        time = datetime(year, month, day, hour, minute, second)

        user = match.group('user')
        ip = match.group('ip')

        return {"time": time, "user": user, "ip": ip}
    
    return None

def severity(count: int) -> str:
    if count >= 20:
        return "Critical"
    elif count >= 10:
        return "High"
    elif count >= 5:
        return "Medium"
    else:
        return "Low"

def monitor_log_file(file_path: str, threshold: int = 3, window_seconds: int = 120, year: int = 2026):
    """
    Continuously monitor a log file for brute force attempts in real-time.
    """
    print(f"Starting real-time monitoring of {file_path}")
    print(f"Threshold: {threshold} attempts within {window_seconds} seconds\n")
    
    ip_events = defaultdict(deque)
    alerted_ips = set()  # Track IPs we've already alerted on
    
    # Open file and seek to end to only read new lines
    with open(file_path, 'r') as f:
        # Go to end of file
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            
            if not line:
                # No new line, wait a bit
                time.sleep(0.5)
                continue
            
            event = parse_failed_event(line.strip(), year)
            if not event:
                continue
            
            ip = event['ip']
            current_time = event['time']
            
            # Track events for this IP
            ip_events[ip].append(current_time)
            
            # Slide the window
            while ip_events[ip] and (current_time - ip_events[ip][0]).total_seconds() > window_seconds:
                ip_events[ip].popleft()
            
            # Check if threshold reached and we haven't alerted yet
            if len(ip_events[ip]) == threshold and ip not in alerted_ips:
                severity_level = severity(len(ip_events[ip]))
                
                print(f"\n🚨 ALERT: Brute force detected!")
                print(f"IP: {ip}")
                print(f"Failed attempts: {len(ip_events[ip])}")
                print(f"Severity: {severity_level}")
                print(f"First attempt: {ip_events[ip][0]}")
                print(f"Last attempt: {ip_events[ip][-1]}")
                print("-" * 50)
                
                alerted_ips.add(ip)
                
                # Optional: Reset alert after some time
                # You could implement a mechanism to remove from alerted_ips after a cooldown

if __name__ == "__main__":
    # Monitor the log file in real-time
    # On Linux: /var/log/auth.log
    # For testing: sample_auth.log
    
    LOG_FILE = "sample_auth.log"  # Change to your actual log file
    
    try:
        monitor_log_file(LOG_FILE, threshold=3, window_seconds=120)
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")
    except FileNotFoundError:
        print(f"Error: Log file '{LOG_FILE}' not found.")
