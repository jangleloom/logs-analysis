import re 
from datetime import datetime
from collections import deque, defaultdict

# Sample: Jan 10 12:01:10 server sshd[1001]: Failed password for invalid user admin from 203.0.113.5 port 53421 ssh2
# Case 1: Failed password for invalid user admin from 203.0.113.5 -- User: admin
# Case 2: Failed password for user john from 203.0.113.5 -- User: john
# Detect failed SSH login attempts
# IOCs: date, time, username, IP address
FAILED_LOGIN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd(?:\[\d+\]): Failed password for (?:invalid user )?(?P<user>\S+).*from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)

MONTHS = { 
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, 
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# For each failed event, parse the log line and extract relevant information into a dictionary
# Format: datetime(year, month, day, hour, minute, second)
def parse_failed_event(line: str, year: int) -> dict | None:
    match = FAILED_LOGIN.match(line)
    if match:
        month_str = match.group('month')
        # datetime object needs months to be an int 
        month = MONTHS[month_str]
        day = int(match.group('day'))

        time_str = match.group('time')
        # Split time into hour, minute, second
        hour, minute, second = map(int, time_str.split(':'))
        time = datetime(year, month, day, hour, minute, second)

        user = match.group('user')
        ip = match.group('ip')

        return {"time": time, "user": user, "ip": ip}
    
    return None

# No. of logins and corrosponding severity levels 
def severity(count: int) -> str:
    if count >= 20:
        return "Critical"
    elif count >= 10:
        return "High"
    elif count >= 5:
        return "Medium"
    else:
        return "Low"

def detect_failed_logins(file_path: str, threshold: int = 3, window_seconds: int = 120, year: int = 2026):
    alerts = []
    ip_events = defaultdict(deque) # key: ip, value: deque of timestamps 

    with open(file_path, 'r') as f:
        for line in f: 
            event = parse_failed_event(line, year)
            if not event:
                continue
            
            ip = event['ip']
            current_time = event['time']

            # For each IP, maintain a deque of timestamps within the time window
            ip_events[ip].append(current_time)
            # ip_events is now a deque of datetime objects 

            # Slide the window: remove timestamps older than window_seconds from the current time
            # current_time - ip_events[ip][0] --> timedelta object, can use .total_seconds() to get seconds
            # datetime (specific time) subtraction results in a timedelta (duration) object
            while ip_events[ip] and (current_time - ip_events[ip][0]).total_seconds() > window_seconds:
                ip_events[ip].popleft() 
            
            # Check if the number of failed attempts exceeds the threshold (Only trigger ONCE per IP to avoid duplicates)
            if len(ip_events[ip]) == threshold:
                count = len(ip_events[ip])
                severity_level = severity(count)
                # Generate an alert
                alerts.append({
                    "ip": ip,
                    "count": count,
                    "severity": severity_level,
                    "first_attempt": ip_events[ip][0],
                    "last_attempt": ip_events[ip][-1]
                })
    return alerts
            
if __name__ == "__main__":
    alerts = detect_failed_logins("sample_auth.log", threshold=3, window_seconds=120)
    
    if alerts:
        print(f"Found {len(alerts)} brute force attempts:\n")
        for alert in alerts:
            print(f"IP: {alert['ip']}")
            print(f"  Failed attempts: {alert['count']}")
            print(f"  Severity: {alert['severity']}")
            print(f"  First attempt: {alert['first_attempt']}")
            print(f"  Last attempt: {alert['last_attempt']}")
            print()
    else:
        print("No brute force attempts detected.")


