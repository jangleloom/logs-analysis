import re
from datetime import datetime
from collections import defaultdict, deque

# Sample: Aug  7 14:15:14 server sudo:   user3 : TTY=pts/34 ; PWD=/path ; USER=root ; COMMAND=/usr/bin/egrep ^[a-z]* /filename/toto1234 
# Detect sudo command usage attempts
# IOCs: date, time, invoking user (the one who ran server sudo), key-value blob -- details (parse by ";")
# [time] [hostname] sudo: invoking user : details (kv_blob)
# kv_blob sample: "TTY=pts/34 ; PWD=/path ; USER=root ; COMMAND=/usr/bin/egrep ^[a-z]* /filename/toto1234"

SUDO_USED = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+\S+\s+sudo:\s+(?P<invoking_user>[^:]+?)\s*:\s*(?P<kv_blob>.*)$'
)

MONTHS = { 
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, 
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_sudo_event(line: str, year: int) -> dict| None:
    match = SUDO_USED.match(line)
    if match: 
        month_str = match.group('month')
        # datetime object needs month to be an int 
        month = MONTHS[month_str]
        day = int(match.group('day'))

        time_str = match.group('time')
        # Split time into hour, min, sec
        hour, minute, second = map(int, time_str.split(':'))
        # Create datetime object 
        time = datetime(year, month, day, hour, minute, second)

        invoking_user = match.group('invoking_user').strip()

        kv_blob = match.group('kv_blob')
        # kv_blob parts are not fixed 
        kv_list = kv_blob.split(';') # LIST of key-value pairs 
        details = [p.strip() for p in kv_list] # for each key-value pair, remove whitespace 
        # details = ["TTY=pts/34","PWD=/path","USER=root","COMMAND=/usr/bin/egrep ^[a-z]* /filename/toto1234"] 
        
        # Convert list to dictionary ie. structured sudo data 
        # ie. turning ["USER=root", "COMMAND=..."] to { "USER": "root", "COMMAND": "..."}
        # Create empty dictionary 
        kv_dict = {} 
        for d in details: 
            # Split "=" ONLY ONCE since there may be more than one "="
            key, value = d.split('=', 1)
            # Account for malformed lines 
            if '=' not in d:
                continue
            
            # e.g. "USER=root" ==> [USER, root]
            # Build key-value pair into kv dictionary, remove whitespace 
            kv_dict[key.strip()] = value.strip()

        target_user = kv_dict.get("USER")
        command = kv_dict.get("COMMAND")

        return {
            "time": time, 
            "invoking_user": invoking_user, 
            "target_user": target_user, 
            "command": command}
    return None

# Severity level for sudo access depends on the type of commands and what it does, rather than count
# Check per event  
def severity_commands(command: str) -> str:
    cmd = command.lower()

    # List of dictionaries 
    RULES = [
        {
            "category": "Credential Access",
            "severity": "Critical",
            "patterns":  
            [
                "/etc/shadow",
                "/root/.ssh",
                ".ssh/id_rsa"
            ]
        },

        {
            "category": "Persistence",
            "severity": "High",
            "patterns": [
                "/etc/sudoers", 
                "crontab", 
                "useradd"
            ]
        },

        {
            "category": "Download and Execute",
            "severity": "Medium",
            "patterns": [
                "curl", "wget"
            ]
        }
    ]

    for rule in RULES: 
        for pattern in rule["patterns"]:
            if pattern in cmd:
                #return tuple 
                return rule["severity"], rule["category"]
    return None # Benign command

# When same invoking user performs many sudo actions in a set time window
def severity_burst(count: int) -> str:
    if count >= 20:
        return "Critical"
    elif count >= 10:
        return "High"
    elif count >= 5: 
        return "Medium"
    else:
        return "Low"
    
def detect_sudo_burst(file_path: str, threshold: int = 3, window_seconds: int = 120, year: int = 2026):
    alerts = []
    invoking_user_events = defaultdict(deque)

    with open(file_path, 'r') as f: 
        for line in f:
            # Extract components for each line
            event = parse_sudo_event(line, year)
            if not event:
                continue

            invoking_user = event['invoking_user']
            current_time = event['time']

            # For each invoking user, maintain a deque of timestamps within window
            invoking_user_events[invoking_user].append(current_time)

            # Sliding window 
            while invoking_user_events[invoking_user] and (current_time - invoking_user_events[invoking_user][0]).total_seconds() > window_seconds:
                invoking_user_events[invoking_user].popleft()

            if len(invoking_user_events[invoking_user]) == threshold:
                count = len(invoking_user_events[invoking_user])
                severity_level = severity_burst(count)
                alerts.append({
                    "invoking_user": invoking_user,
                    "count": count,
                    "severity": severity_level,
                    "first_attempt": invoking_user_events[invoking_user][0],
                    "last_attempt": invoking_user_events[invoking_user][-1],
                })
    return alerts 

def detect_sus_command(sudo_events: list[dict]):
    alerts = []

    for event in sudo_events:
        invoking_user = event['invoking_user']
        target_user = event['target_user']
        time_accessed = event['time']
        
        command = event['command']
        tuple_result = severity_commands(command)
        # Skip benign commands 
        if not tuple_result:
            continue
        severity_level, category = tuple_result

        alerts.append({
            "invoking_user": invoking_user,
            "target_user": target_user,
            "command": command,
            "category": category,
            "severity_level": severity_level,
            "time_accessed": time_accessed,
        })

    return alerts

def print_alert(alert):
    print("=" * 60)
    print(f"ALERT TYPE   : {alert.get('category', 'N/A')}")
    print(f"SEVERITY     : {alert.get('severity_level', alert.get('severity'))}")
    print(f"TIME         : {alert.get('time_accessed', alert.get('last_attempt'))}")
    print(f"USER         : {alert.get('invoking_user')}")
    
    if "target_user" in alert:
        print(f"TARGET USER  : {alert.get('target_user')}")
    if "command" in alert:
        print(f"COMMAND      : {alert.get('command')}")
    if "count" in alert:
        print(f"EVENT COUNT  : {alert.get('count')}")
        print(f"WINDOW       : {alert.get('first_attempt')} → {alert.get('last_attempt')}")

def main(): 
    sudo_events = []
    
    # Convert raw log 
    with open("sudo_sample.log") as f: 
        for line in f:
            event = parse_sudo_event(line, 2026)
            if event:
                sudo_events.append(event)
    
    # 1. Event-based/Command detection 
    sus_command_alerts = detect_sus_command(sudo_events)
    # 2. Frequency-based detection
    sudo_burst_alerts = detect_sudo_burst("sudo_sample.log", threshold=3, window_seconds=120)

    all_alerts = (sus_command_alerts + sudo_burst_alerts)

    for alert in all_alerts:
        print_alert(alert)

if __name__ == "__main__":
    main()
        
        


