"""
Generate synthetic SSH auth logs with diverse IPs for testing.
Creates realistic brute force attack patterns from multiple sources.
"""

import random
from datetime import datetime, timedelta

# Common usernames tried in brute force attacks
USERNAMES = [
    'admin', 'root', 'test', 'user', 'oracle', 'postgres', 'mysql',
    'ubuntu', 'pi', 'guest', 'administrator', 'backup', 'webadmin',
    'tomcat', 'jenkins', 'git', 'deploy', 'ansible', 'nagios'
]

def generate_random_ip():
    """Generate a random IP address."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_attack_ips(num_attackers=50):
    """Generate list of attacker IPs with attack characteristics."""
    attackers = []

    for _ in range(num_attackers):
        ip = generate_random_ip()
        # Vary the number of attempts per IP (3-20 attempts)
        num_attempts = random.randint(3, 20)
        attackers.append({
            'ip': ip,
            'attempts': num_attempts
        })

    return attackers

def generate_ssh_log_entry(timestamp, ip, username, port):
    """Generate a single SSH log line in syslog format."""
    # Randomly decide if it's an invalid user or valid user attempt
    if random.random() < 0.7:  # 70% invalid users
        return f"{timestamp.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: Failed password for invalid user {username} from {ip} port {port} ssh2"
    else:
        return f"{timestamp.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: Failed password for user {username} from {ip} port {port} ssh2"

def generate_ssh_logs(output_file='ssh_diverse_sample.log', num_attackers=50, start_date=None):
    """
    Generate SSH auth logs with diverse attacker IPs.

    Args:
        output_file: Output filename
        num_attackers: Number of different attacking IPs
        start_date: Starting datetime (defaults to Jan 10, 2026)
    """

    if start_date is None:
        start_date = datetime(2026, 1, 10, 12, 0, 0)

    attackers = generate_attack_ips(num_attackers)

    print(f"Generating SSH logs for {num_attackers} attackers...")

    lines = []
    current_time = start_date

    for attacker in attackers:
        ip = attacker['ip']
        num_attempts = attacker['attempts']

        # Space out attempts over 1-5 minutes
        time_between_attempts = random.randint(5, 30)  # seconds

        for attempt in range(num_attempts):
            username = random.choice(USERNAMES)
            port = random.randint(50000, 60000)

            lines.append(generate_ssh_log_entry(current_time, ip, username, port))

            # Move time forward
            current_time += timedelta(seconds=time_between_attempts)

        # Add some time gap between different attackers
        current_time += timedelta(seconds=random.randint(30, 120))

    # Shuffle to make it more realistic (attacks happen concurrently)
    random.shuffle(lines)

    # Sort by timestamp to maintain log order
    # Parse and sort
    def parse_time(line):
        parts = line.split()
        month = parts[0]
        day = int(parts[1])
        time_str = parts[2]
        # Create sortable string
        months = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                  'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
        return (months.get(month, 1), day, time_str)

    lines.sort(key=parse_time)

    # Write to file
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))
        f.write('\n')

    print(f"\nGenerated {len(lines)} log entries")
    print(f"Output: {output_file}")
    print(f"\nStats:")
    print(f"  - Unique IPs: {num_attackers}")
    print(f"  - Total attempts: {len(lines)}")
    print(f"  - Avg attempts per IP: {len(lines) / num_attackers:.1f}")

    # Show sample of IPs
    print(f"\nSample attacker IPs:")
    for i, attacker in enumerate(attackers[:5]):
        print(f"  {attacker['ip']}: {attacker['attempts']} attempts")

if __name__ == "__main__":
    # Generate realistic daily volumes for internet-facing host
    # Target: 200-5000 failed SSH attempts per day
    # Strategy: ~100-150 attackers, averaging 20-40 attempts each = ~2000-6000 total
    generate_ssh_logs(
        output_file='ssh_diverse_sample.log',
        num_attackers=120,  # Realistic number of distinct attackers per day
        start_date=datetime(2026, 1, 10, 0, 0, 0)  # Start at midnight for full day
    )

    print("\nYou can now use this file in extract.py:")
    print('  ssh_alerts = detect_failed_logins("ssh_diverse_sample.log", threshold=3, window_seconds=120)')
    print("\nRealistic volumes: ~2000-3000 failed SSH attempts/day (internet-facing host)")
