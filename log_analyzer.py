import re
import sys
from collections import defaultdict

SAMPLE_LOGS = """
Oct 06 12:01:05 server sshd[1024]: Failed password for root from 192.168.1.100 port 45210 ssh2
Oct 06 12:01:07 server sshd[1025]: Failed password for root from 192.168.1.100 port 45212 ssh2
Oct 06 12:01:09 server sshd[1026]: Failed password for root from 192.168.1.100 port 45214 ssh2
Oct 06 12:01:11 server sshd[1027]: Failed password for admin from 192.168.1.100 port 45216 ssh2
Oct 06 12:01:15 server sshd[1028]: Failed password for user from 10.0.0.55 port 33100 ssh2
Oct 06 12:02:00 server sshd[1030]: Accepted password for admin from 192.168.1.10 port 50122 ssh2
"""

def analyze_logs(log_text, threshold=3):
    failed_attempts = defaultdict(int)
    accepted_attempts = defaultdict(int)

    lines = log_text.strip().split('\n')
    for line in lines:
        if "Failed password" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
        elif "Accepted password" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                accepted_attempts[ip] += 1

    print("=" * 60)
    print("📊 SIEM Authentication Security Report")
    print("=" * 60)
    
    print("\n--- 🚨 Suspicious Brute-Force Alerts ---")
    flagged = False
    for ip, count in failed_attempts.items():
        if count >= threshold:
            flagged = True
            print(f"🚨 [ALERT] Potential Brute-Force Attack detected from IP: {ip:<15} ({count} failed login attempts)")
    if not flagged:
        print("✅ No IPs exceeded the failure threshold.")

    print("\n--- 📈 Authentication Overview ---")
    for ip, count in failed_attempts.items():
        print(f"• IP: {ip:<15} | Failed Logins: {count}")
    for ip, count in accepted_attempts.items():
        print(f"• IP: {ip:<15} | Successful Logins: {count}")
    print("=" * 60)

def main():
    analyze_logs(SAMPLE_LOGS)

if __name__ == "__main__":
    main()
