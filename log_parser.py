"""
log_parser.py
Parses SSH/auth-style log files and flags suspicious activity, such as
repeated failed logins from the same IP (a common brute-force signature).

Usage:
    python log_parser.py <logfile_path> [--threshold 5]

Expects log lines in a format similar to Linux /var/log/auth.log, e.g.:
    Sep 27 10:15:02 server sshd[1234]: Failed password for root from 203.0.113.5 port 51514 ssh2
    Sep 27 10:15:05 server sshd[1234]: Accepted password for denys from 192.168.1.10 port 51600 ssh2
"""

import argparse
import re
from collections import defaultdict

FAILED_PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
ACCEPTED_PATTERN = re.compile(r"Accepted password for (\S+) from (\S+)")


def parse_log(path: str):
    failed_attempts = defaultdict(list)  # ip -> list of usernames tried
    accepted_logins = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            failed_match = FAILED_PATTERN.search(line)
            if failed_match:
                user, ip = failed_match.groups()
                failed_attempts[ip].append(user)
                continue

            accepted_match = ACCEPTED_PATTERN.search(line)
            if accepted_match:
                user, ip = accepted_match.groups()
                accepted_logins.append((user, ip))

    return failed_attempts, accepted_logins


def report(failed_attempts, accepted_logins, threshold: int):
    print("=== Suspicious IPs (failed login attempts) ===")
    flagged = {ip: users for ip, users in failed_attempts.items() if len(users) >= threshold}

    if not flagged:
        print(f"No IPs exceeded the threshold of {threshold} failed attempts.")
    else:
        for ip, users in sorted(flagged.items(), key=lambda x: -len(x[1])):
            unique_users = set(users)
            print(f"[!] {ip}: {len(users)} failed attempts "
                  f"(usernames tried: {', '.join(sorted(unique_users))})")

    print("\n=== Successful Logins ===")
    if not accepted_logins:
        print("None found.")
    else:
        for user, ip in accepted_logins:
            flag = " <-- from a flagged IP!" if ip in flagged else ""
            print(f"[+] {user} logged in from {ip}{flag}")


def main():
    parser = argparse.ArgumentParser(description="Parse auth logs for suspicious activity")
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument("--threshold", type=int, default=5,
                         help="Failed attempts from one IP to flag as suspicious (default: 5)")
    args = parser.parse_args()

    try:
        failed, accepted = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"[!] Log file not found: {args.logfile}")
        return

    report(failed, accepted, args.threshold)


if __name__ == "__main__":
    main()
