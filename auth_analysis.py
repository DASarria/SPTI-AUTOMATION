import re
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


AUTH_FAIL_PATTERN = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
AUTH_SUCCESS_PATTERN = re.compile(
    r"Accepted \S+ for \S+ from \d+\.\d+\.\d+\.\d+"
)


def analyze_auth_log(log_path: str, threshold: int = 10) -> Dict:
    failed_by_ip: Dict[str, int] = Counter()
    failed_by_user: Dict[str, int] = Counter()
    success_count = 0
    fail_count = 0

    log_file = Path(log_path)
    if not log_file.exists():
        print(f"Error: {log_path} not found")
        return {}

    for line in log_file.open():
        m = AUTH_FAIL_PATTERN.search(line)
        if m:
            ip = m.group("ip")
            user = m.group("user")
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1
            fail_count += 1
            continue

        m = AUTH_SUCCESS_PATTERN.search(line)
        if m:
            success_count += 1

    brute_force_ips = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in failed_by_ip.items()
        if count >= threshold
    ]
    brute_force_ips.sort(key=lambda x: x["failed_attempts"], reverse=True)

    targeted_users = [
        {"user": user, "attempts": count}
        for user, count in failed_by_user.most_common(10)
    ]

    ratio = fail_count / (fail_count + success_count) if (fail_count + success_count) > 0 else 0

    return {
        "summary": {
            "total_failed": fail_count,
            "total_successful": success_count,
            "fail_to_success_ratio": round(ratio, 3),
        },
        "brute_force_ips": brute_force_ips,
        "targeted_users": targeted_users,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze SSH authentication logs")
    parser.add_argument("--input", "-i", default="auth.log", help="Auth log file")
    parser.add_argument("--output", "-o", help="JSON output file (default: stdout)")
    parser.add_argument("--threshold", type=int, default=10, help="Failed attempts threshold (default: 10)")
    args = parser.parse_args()

    results = analyze_auth_log(args.input, args.threshold)

    if not results:
        return

    print("\n=== AUTH LOG ANALYSIS ===")
    print(f"Total failed logins: {results['summary']['total_failed']}")
    print(f"Total successful logins: {results['summary']['total_successful']}")
    print(f"Fail/success ratio: {results['summary']['fail_to_success_ratio']}")

    print(f"\nIPs with >{args.threshold} failed attempts:")
    for entry in results["brute_force_ips"]:
        print(f"  {entry['ip']}: {entry['failed_attempts']} attempts")

    print(f"\nMost targeted users:")
    for entry in results["targeted_users"]:
        print(f"  {entry['user']}: {entry['attempts']} attempts")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results written to {args.output}")


if __name__ == "__main__":
    main()
