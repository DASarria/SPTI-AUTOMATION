import re
import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[.+?\] "(?P<method>\w+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+)'
)

ATTACK_PATTERNS = re.compile(
    r"(union.*select|insert.*into|delete.*from|drop\s+table"  
    r"|\.\./|\.\.\\\\|\.\.%2f"                                 
    r"|<script|javascript:|onerror|onload"                     
    r"|cmd=|exec=|shell=|system\()"                            
    r"|/admin|/wp-admin|/phpmyadmin",                          
    re.IGNORECASE,
)


def parse_access_log(log_path: str) -> Tuple[List[Dict], Dict]:

    log_file = Path(log_path)
    if not log_file.exists():
        print(f"Error: {log_path} not found")
        return [], {}

    requests = []
    hourly_counts = Counter()

    for line in log_file.open():
        m = LOG_PATTERN.match(line)
        if not m:
            continue

        ip = m.group("ip")
        status = int(m.group("status"))
        path = m.group("path")
        method = m.group("method")

        requests.append({
            "ip": ip,
            "method": method,
            "path": path,
            "status": status,
        })

        hour_match = re.search(r'\[(\d{2}/\w+/\d{4}):(\d{2}):', line)
        if hour_match:
            date_str = hour_match.group(1)
            hour = hour_match.group(2)
            hourly_counts[f"{date_str}-{hour}"] += 1

    return requests, dict(hourly_counts)


def find_attack_requests(requests: List[Dict]) -> List[Dict]:
    suspicious = []
    for req in requests:
        if ATTACK_PATTERNS.search(req["path"]):
            suspicious.append(req)
    return suspicious


def top_ips_by_volume(requests: List[Dict], top_n: int = 5) -> List[Tuple[str, int]]:
    ip_counts = Counter(r["ip"] for r in requests)
    return ip_counts.most_common(top_n)


def status_distribution(requests: List[Dict]) -> Dict[str, int]:
    return dict(Counter(r["status"] for r in requests))


def detect_anomalies(hourly_counts: Dict[str, int], threshold_sigma: float = 3.0) -> List[Dict]:
    if len(hourly_counts) < 2:
        return []

    counts = list(hourly_counts.values())
    mean = statistics.mean(counts)
    stdev = statistics.stdev(counts)

    if stdev == 0:
        return []

    anomalies = []
    for hour, count in hourly_counts.items():
        z_score = (count - mean) / stdev
        if abs(z_score) > threshold_sigma:
            anomalies.append({
                "hour": hour,
                "request_count": count,
                "z_score": round(z_score, 2),
                "mean": round(mean, 1),
                "stdev": round(stdev, 1),
            })

    return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)


def main():
    parser = argparse.ArgumentParser(description="Analyze web access logs")
    parser.add_argument("--input", "-i", default="access.log", help="Access log file")
    parser.add_argument("--output", "-o", help="JSON output file (default: stdout)")
    parser.add_argument("--sigma", type=float, default=3.0, help="Sigma threshold for anomalies (default: 3.0)")
    args = parser.parse_args()

    requests, hourly = parse_access_log(args.input)
    if not requests:
        return

    print(f"[*] Parsed {len(requests)} requests")

    attacks = find_attack_requests(requests)
    top_ips = top_ips_by_volume(requests)
    status_dist = status_distribution(requests)
    anomalies = detect_anomalies(hourly, args.sigma)

    results = {
        "summary": {
            "total_requests": len(requests),
            "attack_requests_detected": len(attacks),
        },
        "attack_requests": attacks[:50],  
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "status_distribution": status_dist,
        "anomalous_hours": anomalies,
    }

    print("\n=== WEB LOG ANALYSIS ===")
    print(f"Total requests: {len(requests)}")
    print(f"Attack patterns detected: {len(attacks)}")
    print(f"\nTop 5 IPs:")
    for ip, count in top_ips:
        print(f"  {ip}: {count} requests")

    print(f"\nStatus distribution:")
    for status in sorted(status_dist.keys()):
        print(f"  {status}: {status_dist[status]}")

    if anomalies:
        print(f"\nAnomalous hours (>{args.sigma}σ):")
        for anom in anomalies[:5]:
            print(f"  {anom['hour']}: {anom['request_count']} requests (z={anom['z_score']}σ)")
    else:
        print(f"\nNo anomalies detected (threshold: >{args.sigma}σ)")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results written to {args.output}")


if __name__ == "__main__":
    main()
