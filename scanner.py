import socket
import time
import json
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Tuple


def parse_ports(port_spec: str) -> List[int]:
    ports = []
    for part in port_spec.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))



def scan_port_sequential(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def scan_sequential(host: str, ports: List[int], timeout: float = 1.0) -> Tuple[List[int], float]:
    start = time.perf_counter()
    open_ports = [p for p in ports if scan_port_sequential(host, p, timeout)]
    elapsed = time.perf_counter() - start
    return open_ports, elapsed



def scan_port_for_threading(args: Tuple[str, int, float]) -> int | None:
    host, port, timeout = args
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None


def scan_threaded(host: str, ports: List[int], max_workers: int = 200, timeout: float = 0.5) -> Tuple[List[int], float]:
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(scan_port_for_threading, [(host, p, timeout) for p in ports])
    open_ports = sorted([p for p in results if p is not None])
    elapsed = time.perf_counter() - start
    return open_ports, elapsed



async def scan_port_async(host: str, port: int, timeout: float = 0.5) -> int | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_host_limited(host: str, ports: List[int], max_concurrent: int = 200, timeout: float = 0.5) -> List[int]:
    semaphore = asyncio.Semaphore(max_concurrent)

    async def limited_scan(port: int) -> int | None:
        async with semaphore:
            await asyncio.sleep(0)
            return await scan_port_async(host, port, timeout)

    results = await asyncio.gather(*[limited_scan(p) for p in ports])
    return sorted([p for p in results if p is not None])


def scan_asyncio(host: str, ports: List[int], max_concurrent: int = 200, timeout: float = 0.5) -> Tuple[List[int], float]:
    start = time.perf_counter()
    open_ports = asyncio.run(scan_host_limited(host, ports, max_concurrent, timeout))
    elapsed = time.perf_counter() - start
    return open_ports, elapsed


def main():
    parser = argparse.ArgumentParser(
        description="Concurrent port scanner: sequential vs threading vs asyncio",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py 127.0.0.1 --ports 1-1024 --rate 200
  python3 scanner.py 192.168.1.1 --ports 22,80,443,8080 --timeout 1.0 --output scan.json
        """
    )
    parser.add_argument("target", help="IP address to scan")
    parser.add_argument("--ports", default="1-1024", help="Port range or comma-separated list (default: 1-1024)")
    parser.add_argument("--rate", type=int, default=200, help="Max concurrent connections (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout in seconds (default: 0.5)")
    parser.add_argument("--output", help="JSON output file (default: stdout)")
    parser.add_argument("--mode", choices=["seq", "thread", "async"], default="async",
                        help="Scanning mode (default: async)")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.target} ports {min(ports)}-{max(ports)} ({len(ports)} total) with {args.mode} mode")
    print(f"[*] Rate limit: {args.rate}, Timeout: {args.timeout}s")

    if args.mode == "seq":
        open_ports, elapsed = scan_sequential(args.target, ports, args.timeout)
    elif args.mode == "thread":
        open_ports, elapsed = scan_threaded(args.target, ports, args.rate, args.timeout)
    else:  
        open_ports, elapsed = scan_asyncio(args.target, ports, args.rate, args.timeout)

    result = {
        "target": args.target,
        "scan_time_seconds": round(elapsed, 3),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "open_ports": open_ports,
        "scan_mode": args.mode,
        "rate_limit": args.rate,
    }

    output = json.dumps(result, indent=2)
    print(f"[+] Scan complete in {elapsed:.2f}s")
    print(f"[+] Open ports: {open_ports}")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[+] Results written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
