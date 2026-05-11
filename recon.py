#!/usr/bin/env python3
import argparse
import subprocess
import json
import socket
import re
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any
import sys


DEFAULT_OUTPUT_DIR = Path("sample_output")


def load_existing_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


class ReconAuditor:

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.audit_file = self.output_dir / "audit.log"

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )
        self.logger = logging.getLogger(__name__)

        fh = logging.FileHandler(self.audit_file)
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(fh)

    def log(self, level: str, msg: str):
        getattr(self.logger, level.lower())(msg)

    def get_results_path(self, filename: str) -> Path:
        return self.output_dir / filename


def run_cmd(cmd: list, timeout: int = 30, description: str = "") -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)


def is_ip_address(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def recon_domain(target: str, auditor: ReconAuditor) -> Dict[str, Any]:
    results = {"target": target, "type": "domain", "timestamp": datetime.utcnow().isoformat() + "Z"}
    auditor.log("info", f"Running whois on domain {target}")
    code, out, err = run_cmd(["whois", target], timeout=30)
    if code == 0:
        whois_data = {"status": "success", "data": out}
        registrar = re.search(r"Registrar:\s*(.+)", out)
        registrant = re.search(r"Registrant Organization:\s*(.+)", out)
        whois_data["registrar"] = registrar.group(1).strip() if registrar else None
        whois_data["registrant"] = registrant.group(1).strip() if registrant else None
    else:
        whois_data = {"status": "error", "error": err or "Unknown error"}
        auditor.log("warning", f"whois failed: {err}")
    results["whois"] = whois_data
    for record_type in ["A", "MX", "NS", "TXT"]:
        auditor.log("info", f"Querying {record_type} records for {target}")
        code, out, err = run_cmd(["dig", target, record_type, "+short"], timeout=15)
        if code == 0:
            results[f"dns_{record_type}"] = {"status": "success", "records": out.strip().split('\n') if out.strip() else []}
        else:
            results[f"dns_{record_type}"] = {"status": "error", "error": err}
            auditor.log("warning", f"dig {record_type} failed: {err}")
    auditor.log("info", f"Fetching HTTP headers for {target}")
    for proto in ["http", "https"]:
        url = f"{proto}://{target}"
        code, out, err = run_cmd(["curl", "-I", "-L", url], timeout=15)
        if code == 0:
            headers = {}
            for line in out.split('\n'):
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            results[f"{proto}_headers"] = {"status": "success", "headers": headers}
        else:
            results[f"{proto}_headers"] = {"status": "error", "error": err}
            auditor.log("warning", f"curl {proto} failed: {err}")

    return results


def recon_ip(target: str, auditor: ReconAuditor) -> Dict[str, Any]:
    results = {"target": target, "type": "ip", "timestamp": datetime.utcnow().isoformat() + "Z"}

    auditor.log("info", f"Running nmap on {target}")
    nmap_file = auditor.get_results_path(f"nmap_{target.replace('.', '_')}.xml")
    code, out, err = run_cmd(
        ["nmap", "-sV", "--open", "--top-ports", "100", "-oX", str(nmap_file), target],
        timeout=120
    )

    open_ports = []
    nmap_data = {"status": "success" if code == 0 else "error"}
    if code == 0:
        try:
            tree = ET.parse(nmap_file)
            root = tree.getroot()
            for port in root.findall(".//port"):
                if port.find("state").get("state") == "open":
                    portid = port.get("portid")
                    service = port.find("service")
                    service_name = service.get("name", "unknown") if service is not None else "unknown"
                    open_ports.append({"port": int(portid), "service": service_name})
            nmap_data["open_ports"] = sorted(open_ports, key=lambda x: x["port"])
        except Exception as e:
            auditor.log("warning", f"Failed to parse nmap XML: {e}")
            nmap_data["parse_error"] = str(e)
    else:
        nmap_data["error"] = err
        auditor.log("warning", f"nmap failed: {err}")
    results["nmap"] = nmap_data

    auditor.log("info", f"Reverse DNS lookup for {target}")
    code, out, err = run_cmd(["dig", "-x", target, "+short"], timeout=15)
    if code == 0:
        results["reverse_dns"] = {"status": "success", "hostname": out.strip() if out else None}
    else:
        results["reverse_dns"] = {"status": "error", "error": err}
        auditor.log("warning", f"Reverse DNS failed: {err}")

    auditor.log("info", f"Running whois on IP {target}")
    code, out, err = run_cmd(["whois", target], timeout=30)
    if code == 0:
        whois_data = {"status": "success"}
        org = re.search(r"(Organization:|OrgName:)\s*(.+)", out)
        country = re.search(r"(Country:|Country Code:)\s*(.+)", out)
        whois_data["organization"] = org.group(2).strip() if org else None
        whois_data["country"] = country.group(2).strip() if country else None
    else:
        whois_data = {"status": "error", "error": err}
        auditor.log("warning", f"WHOIS on IP failed: {err}")
    results["whois"] = whois_data

    return results


def generate_markdown_report(results: Dict[str, Any], auditor: ReconAuditor):
    target = results["target"]
    recon_type = results["type"]

    report = f"# Reconnaissance Report: {target}\n\n"
    report += f"**Type:** {recon_type}\n"
    report += f"**Timestamp:** {results['timestamp']}\n\n"

    if recon_type == "domain":
        report += "## WHOIS Information\n"
        if results.get("whois", {}).get("status") == "success":
            whois = results["whois"]
            report += f"- Registrar: {whois.get('registrar', 'N/A')}\n"
            report += f"- Registrant: {whois.get('registrant', 'N/A')}\n"
        else:
            report += "Failed to retrieve WHOIS data\n"

        report += "\n## DNS Records\n"
        for record_type in ["A", "MX", "NS", "TXT"]:
            key = f"dns_{record_type}"
            if results.get(key, {}).get("status") == "success":
                records = results[key].get("records", [])
                report += f"\n### {record_type} Records\n"
                for rec in records:
                    if rec:
                        report += f"- {rec}\n"

        report += "\n## HTTP Headers\n"
        for proto in ["http", "https"]:
            key = f"{proto}_headers"
            if results.get(key, {}).get("status") == "success":
                headers = results[key].get("headers", {})
                report += f"\n### {proto.upper()}\n"
                report += f"**Notable Security Headers:**\n"
                security_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
                for h in security_headers:
                    if h in headers:
                        report += f"- {h}: {headers[h]}\n"
                    else:
                        report += f"- {h}: **MISSING**\n"

    else:
        report += "## nmap Scan Results\n"
        if results.get("nmap", {}).get("status") == "success":
            open_ports = results["nmap"].get("open_ports", [])
            if open_ports:
                report += "| Port | Service |\n|------|----------|\n"
                for p in open_ports:
                    report += f"| {p['port']} | {p['service']} |\n"
            else:
                report += "No open ports detected\n"
        else:
            report += f"nmap scan failed\n"

        report += "\n## Reverse DNS\n"
        if results.get("reverse_dns", {}).get("status") == "success":
            hostname = results["reverse_dns"].get("hostname")
            report += f"- Hostname: {hostname or 'None'}\n"

        report += "\n## WHOIS Information\n"
        if results.get("whois", {}).get("status") == "success":
            whois = results["whois"]
            report += f"- Organization: {whois.get('organization', 'N/A')}\n"
            report += f"- Country: {whois.get('country', 'N/A')}\n"

    report_file = auditor.get_results_path("report.md")
    existing_report = report_file.exists()
    with open(report_file, 'a', encoding='utf-8') as f:
        if existing_report:
            f.write("\n\n---\n\n")
        f.write(report)
    auditor.log("info", f"Markdown report appended to {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Integrated reconnaissance tool (domain and IP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py example.com
  python3 recon.py 192.168.1.1 --mode ip --output ./recon_out
  python3 recon.py 8.8.8.8 --verbose
        """
    )
    parser.add_argument("target", help="Domain name or IP address")
    parser.add_argument("--mode", choices=["domain", "ip", "auto"], default="auto",
                        help="Reconnaissance mode (default: auto-detect)")
    parser.add_argument("--output", "-o", help="Output directory (default: ./sample_output)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    mode = args.mode
    if mode == "auto":
        mode = "ip" if is_ip_address(args.target) else "domain"
    if not args.output:
        args.output = str(DEFAULT_OUTPUT_DIR)

    auditor = ReconAuditor(args.output)
    auditor.log("info", f"Starting {mode} reconnaissance on {args.target}")
    auditor.log("info", f"Output directory: {args.output}")
    if mode == "domain":
        results = recon_domain(args.target, auditor)
    else:
        results = recon_ip(args.target, auditor)
    results_file = auditor.get_results_path("results.json")
    existing_results = load_existing_json(results_file)
    if isinstance(existing_results, dict):
        existing_results.setdefault("part4_runs", [])
        existing_results["part4_runs"].append(results)
        merged_results = existing_results
    elif isinstance(existing_results, list):
        existing_results.append(results)
        merged_results = existing_results
    else:
        merged_results = results

    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(merged_results, f, indent=2)
    auditor.log("info", f"Results written to {results_file} (merged with existing content when present)")
    generate_markdown_report(results, auditor)

    auditor.log("info", "Reconnaissance complete")
    print(f"\n[+] Reconnaissance complete")
    print(f"[+] Output directory: {args.output}")
    print(f"[+] Results: {results_file}")
    print(f"[+] Report: {auditor.get_results_path('report.md')}")
    print(f"[+] Audit log: {auditor.audit_file}")
    print("[+] Existing files in sample_output were appended/merged in place; missing files were created.")


if __name__ == "__main__":
    main()
