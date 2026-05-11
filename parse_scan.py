#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import subprocess
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def parse_nmap_xml(xml_file: str) -> List[Dict]:
    hosts = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        log.error(f"Failed to parse XML: {e}")
        return []

    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None or addr_elem.get("addrtype") != "ipv4":
            continue
        ip = addr_elem.get("addr")

        hostname = None
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                if hn.get("type") == "user":
                    hostname = hn.get("name")
                    break

        open_ports = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    portid = port.get("portid")
                    service_elem = port.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    version = service_elem.get("extrainfo", "") if service_elem is not None else ""
                    product = service_elem.get("product", "") if service_elem is not None else ""

                    open_ports.append({
                        "port": int(portid),
                        "service": service_name,
                        "version": version,
                        "product": product,
                    })

        if open_ports:
            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            })
            log.info(f"Parsed host {ip}: {len(open_ports)} open ports")

    return hosts


def get_ssh_key_type(ip: str, port: int = 22, timeout: int = 5) -> Optional[str]:
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-p", str(port), "-T", str(timeout), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 2
        )
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except subprocess.TimeoutExpired:
        log.warning(f"ssh-keyscan timed out for {ip}:{port}")
    except FileNotFoundError:
        log.warning("ssh-keyscan not found (openssh-clients not installed?)")
    except Exception as e:
        log.warning(f"Error running ssh-keyscan on {ip}:{port}: {e}")
    return None


def enrich_ssh_hosts(hosts: List[Dict]) -> List[Dict]:
    for host in hosts:
        has_ssh = any(p["port"] == 22 for p in host["open_ports"])
        if has_ssh:
            key_type = get_ssh_key_type(host["ip"], 22)
            if key_type:
                host["ssh_host_key_type"] = key_type
                log.info(f"{host['ip']}: SSH key type = {key_type}")
            else:
                host["ssh_host_key_type"] = None
    return hosts


def main():
    parser = argparse.ArgumentParser(description="Parse nmap XML and enrich with SSH keys")
    parser.add_argument("--input", "-i", required=True, help="nmap XML output file")
    parser.add_argument("--output", "-o", required=True, help="JSON output file")
    parser.add_argument("--no-ssh", action="store_true", help="Skip SSH key scanning")
    args = parser.parse_args()

    log.info(f"Parsing {args.input}")
    hosts = parse_nmap_xml(args.input)

    if not hosts:
        log.error("No hosts found in nmap output")
        return

    log.info(f"Found {len(hosts)} live hosts")

    if not args.no_ssh:
        log.info("Enriching with SSH host keys...")
        hosts = enrich_ssh_hosts(hosts)

    with open(args.output, 'w') as f:
        json.dump(hosts, f, indent=2)

    log.info(f"Wrote {len(hosts)} hosts to {args.output}")


if __name__ == "__main__":
    main()
