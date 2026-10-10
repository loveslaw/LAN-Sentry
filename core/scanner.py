"""
Subnet Scanner and Port Probe Engine
Asynchronously discovers live LAN hosts, resolves MAC addresses via ARP cache, and audits open ports.
"""

import concurrent.futures
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.vendor import lookup_vendor

COMMON_PORTS = [21, 22, 80, 443, 445, 3389, 8080]


@dataclass
class DiscoveredDevice:
    ip: str
    mac: str = "Unknown"
    vendor: str = "Unknown"
    hostname: str = "Unknown"
    open_ports: List[int] = field(default_factory=list)
    latency_ms: float = 0.0


def get_local_ip() -> str:
    """Finds the primary local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def parse_arp_table() -> Dict[str, str]:
    """Parses local OS ARP table into a mapping of IP -> MAC."""
    arp_map = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            # Matches IP and MAC patterns
            match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{17})", line)
            if match:
                ip, mac = match.groups()
                mac_formatted = mac.replace("-", ":").upper()
                arp_map[ip] = mac_formatted
    except Exception:
        pass
    return arp_map


def probe_port(ip: str, port: int, timeout: float = 0.2) -> bool:
    """Probes if a specific TCP port is open on the target host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def ping_host(ip: str, timeout: float = 0.3) -> Optional[float]:
    """Attempts to connect to a high-probability port or check echo response."""
    start = time.perf_counter()
    # Try quick connection on common ports to detect alive host
    for p in [80, 443, 445, 135, 22, 53]:
        if probe_port(ip, p, timeout=timeout):
            latency = (time.perf_counter() - start) * 1000
            return round(latency, 2)
    return None


def scan_subnet(subnet_base: str, start_host: int = 1, end_host: int = 254) -> List[DiscoveredDevice]:
    """
    Scans a /24 subnet (e.g. '192.168.1') across the specified range.
    Uses concurrent threads to complete scan in 1-2 seconds.
    """
    arp_map = parse_arp_table()
    devices = []

    def check_host(h):
        ip = f"{subnet_base}.{h}"
        latency = ping_host(ip)
        # Even if ping failed, check if ARP table already has it (some hosts drop TCP/ICMP but answer ARP)
        has_arp = ip in arp_map and not arp_map[ip].startswith("FF:FF:FF")
        if latency is not None or has_arp:
            mac = arp_map.get(ip, "Unknown")
            vendor = lookup_vendor(mac)

            # Resolve hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown"

            # Check open ports
            open_ports = []
            for port in COMMON_PORTS:
                if probe_port(ip, port, timeout=0.15):
                    open_ports.append(port)

            return DiscoveredDevice(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostname=hostname,
                open_ports=open_ports,
                latency_ms=latency if latency is not None else 1.0,
            )
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        futures = [executor.submit(check_host, h) for h in range(start_host, end_host + 1)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                devices.append(res)

    devices.sort(key=lambda d: [int(x) for x in d.ip.split(".")])
    return devices
