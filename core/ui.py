"""
Rich Terminal UI for LAN-Sentry
Author: loveslaw
"""

from typing import List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.scanner import DiscoveredDevice

console = Console()

BANNER = """[bold red]
  ██╗      █████╗ ███╗   ██╗     ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
  ██║     ██╔══██╗████╗  ██║     ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ██║     ███████║██╔██╗ ██║     ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
  ██║     ██╔══██║██║╚██╗██║     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
  ███████╗██║  ██║██║ ╚████║     ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
[/bold red]
[dim cyan]  High-Speed LAN Sniffer · Port Auditor · Intruder Detection Webhooks[/dim cyan]
[dim white]  Author: loveslaw | Version: 1.0.0[/dim white]
"""


def show_banner():
    console.print(BANNER)


def print_device_table(devices: List[DiscoveredDevice], title: str = "Discovered LAN Devices"):
    table = Table(title=title, border_style="dim white", show_header=True)
    table.add_column("IP Address", style="bold cyan")
    table.add_column("MAC Address", style="white")
    table.add_column("Manufacturer / Vendor", style="green")
    table.add_column("Hostname", style="dim white")
    table.add_column("Open Ports", style="yellow")
    table.add_column("Latency", style="dim magenta")

    for d in devices:
        ports_str = ", ".join(map(str, d.open_ports)) if d.open_ports else "-"
        table.add_row(
            d.ip,
            d.mac,
            d.vendor,
            d.hostname,
            ports_str,
            f"{d.latency_ms} ms",
        )

    console.print(table)
