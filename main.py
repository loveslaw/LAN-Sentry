"""
LAN-Sentry CLI Entrypoint
Author: loveslaw
"""

import argparse
import json
import os
import sys
import time

from core.ui import console, show_banner, print_device_table
from core.scanner import get_local_ip, scan_subnet, DiscoveredDevice
from core.watcher import IntruderWatcher


def load_config(config_file: str = "config/config.json") -> dict:
    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def cmd_scan(args, cfg: dict):
    subnet = args.subnet
    if not subnet or subnet == "auto":
        local_ip = get_local_ip()
        parts = local_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"

    start_h = args.start or cfg.get("start_host", 1)
    end_h = args.end or cfg.get("end_host", 254)

    with console.status(f"[bold cyan]Scanning subnet {subnet}.{start_h}-{end_h}..."):
        devices = scan_subnet(subnet, start_host=start_h, end_host=end_h)

    print_device_table(devices, title=f"Scan Results for {subnet}.0/24 ({len(devices)} active devices)")


def cmd_watch(args, cfg: dict):
    webhook_url = args.webhook or cfg.get("discord_webhook_url") or os.getenv("DISCORD_WEBHOOK_URL")
    interval = args.interval or cfg.get("scan_interval_seconds", 30)
    subnet = args.subnet or cfg.get("subnet_base", "auto")

    if not subnet or subnet == "auto":
        local_ip = get_local_ip()
        parts = local_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"

    watcher = IntruderWatcher(webhook_url=webhook_url)

    console.print(f"[bold green]✔ LAN-Sentry Guard Active on {subnet}.0/24[/bold green]")
    console.print(f"[dim]Scan Interval: {interval}s | Webhook Alerts: {'Enabled' if webhook_url else 'Disabled (Local only)'}[/dim]\n")

    try:
        while True:
            with console.status(f"[dim cyan]Scanning network...[/dim cyan]"):
                devices = scan_subnet(subnet, start_host=1, end_host=254)
                intruders = watcher.find_intruders(devices)

            if intruders:
                console.print(f"\n[bold red]🚨 DETECTED {len(intruders)} UNRECOGNIZED DEVICE(S)![/bold red]")
                print_device_table(intruders, title="🚨 Intruder Alert")
                for intr in intruders:
                    if watcher.send_discord_alert(intr):
                        console.print(f"[dim green]✔ Discord alert sent for {intr.ip} ({intr.mac})[/dim green]")
            else:
                console.print(f"[dim green][{time.strftime('%H:%M:%S')}] Network secure. {len(devices)} active devices verified.[/dim green]")

            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]LAN-Sentry watcher stopped by user.[/yellow]")


def cmd_authorize(args):
    watcher = IntruderWatcher()
    watcher.authorize_device(args.target, args.label)
    console.print(f"[bold green]✔ Authorized device registered:[/bold green] [cyan]{args.target}[/cyan] -> [yellow]{args.label}[/yellow]")


def cmd_list(args):
    watcher = IntruderWatcher()
    known = watcher.known_devices
    if not known:
        console.print("[dim]No authorized devices registered yet.[/dim]")
        return

    from rich.table import Table
    table = Table(title="Authorized LAN Devices", border_style="dim green")
    table.add_column("MAC / Identifier", style="bold cyan")
    table.add_column("Label / Device Name", style="yellow")
    for k, v in known.items():
        table.add_row(k, v)
    console.print(table)


def main():
    show_banner()
    cfg = load_config()

    parser = argparse.ArgumentParser(description="LAN-Sentry - Local Subnet Sniffer & Intruder Alert")
    subparsers = parser.add_subparsers(dest="command")

    # Scan
    scan_p = subparsers.add_parser("scan", help="Perform a quick scan of the local subnet")
    scan_p.add_argument("--subnet", help="Subnet base (e.g. 192.168.1, or 'auto')")
    scan_p.add_argument("--start", type=int, default=1, help="Start host index (default: 1)")
    scan_p.add_argument("--end", type=int, default=254, help="End host index (default: 254)")

    # Watch
    watch_p = subparsers.add_parser("watch", help="Continuous monitoring and intruder alert daemon")
    watch_p.add_argument("--subnet", help="Subnet base (default: auto)")
    watch_p.add_argument("--interval", type=int, help="Scan interval in seconds (default: 30)")
    watch_p.add_argument("--webhook", help="Discord Webhook URL for intruder alerts")

    # Authorize
    auth_p = subparsers.add_parser("authorize", help="Add a device MAC/IP to the trusted list")
    auth_p.add_argument("target", help="MAC address or IP to authorize")
    auth_p.add_argument("--label", required=True, help="Friendly label (e.g. 'My MacBook Pro')")

    # List
    subparsers.add_parser("list-authorized", help="List all authorized devices")

    if len(sys.argv) == 1:
        # Default action: run scan
        cmd_scan(argparse.Namespace(subnet="auto", start=1, end=254), cfg)
    else:
        args = parser.parse_args()
        if args.command == "scan":
            cmd_scan(args, cfg)
        elif args.command == "watch":
            cmd_watch(args, cfg)
        elif args.command == "authorize":
            cmd_authorize(args)
        elif args.command == "list-authorized":
            cmd_list(args)
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
