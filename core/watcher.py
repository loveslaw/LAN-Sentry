"""
Intruder Detection & Webhook Alert Engine
Compares discovered LAN devices against known authorized devices and fires Discord alerts.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional
import urllib.request
import urllib.parse

from core.scanner import DiscoveredDevice


class IntruderWatcher:
    def __init__(self, known_devices_file: str = "config/known_devices.json", webhook_url: Optional[str] = None):
        self.known_devices_file = known_devices_file
        self.webhook_url = webhook_url
        self.known_devices: Dict[str, str] = self.load_known_devices()

    def load_known_devices(self) -> Dict[str, str]:
        if not os.path.exists(self.known_devices_file):
            return {}
        try:
            with open(self.known_devices_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_known_devices(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.known_devices_file)), exist_ok=True)
        with open(self.known_devices_file, "w", encoding="utf-8") as f:
            json.dump(self.known_devices, f, indent=2)

    def authorize_device(self, mac_or_ip: str, label: str) -> None:
        key = mac_or_ip.strip().upper()
        self.known_devices[key] = label
        self.save_known_devices()

    def find_intruders(self, devices: List[DiscoveredDevice]) -> List[DiscoveredDevice]:
        intruders = []
        for dev in devices:
            mac_key = dev.mac.strip().upper()
            ip_key = dev.ip.strip()
            # If neither MAC nor IP is in known list, it's an intruder
            if mac_key not in self.known_devices and ip_key not in self.known_devices:
                intruders.append(dev)
        return intruders

    def send_discord_alert(self, intruder: DiscoveredDevice) -> bool:
        if not self.webhook_url or not self.webhook_url.startswith("https://"):
            return False

        payload = {
            "username": "LAN-Sentry Guard",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/2716/2716612.png",
            "embeds": [
                {
                    "title": "🚨 UNAUTHORIZED DEVICE CONNECTED TO LAN",
                    "description": "An unrecognized device was detected during real-time network scanning.",
                    "color": 15548997,  # Red
                    "fields": [
                        {"name": "IP Address", "value": f"`{intruder.ip}`", "inline": True},
                        {"name": "MAC Address", "value": f"`{intruder.mac}`", "inline": True},
                        {"name": "Manufacturer", "value": intruder.vendor, "inline": True},
                        {"name": "Hostname", "value": intruder.hostname, "inline": True},
                        {
                            "name": "Open Ports",
                            "value": ", ".join(map(str, intruder.open_ports)) if intruder.open_ports else "None Detected",
                            "inline": True,
                        },
                        {"name": "Latency", "value": f"{intruder.latency_ms} ms", "inline": True},
                    ],
                    "footer": {"text": "LAN-Sentry Intruder Detection System"},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ],
        }

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "LAN-Sentry/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status in (200, 204)
        except Exception:
            return False
