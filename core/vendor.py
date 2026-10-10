"""
MAC Address OUI Vendor Lookup Database
Provides instant offline manufacturer identification for detected LAN network devices.
"""

import re
from typing import Optional

OUI_DATABASE = {
    "00:1A:2B": "Ayecom Technology",
    "00:1C:B3": "Apple, Inc.",
    "00:25:00": "Apple, Inc.",
    "00:26:BB": "Apple, Inc.",
    "3C:D9:2B": "Hewlett Packard",
    "DC:A6:32": "Raspberry Pi Trading",
    "B8:27:EB": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",
    "30:AE:A4": "Espressif Inc (ESP32/ESP8266)",
    "24:0A:C4": "Espressif Inc (ESP32)",
    "D8:3A:DD": "Espressif Inc (IoT Device)",
    "A4:CF:12": "Espressif Inc (IoT Device)",
    "00:50:56": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "00:15:5D": "Microsoft Corporation (Hyper-V)",
    "F0:18:98": "Apple, Inc.",
    "F4:34:F0": "Apple, Inc.",
    "AC:BC:32": "Apple, Inc.",
    "40:4E:36": "Samsung Electronics",
    "88:32:9B": "Samsung Electronics",
    "50:01:D9": "Samsung Electronics",
    "60:A4:4C": "Google, Inc.",
    "D8:6C:63": "Google Nest",
    "FC:65:DE": "Amazon Technologies",
    "68:54:5A": "Amazon Technologies",
    "00:FC:8B": "Amazon Technologies",
    "00:11:32": "Synology Incorporated",
    "00:1A:79": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "00:1D:AA": "TP-Link Corporation",
    "50:C7:BF": "TP-Link Corporation",
    "E8:48:B8": "TP-Link Corporation",
    "00:04:4B": "NVIDIA Corporation",
    "48:B0:2D": "NVIDIA Corporation",
    "00:E0:4C": "Realtek Semiconductor",
    "70:85:C2": "ASUSTek Computer",
    "04:D4:C4": "ASUSTek Computer",
    "00:1F:D0": "Giga-Byte Technology",
    "70:89:CC": "Sony Interactive Entertainment",
    "98:B6:E9": "Nintendo Co., Ltd.",
    "F8:4D:FC": "Cisco Systems",
}


def lookup_vendor(mac_address: str) -> str:
    """Returns the hardware vendor for a given MAC address or 'Unknown / Generic'."""
    if not mac_address:
        return "Unknown"

    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac_address).upper()
    if len(cleaned) < 6:
        return "Unknown"

    oui_key = f"{cleaned[0:2]}:{cleaned[2:4]}:{cleaned[4:6]}"
    return OUI_DATABASE.get(oui_key, "Generic / Unregistered Vendor")
