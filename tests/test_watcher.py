"""
Unit tests for Intruder Watcher
"""

import json
import pytest
from core.scanner import DiscoveredDevice
from core.watcher import IntruderWatcher


def test_intruder_detection_filtering(tmp_path):
    known_file = tmp_path / "known.json"
    known_data = {
        "AA:BB:CC:DD:EE:01": "My Gaming PC",
        "192.168.1.50": "Home Gateway",
    }
    known_file.write_text(json.dumps(known_data))

    watcher = IntruderWatcher(known_devices_file=str(known_file))

    devices = [
        DiscoveredDevice(ip="192.168.1.20", mac="AA:BB:CC:DD:EE:01", vendor="ASUSTek"),  # Authorized by MAC
        DiscoveredDevice(ip="192.168.1.50", mac="Unknown", vendor="Cisco"),               # Authorized by IP
        DiscoveredDevice(ip="192.168.1.99", mac="11:22:33:44:55:66", vendor="Unknown"),  # Intruder!
    ]

    intruders = watcher.find_intruders(devices)
    assert len(intruders) == 1
    assert intruders[0].ip == "192.168.1.99"
    assert intruders[0].mac == "11:22:33:44:55:66"


def test_device_authorization_persistence(tmp_path):
    known_file = tmp_path / "known.json"
    watcher = IntruderWatcher(known_devices_file=str(known_file))

    assert len(watcher.known_devices) == 0
    watcher.authorize_device("DC:A6:32:00:11:22", "Living Room Pi")

    # Reload from disk
    watcher2 = IntruderWatcher(known_devices_file=str(known_file))
    assert "DC:A6:32:00:11:22" in watcher2.known_devices
    assert watcher2.known_devices["DC:A6:32:00:11:22"] == "Living Room Pi"
