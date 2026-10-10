"""
Unit tests for Subnet Scanner Utilities
"""

import pytest
from core.scanner import get_local_ip, probe_port, parse_arp_table


def test_get_local_ip_format():
    ip = get_local_ip()
    assert isinstance(ip, str)
    parts = ip.split(".")
    assert len(parts) == 4
    for p in parts:
        assert p.isdigit()


def test_probe_port_closed_port():
    # Loopback on an unlikely open high port should return False
    assert probe_port("127.0.0.1", 59999, timeout=0.1) is False


def test_parse_arp_table_returns_dict():
    arp_map = parse_arp_table()
    assert isinstance(arp_map, dict)
