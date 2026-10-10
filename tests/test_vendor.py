"""
Unit tests for MAC Vendor Lookup
"""

import pytest
from core.vendor import lookup_vendor


def test_known_oui_vendors():
    assert lookup_vendor("DC:A6:32:11:22:33") == "Raspberry Pi Trading"
    assert lookup_vendor("30-AE-A4-AA-BB-CC") == "Espressif Inc (ESP32/ESP8266)"
    assert lookup_vendor("001CB3AABBCC") == "Apple, Inc."
    assert lookup_vendor("70:89:CC:01:02:03") == "Sony Interactive Entertainment"


def test_unknown_oui_fallback():
    assert lookup_vendor("00:00:00:11:22:33") == "Generic / Unregistered Vendor"
    assert lookup_vendor("") == "Unknown"
    assert lookup_vendor("invalid") == "Unknown"
