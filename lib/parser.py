#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

parser.py

Parse DHCP lease lines coming from Wazuh archives.log.

Version: 2.0.0-RC1
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------
# DHCP Lease Regex
# ---------------------------------------------------------------------

LEASE_REGEX = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+),'
    r'(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}),'
    r'[^,]*,'
    r'[^,]*,'
    r'[^,]*,'
    r'[^,]*,'
    r'[^,]*,'
    r'[^,]*,'
    r'(?P<hostname>[^,]*)'
)


def parse_line(line: str) -> dict | None:
    """
    Parse a DHCP lease line.

    Returns:
        {
            "ip": "...",
            "mac": "...",
            "hostname": "..."
        }

    or None if the line is not a DHCP lease.
    """

    match = LEASE_REGEX.search(line)

    if not match:
        return None

    hostname = match.group("hostname").strip()

    if not hostname:
        hostname = "unknown"

    return {
        "ip": match.group("ip"),
        "mac": match.group("mac").lower(),
        "hostname": hostname.lower(),
    }


# ---------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------

if __name__ == "__main__":

    sample = (
        "2026 Jul 03 fw "
        "172.16.5.126,"
        "8c:c5:d0:32:50:36,"
        "01:8c:c5:d0:32:50:36,"
        "7200,"
        "1783074523,"
        "5,"
        "0,"
        "0,"
        "galaxy-s25,"
        "0"
    )

    result = parse_line(sample)

    print(result)

    print()

    print("parser.py OK")
