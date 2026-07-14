#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

vendor.py

Local OUI vendor lookup.

Version : 2.1.0-RC4
License : MIT
"""

from __future__ import annotations

import csv
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUI_FILE = PROJECT_ROOT / "resources" / "oui.csv"


def normalize_oui(value: str) -> str:
    """
    Normalize a MAC or OUI value to XX:XX:XX.
    """

    value = value.strip().upper().replace("-", ":").replace(".", "")

    if ":" in value:
        parts = value.split(":")
    else:
        parts = [
            value[0:2],
            value[2:4],
            value[4:6],
        ]

    if len(parts) < 3:
        return ""

    parts = parts[:3]

    if any(len(part) != 2 for part in parts):
        return ""

    return ":".join(parts)


class VendorLookup:

    def __init__(self, filename: Path = OUI_FILE):

        self.filename = filename
        self.vendors = {}

        self.load()

    def load(self) -> None:

        self.vendors = {}

        if not self.filename.exists():
            return

        with self.filename.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as f:

            reader = csv.DictReader(f, delimiter=";")

            for row in reader:

                oui = normalize_oui(row.get("OUI", ""))

                vendor = row.get("VENDOR", "").strip()

                if not oui or not vendor:
                    continue

                self.vendors[oui] = vendor

    def lookup(self, mac: str) -> str:

        oui = normalize_oui(mac)

        if not oui:
            return ""

        return self.vendors.get(oui, "")

    def count(self) -> int:

        return len(self.vendors)


if __name__ == "__main__":

    lookup = VendorLookup()

    print("OUI entries:", lookup.count())
    print("Vendor:", lookup.lookup("8c:c5:d0:32:50:36"))
    print()
    print("vendor.py OK")
