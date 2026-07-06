#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

whitelist.py

Whitelist support for DHCP assets.

Version : 2.0.0-RC2
License : MIT
"""

from __future__ import annotations

import csv
from pathlib import Path

from .utils import (
    load_config,
    normalize_hostname,
)

CFG = load_config()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WHITELIST = PROJECT_ROOT / CFG.get("whitelist", "etc/whitelist.csv")

SUPPORTED_TYPES = {
    "mac",
    "ip",
    "hostname",
    "host",
}


class Whitelist:

    def __init__(self, filename: Path = WHITELIST):

        self.filename = filename
        self.entries = []

        self.load()

    @staticmethod
    def normalize_type(value: str) -> str:

        return value.strip().lower()

    @staticmethod
    def normalize_value(entry_type: str, value: str) -> str:

        value = value.strip()

        if entry_type == "mac":
            return value.lower()

        if entry_type in ("hostname", "host"):
            return normalize_hostname(value)

        return value

    def load(self) -> None:

        self.entries = []

        if not self.filename.exists():
            return

        with self.filename.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as f:

            reader = csv.DictReader(f, delimiter=";")

            for row in reader:

                entry_type = self.normalize_type(
                    row.get("TYPE", "")
                )

                if entry_type not in SUPPORTED_TYPES:
                    continue

                value = self.normalize_value(
                    entry_type,
                    row.get("VALUE", ""),
                )

                if not value:
                    continue

                self.entries.append(
                    {
                        "TYPE": entry_type,
                        "VALUE": value,
                        "COMMENT": row.get("COMMENT", ""),
                    }
                )

    def match(self, record: dict) -> dict | None:

        mac = record["mac"].lower()
        ip = record["ip"]

        hostname = normalize_hostname(record["hostname"])
        short_hostname = hostname.split(".", 1)[0]

        for entry in self.entries:

            entry_type = entry["TYPE"]
            value = entry["VALUE"]

            if entry_type == "mac" and value == mac:
                return entry

            if entry_type == "ip" and value == ip:
                return entry

            if entry_type in ("hostname", "host"):

                if value == hostname or value == short_hostname:
                    return entry

        return None

    def count(self) -> int:

        return len(self.entries)


if __name__ == "__main__":

    whitelist = Whitelist()

    print("Whitelist entries:", whitelist.count())
    print()
    print("whitelist.py OK")
