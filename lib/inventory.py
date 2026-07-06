#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

inventory.py

Inventory manager.

Version: 2.0.0-RC1
"""

from __future__ import annotations

import csv
from pathlib import Path

from .utils import (
    load_config,
    atomic_write,
    utc_now,
    normalize_hostname,
)

from .vendor import (
    VendorLookup,
)

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

CFG = load_config()

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INVENTORY = PROJECT_ROOT / CFG["inventory"]

VENDOR_LOOKUP = VendorLookup()

HEADER = [
    "MAC",
    "IP",
    "HOSTNAME",
    "FIRST_SEEN",
    "LAST_SEEN",
    "LAST_EVENT",
    "COUNT",
    "VENDOR",
    "STATUS",
    "LAST_ALERT",
]


# ---------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------

def ensure_inventory() -> None:
    """
    Create inventory.csv if it does not exist.
    """

    if INVENTORY.exists():
        return

    rows = ";".join(HEADER) + "\n"

    INVENTORY.parent.mkdir(parents=True, exist_ok=True)

    atomic_write(INVENTORY, rows)


def load_inventory() -> dict:
    """
    Load inventory into memory.

    Returns
    -------
    dict
        Dictionary indexed by MAC.
    """

    ensure_inventory()

    inventory = {}

    with INVENTORY.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f, delimiter=";")

        for row in reader:

            mac = row["MAC"].lower()

            inventory[mac] = row

    return inventory


def save_inventory(inventory: dict) -> None:
    """
    Save inventory atomically.
    """

    lines = []

    lines.append(";".join(HEADER))

    for mac in sorted(inventory):

        row = inventory[mac]

        values = [
            row.get(col, "")
            for col in HEADER
        ]

        lines.append(";".join(values))

    atomic_write(
        INVENTORY,
        "\n".join(lines) + "\n"
    )

# ---------------------------------------------------------------------
# Query API
# ---------------------------------------------------------------------

def asset_exists(inventory: dict, mac: str) -> bool:
    """
    Check if an asset exists.
    """
    return mac.lower() in inventory


def get_asset(inventory: dict, mac: str) -> dict | None:
    """
    Return asset by MAC.
    """
    return inventory.get(mac.lower())


def get_all_assets(inventory: dict) -> list[dict]:
    """
    Return all assets.
    """
    return list(inventory.values())


# ---------------------------------------------------------------------
# Update API
# ---------------------------------------------------------------------

def update_asset(
    inventory: dict,
    ip: str,
    mac: str,
    hostname: str,
) -> dict:
    """
    Create or update an asset.

    Returns
    -------
    dict
        {
            "changed": bool,
            "new_asset": bool,
            "event": str,
            "asset": dict
        }
    """

    now = utc_now()

    mac = mac.lower()

    hostname = normalize_hostname(hostname)

    if mac not in inventory:

        asset = {
            "MAC": mac,
            "IP": ip,
            "HOSTNAME": hostname,
            "FIRST_SEEN": now,
            "LAST_SEEN": now,
            "LAST_EVENT": "NEW",
            "COUNT": "1",
            "VENDOR": VENDOR_LOOKUP.lookup(mac),
            "STATUS": "NEW",
            "LAST_ALERT": "",
        }

        inventory[mac] = asset

        return {
            "changed": True,
            "new_asset": True,
            "event": "NEW",
            "asset": asset,
        }

    asset = inventory[mac]

    if not asset.get("VENDOR"):
        vendor = VENDOR_LOOKUP.lookup(mac)

        if vendor:
            asset["VENDOR"] = vendor

    changed = False

    event = "RENEW"

    if asset["IP"] != ip:

        asset["IP"] = ip

        changed = True

        event = "IP_CHANGE"

    if asset["HOSTNAME"] != hostname:

        asset["HOSTNAME"] = hostname

        changed = True

        event = "HOSTNAME_CHANGE"

    asset["LAST_SEEN"] = now

    asset["COUNT"] = str(
        int(asset["COUNT"]) + 1
    )

    asset["LAST_EVENT"] = event

    return {
        "changed": changed,
        "new_asset": False,
        "event": event,
        "asset": asset,
    }

# ---------------------------------------------------------------------
# Self Test
# ---------------------------------------------------------------------

if __name__ == "__main__":

    print("=== inventory.py self-test ===")

    ensure_inventory()

    inventory = load_inventory()

    print(f"Assets before: {len(inventory)}")

    result = update_asset(
        inventory=inventory,
        ip="192.168.1.100",
        mac="AA:BB:CC:DD:EE:FF",
        hostname="TEST-PC",
    )

    print("Event :", result["event"])
    print("New   :", result["new_asset"])

    save_inventory(inventory)

    inventory = load_inventory()

    print(f"Assets after : {len(inventory)}")

    asset = get_asset(
        inventory,
        "aa:bb:cc:dd:ee:ff"
    )

    print(asset)

    print()

    print("inventory.py OK")
