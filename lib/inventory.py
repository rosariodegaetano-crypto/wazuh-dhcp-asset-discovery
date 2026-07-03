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

from utils import (
    load_config,
    atomic_write,
)

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

CFG = load_config()

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INVENTORY = PROJECT_ROOT / CFG["inventory"]

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
# Self Test
# ---------------------------------------------------------------------

if __name__ == "__main__":

    print("=== inventory.py self-test ===")

    ensure_inventory()

    inv = load_inventory()

    print("Inventory loaded")

    print("Assets:", len(inv))

    print()

    print(INVENTORY)

    print()

    print("inventory.py OK")
