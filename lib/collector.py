#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

collector.py

Main collection engine.

Version: 2.0.0-RC1
"""

from __future__ import annotations

import time
from pathlib import Path

from .utils import (
    load_config,
    setup_logger,
)

from .parser import parse_line

from .inventory import (
    load_inventory,
    save_inventory,
    update_asset,
)

from .event_writer import (
    write_unknown_event,
)


def follow(filename: Path):
    """
    Simple tail -f generator.
    """

    with filename.open("r", encoding="utf-8") as f:

        f.seek(0, 2)

        while True:

            line = f.readline()

            if not line:
                time.sleep(0.2)
                continue

            yield line.rstrip()


def run():

    cfg = load_config()

    logger = setup_logger()

    archive = Path(cfg["archive"])

    logger.info("DHCP Asset Discovery started")
    logger.info("Watching %s", archive)

    inventory = load_inventory()

    for line in follow(archive):

        record = parse_line(line)

        if record is None:
            continue

        result = update_asset(
            inventory=inventory,
            ip=record["ip"],
            mac=record["mac"],
            hostname=record["hostname"],
        )

        asset = result["asset"]

        #
        # Notify only once
        #
        if asset["STATUS"] == "NEW":

            write_unknown_event(asset)

            asset["STATUS"] = "DISCOVERED"

        save_inventory(inventory)

        logger.info(
            "%-12s %-12s %-15s %-17s %s",
            result["event"],
            asset["STATUS"],
            asset["IP"],
            asset["MAC"],
            asset["HOSTNAME"],
        )

