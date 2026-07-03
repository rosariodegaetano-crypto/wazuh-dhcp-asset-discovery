#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

dhcp_asset.py

Main executable.

Version: 2.0.0-RC1
"""

from __future__ import annotations

import time
from pathlib import Path

from lib.utils import (
    load_config,
    setup_logger,
)
from lib.parser import parse_line

from lib.inventory import (
    load_inventory,
    save_inventory,
    update_asset,
)

def follow(filename: Path):
    """
    Generator similar to 'tail -f'.

    Yields each new line appended to the file.
    """

    with filename.open("r", encoding="utf-8") as f:

        f.seek(0, 2)

        while True:

            line = f.readline()

            if not line:
                time.sleep(0.2)
                continue

            yield line.rstrip()


def main():

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

        save_inventory(inventory)

        logger.info(
            "%s | %s | %s | %s",
            result["event"],
            record["ip"],
            record["mac"],
            record["hostname"],
        )

if __name__ == "__main__":

    try:
        main()
    except KeyboardInterrupt:
        print()
        print("DHCP Asset Discovery stopped")

