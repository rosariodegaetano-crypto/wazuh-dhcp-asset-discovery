#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

collector.py

Main collection engine.

Version : 2.0.0-RC1
License : MIT
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
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

from .agent_checker import (
    AgentChecker,
)

from .whitelist import (
    Whitelist,
)


def today_utc() -> str:
    """
    Return current UTC date.
    """

    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def should_alert(asset: dict) -> bool:
    """
    Return True if a discovered asset must generate an alert today.
    """

    if asset["STATUS"] != "DISCOVERED":
        return False

    return asset.get("LAST_ALERT", "") != today_utc()


def follow(filename: Path):
    """
    Tail a file and reopen it when it is rotated or truncated.
    """

    logfile = None
    current_inode = None
    current_device = None
    current_size = 0

    while True:

        try:

            stat = filename.stat()

        except FileNotFoundError:

            if logfile is not None:
                logfile.close()
                logfile = None

            time.sleep(0.5)
            continue

        if (
            logfile is None
            or stat.st_ino != current_inode
            or stat.st_dev != current_device
            or stat.st_size < current_size
        ):

            if logfile is not None:
                logfile.close()

            logfile = filename.open(
                "r",
                encoding="utf-8",
                errors="replace",
            )

            logfile.seek(0, 2)

            current_inode = stat.st_ino
            current_device = stat.st_dev
            current_size = stat.st_size

        if logfile.tell() > stat.st_size:

            logfile.close()

            logfile = filename.open(
                "r",
                encoding="utf-8",
                errors="replace",
            )

            current_inode = stat.st_ino
            current_device = stat.st_dev
            current_size = stat.st_size

        line = logfile.readline()

        if line:
            current_size = max(current_size, logfile.tell())
            yield line.rstrip()
        else:
            current_size = stat.st_size
            time.sleep(0.2)


class Collector:

    def __init__(self):

        self.cfg = load_config()

        self.logger = setup_logger()

        self.archive = Path(self.cfg["archive"])

        self.inventory = load_inventory()

        self.checker = AgentChecker()

        self.whitelist = Whitelist()

        #
        # Duplicate protection
        #
        self._last_key = None
        self._last_time = 0

    # ---------------------------------------------------------

    def duplicate(self, record):

        key = (
            record["mac"].lower(),
            record["ip"],
            record["hostname"].lower(),
        )

        now = time.time()

        if key == self._last_key and (now - self._last_time) < 2:

            return True

        self._last_key = key
        self._last_time = now

        return False

    # ---------------------------------------------------------

    def process_record(self, record):

        if self.duplicate(record):
            return

        result = update_asset(

            inventory=self.inventory,

            ip=record["ip"],

            mac=record["mac"],

            hostname=record["hostname"],

        )

        asset = result["asset"]

        whitelist_entry = self.whitelist.match(record)

        #
        # Always recalculate status
        #
        old_status = asset["STATUS"]

        if whitelist_entry is not None:

            asset["STATUS"] = "WHITELISTED"

        elif self.checker.is_managed(asset["HOSTNAME"]):

            asset["STATUS"] = "MANAGED"

        else:

            asset["STATUS"] = "DISCOVERED"

        #
        # Status transition
        #
        if old_status != asset["STATUS"]:

            self.logger.info(

                "STATUS %s -> %s (%s)",

                old_status,

                asset["STATUS"],

                asset["HOSTNAME"],

            )

        #
        # Generate one event per day for unmanaged assets
        #
        if should_alert(asset):

            write_unknown_event(asset)

            asset["LAST_ALERT"] = today_utc()

        save_inventory(self.inventory)

        self.logger.info(

            "%-8s %-11s %-15s %-17s %s",

            result["event"],

            asset["STATUS"],

            asset["IP"],

            asset["MAC"],

            asset["HOSTNAME"],

        )

    # ---------------------------------------------------------

    def run(self):

        self.logger.info("DHCP Asset Discovery started")

        self.logger.info("Watching %s", self.archive)

        self.logger.info(

            "Loaded %d managed agents",

            self.checker.count(),

        )

        self.logger.info(

            "Loaded %d whitelist entries",

            self.whitelist.count(),

        )

        for line in follow(self.archive):

            record = parse_line(line)

            if record is None:
                continue

            self.process_record(record)


def run():

    Collector().run()
