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


def follow(filename: Path):
    """
    Simple tail -f generator.
    """

    with filename.open("r", encoding="utf-8") as logfile:

        logfile.seek(0, 2)

        while True:

            line = logfile.readline()

            if line:
                yield line.rstrip()
            else:
                time.sleep(0.2)


class Collector:

    def __init__(self):

        self.cfg = load_config()

        self.logger = setup_logger()

        self.archive = Path(self.cfg["archive"])

        self.inventory = load_inventory()

        self.checker = AgentChecker()

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

        #
        # Always recalculate status
        #
        old_status = asset["STATUS"]

        if self.checker.is_managed(asset["HOSTNAME"]):

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
        # Generate event ONLY for NEW unmanaged assets
        #
        if (
            result["event"] == "NEW"
            and asset["STATUS"] == "DISCOVERED"
        ):

            write_unknown_event(asset)

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

        for line in follow(self.archive):

            record = parse_line(line)

            if record is None:
                continue

            self.process_record(record)


def run():

    Collector().run()
