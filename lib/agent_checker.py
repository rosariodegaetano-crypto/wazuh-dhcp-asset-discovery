#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

agent_checker.py

Checks whether a DHCP asset is already managed by Wazuh.

Version : 2.0.0-RC1
License : MIT
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

AGENT_CONTROL = "/var/ossec/bin/agent_control"
REFRESH_INTERVAL = 300


class AgentChecker:

    def __init__(self, refresh_interval: int = REFRESH_INTERVAL):

        self.refresh_interval = refresh_interval

        self._agents = set()

        self._last_refresh = 0

        self.refresh(force=True)

    # ---------------------------------------------------------

    @staticmethod
    def normalize(hostname: str) -> str:

        if hostname is None:
            return ""

        hostname = hostname.strip().lower()

        if "." in hostname:
            hostname = hostname.split(".", 1)[0]

        return hostname

    # ---------------------------------------------------------

    def refresh(self, force=False):

        now = time.time()

        if not force:

            if now - self._last_refresh < self.refresh_interval:
                return

        cmd = [
            AGENT_CONTROL,
            "-j",
            "-l",
        ]

        try:

            output = subprocess.check_output(
                cmd,
                text=True,
                stderr=subprocess.DEVNULL,
            )

            data = json.loads(output)

        except Exception:

            return

        agents = set()

        for item in data.get("data", []):

            name = self.normalize(item.get("name", ""))

            if name:

                agents.add(name)

        self._agents = agents

        self._last_refresh = now

    # ---------------------------------------------------------

    def is_managed(self, hostname: str) -> bool:

        self.refresh()

        hostname = self.normalize(hostname)

        return hostname in self._agents

    # ---------------------------------------------------------

    def count(self):

        self.refresh()

        return len(self._agents)

    # ---------------------------------------------------------

    def dump(self):

        self.refresh()

        return sorted(self._agents)


# ----------------------------------------------------------------------

if __name__ == "__main__":

    checker = AgentChecker(refresh_interval=0)

    print()

    print("Agents loaded:", checker.count())

    print()

    tests = [

        "PCSTARGATE76",

        "pcstargate76",

        "pcstargate76.poltelmi.lab",

        "galaxy-s25",

        "controllerstargate",

        "dc01",

        "dc02",

    ]

    for host in tests:

        print(
            f"{host:35} -> {checker.is_managed(host)}"
        )

    print()

    print("First 10 agents:")

    for item in checker.dump()[:10]:

        print(" ", item)

    print()

    print("agent_checker.py OK")
