#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery

event_writer.py

Writes DHCP events for Wazuh.

Version: 2.1.0-RC4
"""

from pathlib import Path

from .utils import load_config

CFG = load_config()

OUTPUT = Path(CFG["output"])


def write_unknown_event(asset: dict) -> None:
    """
    Write one DHCP_UNKNOWN event.
    """

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    line = (
        "DHCP_UNKNOWN|"
        f"{asset['IP']}|"
        f"{asset['MAC']}|"
        f"{asset['HOSTNAME']}|"
        f"{asset.get('VENDOR', '')}|"
        f"{asset['STATUS']}|"
        f"{asset['COUNT']}\n"
    )

    with OUTPUT.open("a", encoding="utf-8") as f:
        f.write(line)


if __name__ == "__main__":

    asset = {
        "IP": "172.16.5.126",
        "MAC": "8c:c5:d0:32:50:36",
        "HOSTNAME": "galaxy-s25",
        "VENDOR": "Samsung Electronics Co.,Ltd",
        "STATUS": "NEW",
        "COUNT": "1",
    }

    write_unknown_event(asset)

    print("event_writer.py OK")
