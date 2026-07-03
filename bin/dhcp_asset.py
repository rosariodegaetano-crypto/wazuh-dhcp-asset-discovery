#!/usr/bin/env python3
"""
DHCP Asset Discovery

Program entry point.
"""

from lib.collector import run


if __name__ == "__main__":

    try:

        run()

    except KeyboardInterrupt:

        print()

        print("DHCP Asset Discovery stopped")

