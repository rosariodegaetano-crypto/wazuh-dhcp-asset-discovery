#!/usr/bin/env python3
"""
Wazuh DHCP Asset Discovery
utils.py

Common utility functions.

Version : 2.0.0-RC1
License : MIT
"""

from __future__ import annotations

import fcntl
import logging
import os
import re
from configparser import ConfigParser
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_FILE = PROJECT_ROOT / "etc" / "dhcp_asset.conf"

MAC_REGEX = re.compile(
    r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
)

# ---------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------


def utc_now() -> str:
    """
    Return current UTC timestamp.

    Format:
        YYYY-MM-DD HH:MM:SS
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------


def load_config(config_file: Path = CONFIG_FILE) -> dict:
    """
    Load configuration file.
    """

    if not config_file.exists():
        raise FileNotFoundError(config_file)

    parser = ConfigParser()

    parser.read(config_file)

    if "general" not in parser:
        raise RuntimeError("Missing [general] section")

    return dict(parser["general"])


# ---------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------


def setup_logger(name: str = "dhcp_asset") -> logging.Logger:
    """
    Configure project logger.
    """

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    cfg = load_config()

    level = getattr(
        logging,
        cfg.get("log_level", "INFO").upper(),
        logging.INFO,
    )

    logger.setLevel(level)

    handler = logging.StreamHandler()

    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"
        )
    )

    logger.addHandler(handler)

    return logger


# ---------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------


def ensure_directory(path: Path) -> None:
    """
    Create directory if needed.
    """

    path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------
# File Lock
# ---------------------------------------------------------------------


def file_lock(fd) -> None:
    """
    Exclusive lock.
    """

    fcntl.flock(fd, fcntl.LOCK_EX)


def file_unlock(fd) -> None:
    """
    Unlock file.
    """

    fcntl.flock(fd, fcntl.LOCK_UN)


# ---------------------------------------------------------------------
# Atomic Write
# ---------------------------------------------------------------------


def atomic_write(path: Path, data: str) -> None:
    """
    Atomic file write.

    Uses:

        file.tmp
            ↓
        os.replace()
    """

    tmp = path.with_suffix(path.suffix + ".tmp")

    with tmp.open("w", encoding="utf-8") as f:
        f.write(data)

    os.replace(tmp, path)


# ---------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------


def validate_mac(mac: str) -> bool:
    """
    Validate MAC address.
    """

    return bool(MAC_REGEX.fullmatch(mac.strip()))


def normalize_hostname(hostname: str) -> str:
    """
    Normalize hostname.
    """

    hostname = hostname.strip()

    if hostname.endswith("."):
        hostname = hostname[:-1]

    return hostname.lower()


# ---------------------------------------------------------------------
# Self Test
# ---------------------------------------------------------------------

if __name__ == "__main__":

    print("=== utils.py self-test ===")

    cfg = load_config()

    print("Configuration loaded")

    print(cfg)

    print()

    print("UTC :", utc_now())

    print()

    print(
        "MAC:",
        validate_mac("50:eb:f6:81:d3:af"),
    )

    print(
        "HOST:",
        normalize_hostname("Galaxy-S25."),
    )

    logger = setup_logger()

    logger.info("utils.py OK")
