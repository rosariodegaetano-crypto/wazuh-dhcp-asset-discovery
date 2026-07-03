# Wazuh DHCP Asset Discovery

DHCP Asset Discovery for Wazuh Manager.

Version: **2.0.0-RC1**

Compatible with:

- Wazuh 4.14.5
- Python 3.10+

---

## Overview

Wazuh DHCP Asset Discovery automatically discovers devices obtaining DHCP leases from KEA/pfSense and maintains a persistent inventory.

The project identifies whether a device is already managed by a Wazuh agent.

If the device is not managed, a custom event is generated for Wazuh.

---

## Features

- DHCP lease parsing
- Continuous monitoring of archives.log
- Persistent inventory (CSV)
- Automatic managed agent detection
- Wazuh event generation
- Systemd service
- Automatic installer
- Modular architecture

---

## Project structure

```
bin/
lib/
etc/
install/
systemd/
resources/
logs/
tests/
docs/
```

---

## Inventory

The inventory stores:

- MAC
- IP
- Hostname
- First seen
- Last seen
- Event type
- Count
- Vendor
- Status
- Last alert

Status values:

- NEW
- DISCOVERED
- MANAGED

---

## Event flow

```
KEA / pfSense
        │
        ▼
archives.log
        │
        ▼
Parser
        │
        ▼
Inventory
        │
        ▼
Agent Checker
        │
   ┌────┴────┐
   │         │
MANAGED   DISCOVERED
             │
             ▼
DHCP_UNKNOWN
```

---

## Installation

```bash
sudo ./install/install.sh
```

---

## Service

```bash
sudo systemctl status dhcp_asset
```

Restart:

```bash
sudo systemctl restart dhcp_asset
```

Logs:

```bash
journalctl -u dhcp_asset -f
```

---

## Output

Generated events:

```
/var/ossec/logs/dhcp_unknown.log
```

Inventory:

```
logs/inventory.csv
```

---

## Current release

Version:

```
2.0.0-RC1
```

Status:

```
Release Candidate
```

---

## License

MIT
