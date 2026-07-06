# Wazuh DHCP Asset Discovery

DHCP Asset Discovery for Wazuh Manager.

Version: **2.0.0-RC3**

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
- Whitelist support
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
- WHITELISTED

---

## Whitelist

Whitelisted assets are stored in:

```text
etc/whitelist.csv
```

Supported fields:

- MAC
- IP
- HOSTNAME

Format:

```csv
TYPE;VALUE;COMMENT
MAC;aa:bb:cc:dd:ee:ff;Example MAC address
HOSTNAME;printer-office;Example hostname
IP;192.168.1.50;Example static DHCP lease
```

When an asset matches the whitelist, the inventory status is set to:

```text
WHITELISTED
```

No `DHCP_UNKNOWN` event is generated for whitelisted assets.

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
2.0.0-RC3
```

Status:

```
Release Candidate
```

---

## License

MIT

---

## Wazuh Alert Rule

To generate Wazuh dashboard alerts for unknown DHCP assets, install the custom decoder and rule:

```bash
sudo cp wazuh/dhcp_asset_decoder.xml /var/ossec/etc/decoders/
sudo cp wazuh/dhcp_asset_rules.xml /var/ossec/etc/rules/
```

Add the `localfile` block from:

```text
wazuh/ossec_localfile_snippet.xml
```

to:

```text
/var/ossec/etc/ossec.conf
```

Validate and restart Wazuh Manager:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

Unknown DHCP assets generate rule `100510` alerts at level `12`.
