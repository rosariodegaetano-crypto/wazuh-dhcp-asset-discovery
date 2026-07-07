# Wazuh DHCP Asset Discovery

DHCP Asset Discovery for Wazuh Manager.

Version: **2.1.0-RC3**

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
2.1.0-RC3
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

---

## Vendor Lookup

The project supports local MAC vendor lookup using the IEEE OUI database.

Local database:

```text
resources/oui.csv
```

Installed database:

```text
/opt/dhcp_asset/resources/oui.csv
```

Format:

```csv
OUI;VENDOR
8C:C5:D0;Samsung Electronics Co.,Ltd
D0:F4:05;Dell Inc.
```

The inventory `VENDOR` field is populated automatically when a MAC address matches a known OUI.

Update the OUI database manually:

```bash
sudo /opt/dhcp_asset/install/update_oui.sh
```

A systemd timer can update the database weekly:

```bash
sudo systemctl enable --now dhcp_asset_oui_update.timer
sudo systemctl list-timers | grep dhcp_asset_oui_update
```

---

## Alert Frequency

Unknown DHCP assets generate at most one Wazuh alert per day.

The collector stores the last alert date in the inventory field:

```text
LAST_ALERT
```

Behavior:

- First detection of an unmanaged asset: alert generated
- Renew of the same asset on the same day: no new alert
- Detection of the same unmanaged asset on a later day: alert generated again
- Managed or whitelisted assets: no unknown-device alert

---

## Vendor In Alerts

Unknown DHCP asset events include vendor information when available.

Event format:

```text
DHCP_UNKNOWN|IP|MAC|HOSTNAME|VENDOR|STATUS|COUNT
```

Example:

```text
DHCP_UNKNOWN|172.16.5.183|8c:c5:d0:32:50:36|galaxy-s25|Samsung Electronics Co.,Ltd|DISCOVERED|1
```

This makes Wazuh alerts and dashboard searches easier to enrich by vendor.

