# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by Keep a Changelog and follows Semantic Versioning.

---

# [2.0.0-RC2] - 2026-07-06

## Added

- Added whitelist support.
- Added `lib/whitelist.py`.
- Added `etc/whitelist.csv` example file.
- Added support for whitelist matching by:
  - MAC
  - IP
  - HOSTNAME

## Changed

- Collector now evaluates whitelist before managed-agent detection.
- Whitelisted assets are stored in inventory with status `WHITELISTED`.

## Fixed

- Prevented `DHCP_UNKNOWN` event generation for whitelisted assets.

---

# [2.0.0-RC1] - 2026-07-03

## Added

### Core

- Initial project architecture
- Modular Python implementation
- Git repository initialization
- Version management

### DHCP Collector

- Continuous monitoring of `archives.log`
- Automatic lease processing
- Real-time event pipeline
- Tail-follow implementation

### Parser

- KEA / pfSense DHCP lease parser
- Automatic extraction of:
  - IP address
  - MAC address
  - Hostname

### Inventory

Persistent inventory stored in CSV.

Fields:

- MAC
- IP
- HOSTNAME
- FIRST_SEEN
- LAST_SEEN
- LAST_EVENT
- COUNT
- VENDOR
- STATUS
- LAST_ALERT

Implemented asset update logic.

### Agent Checker

Implemented managed asset detection using:

```
agent_control -j -l
```

Features:

- JSON parsing
- Hostname normalization
- In-memory cache
- Automatic refresh
- O(1) lookup

### Event Writer

Implemented custom Wazuh event generation.

Output:

```
/var/ossec/logs/dhcp_unknown.log
```

### Collector

Integrated:

- Parser
- Inventory
- Agent Checker
- Event Writer
- Logging

### Configuration

Added:

```
etc/dhcp_asset.conf
```

### Logging

Added configurable logging.

### Service

Added native systemd service.

```
systemd/dhcp_asset.service
```

### Installer

Added automatic installer.

```
install/install.sh
```

Features:

- project deployment
- service installation
- daemon-reload
- enable service
- restart service

### Documentation

Added:

- README
- VERSION
- CHANGELOG

---

## Changed

Improved project architecture.

Moved business logic from:

```
bin/dhcp_asset.py
```

to

```
lib/collector.py
```

Introduced modular design.

Improved inventory update flow.

Improved event generation.

Improved managed asset detection.

---

## Fixed

Fixed module imports.

Fixed package initialization.

Fixed inventory persistence.

Fixed collector execution.

Fixed hostname normalization.

Fixed managed agent lookup.

Fixed permission issues by executing the collector as a privileged service.

---

## Known limitations

Current release requires the collector to run with privileges capable of executing:

```
/var/ossec/bin/agent_control
```

Vendor lookup is not yet implemented.

Whitelist management is not yet implemented.

Inventory cleanup is not yet implemented.

---

## Next Release (2.1)

Planned features:

- Vendor lookup (OUI)
- Whitelist management
- Inventory cleanup
- Automatic purge
- Statistics
- Dashboard
- Debian package
- GitHub Actions
- Unit tests
- Integration tests

---

# End of file
