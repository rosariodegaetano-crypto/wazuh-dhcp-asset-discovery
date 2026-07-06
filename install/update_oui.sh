#!/bin/bash
#
# Wazuh DHCP Asset Discovery
#
# update_oui.sh
#
# Version: 2.1.0-RC1
#

set -euo pipefail

OUI_URL="https://standards-oui.ieee.org/oui/oui.csv"
INSTALL_DIR="/opt/dhcp_asset"
OUTPUT_DIR="${INSTALL_DIR}/resources"
OUTPUT_FILE="${OUTPUT_DIR}/oui.csv"
TMP_FILE="$(mktemp)"

echo "Updating OUI vendor database..."

mkdir -p "${OUTPUT_DIR}"

curl -fsSL "${OUI_URL}" | python3 -c '
import csv
import sys

reader = csv.DictReader(sys.stdin)
writer = csv.writer(sys.stdout, delimiter=";", lineterminator="\n")

writer.writerow(["OUI", "VENDOR"])

for row in reader:
    assignment = row.get("Assignment", "").strip().upper()
    organization = row.get("Organization Name", "").strip()

    if not assignment or not organization:
        continue

    assignment = assignment.replace("-", "").replace(":", "")

    if len(assignment) < 6:
        continue

    oui = ":".join([
        assignment[0:2],
        assignment[2:4],
        assignment[4:6],
    ])

    writer.writerow([oui, organization])
' > "${TMP_FILE}"

install -m 0644 "${TMP_FILE}" "${OUTPUT_FILE}"

rm -f "${TMP_FILE}"

echo "OUI database updated: ${OUTPUT_FILE}"
