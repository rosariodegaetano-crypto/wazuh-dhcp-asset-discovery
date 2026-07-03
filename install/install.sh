#!/bin/bash
#
# Wazuh DHCP Asset Discovery
#
# install.sh
#
# Version: 2.0.0-RC1
#

set -e

PROJECT_NAME="dhcp_asset"

INSTALL_DIR="/opt/dhcp_asset"

SERVICE_FILE="/etc/systemd/system/dhcp_asset.service"

echo
echo "==========================================="
echo " Wazuh DHCP Asset Discovery Installer"
echo "==========================================="
echo

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run this installer as root."
    exit 1
fi

echo "[1/8] Creating installation directory..."

mkdir -p "${INSTALL_DIR}"

echo "[2/8] Copying project..."

cp -R bin "${INSTALL_DIR}/"
cp -R lib "${INSTALL_DIR}/"

if [ -d etc ]; then
    cp -R etc "${INSTALL_DIR}/"
fi

if [ -d resources ]; then
    cp -R resources "${INSTALL_DIR}/"
fi

mkdir -p "${INSTALL_DIR}/logs"
mkdir -p "${INSTALL_DIR}/tmp"

echo "[3/8] Installing systemd service..."

cp systemd/dhcp_asset.service "${SERVICE_FILE}"

echo "[4/8] Reloading systemd..."

systemctl daemon-reload

echo "[5/8] Enabling service..."

systemctl enable dhcp_asset

echo "[6/8] Restarting service..."

systemctl restart dhcp_asset

echo "[7/8] Waiting..."

sleep 2

echo "[8/8] Service status"

systemctl --no-pager --full status dhcp_asset || true

echo
echo "==========================================="
echo " Installation completed"
echo "==========================================="
echo
echo "Configuration : ${INSTALL_DIR}/etc"
echo "Logs          : /var/ossec/logs/dhcp_unknown.log"
echo "Inventory     : ${INSTALL_DIR}/logs/inventory.csv"
echo
