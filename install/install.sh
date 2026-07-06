#!/bin/bash
#
# Wazuh DHCP Asset Discovery
#
# install.sh
#
# Version: 2.1.0-RC2
#

set -e

PROJECT_NAME="dhcp_asset"

INSTALL_DIR="/opt/dhcp_asset"

SERVICE_FILE="/etc/systemd/system/dhcp_asset.service"
OUI_UPDATE_SERVICE_FILE="/etc/systemd/system/dhcp_asset_oui_update.service"
OUI_UPDATE_TIMER_FILE="/etc/systemd/system/dhcp_asset_oui_update.timer"

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
cp -R install "${INSTALL_DIR}/"

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

if [ -f systemd/dhcp_asset_oui_update.service ]; then
    cp systemd/dhcp_asset_oui_update.service "${OUI_UPDATE_SERVICE_FILE}"
fi

if [ -f systemd/dhcp_asset_oui_update.timer ]; then
    cp systemd/dhcp_asset_oui_update.timer "${OUI_UPDATE_TIMER_FILE}"
fi

echo "[4/8] Reloading systemd..."

systemctl daemon-reload

echo "[5/8] Enabling service..."

systemctl enable dhcp_asset

if [ -f "${OUI_UPDATE_TIMER_FILE}" ]; then
    systemctl enable dhcp_asset_oui_update.timer
fi

echo "[6/8] Restarting service..."

systemctl restart dhcp_asset

if [ -f "${OUI_UPDATE_TIMER_FILE}" ]; then
    systemctl restart dhcp_asset_oui_update.timer
fi

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
echo "OUI database  : ${INSTALL_DIR}/resources/oui.csv"
echo
