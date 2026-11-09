#!/bin/bash
# Variables globales del instalador.
INSTALL_DIR="${INSTALL_DIR:-/opt/hostberry}"
SERVICE_NAME="hostberry"
USER_NAME="hostberry"
GROUP_NAME="hostberry"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
# Unit del wpa_supplicant dedicado para wlan0 durante el asistente (sin autoscan: el portal del AP
# no se cae en radio única). La app solo lo arranca/para; no puede crearlo (ProtectSystem=strict).
SETUP_SUPPLICANT_UNIT_FILE="/etc/systemd/system/hostberry-wifi-setup.service"
SETUP_SUPPLICANT_CONF_FILE="/etc/wpa_supplicant/hostberry-wlan0-setup.conf"
CONFIG_FILE="${INSTALL_DIR}/config.yaml"
LOG_DIR="/var/log/hostberry"
DATA_DIR="${INSTALL_DIR}/data"
GITHUB_REPO="https://github.com/ak4kuro/hostberry-project.git"
TEMP_CLONE_DIR="/tmp/hostberry-install"

# Secretos generados en instalación (JWT y password admin inicial)
GENERATED_JWT_SECRET=""
GENERATED_ADMIN_PASSWORD=""

# Reboot al final en install y --update (salvo HOSTBERRY_SKIP_REBOOT=1).
NEED_REBOOT_FOR_AP0=0

# No iniciar hostapd/ap0 en caliente durante install (SSH por WiFi).
HOSTBERRY_DEFER_AP_START=0
