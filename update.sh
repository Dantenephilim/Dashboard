#!/usr/bin/env bash
# ==============================================================================
# Script de Actualización Rápida para Ubuntu Server & Docker
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}==============================================================${NC}"
echo -e "${CYAN}   🔄 ACTUALIZADOR DEL DASHBOARD (UBUNTU SERVER & DOCKER)     ${NC}"
echo -e "${CYAN}==============================================================${NC}"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Evitar errores de 'dubious ownership' de git si se ejecuta con sudo
git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true

echo -e "${BLUE}[1/4] Descargando última versión de GitHub...${NC}"
git fetch origin main
git reset --hard origin/main

echo -e "${BLUE}[2/4] Reconstruyendo imagen optimizada y levantando contenedor...${NC}"
docker compose up -d --build

echo -e "${BLUE}[3/4] Limpiando capas intermedias...${NC}"
docker image prune -f 2>/dev/null || true

# Obtener IP
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
if [ -z "$SERVER_IP" ]; then
  SERVER_IP="<IP-DE-TU-SERVIDOR>"
fi

PORT_CONFIG=$(grep -E '^PORT=' .env 2>/dev/null | cut -d '=' -f 2 | tr -d '\r' | tr -d ' ' || echo "8090")
PORT_CONFIG=${PORT_CONFIG:-8090}

echo ""
echo -e "${GREEN}==============================================================${NC}"
echo -e "${GREEN}    ✅ ¡ACTUALIZACIÓN COMPLETADA CON ÉXITO!                   ${NC}"
echo -e "${GREEN}==============================================================${NC}"
echo -e " Versión: $(git log -1 --format='%h - %s (%cr)' 2>/dev/null || echo 'v1.1.0')"
echo -e " Acceso web: ${YELLOW}👉 http://${SERVER_IP}:${PORT_CONFIG}${NC}"
echo -e "${GREEN}==============================================================${NC}"
