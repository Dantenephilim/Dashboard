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

echo -e "${BLUE}[1/4] Comprobando cambios en GitHub...${NC}"
git fetch origin main 2>/dev/null || true
LOCAL_HASH=$(git rev-parse HEAD 2>/dev/null || echo "local")
REMOTE_HASH=$(git rev-parse origin/main 2>/dev/null || echo "remote")

if [ "$LOCAL_HASH" = "$REMOTE_HASH" ] && [ "$LOCAL_HASH" != "local" ]; then
  echo -e "${GREEN}[✓] Tu código ya se encuentra en la versión más reciente.${NC}"
else
  echo -e "${YELLOW}[+] Nuevos cambios detectados. Descargando con git pull...${NC}"
  git pull origin main
fi

echo -e "${BLUE}[2/4] Reconstruyendo imagen optimizada...${NC}"
docker compose build

echo -e "${BLUE}[3/4] Reiniciando el contenedor en el puerto 8090...${NC}"
docker compose up -d

echo -e "${BLUE}[4/4] Limpiando capas intermedias huérfanas...${NC}"
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
