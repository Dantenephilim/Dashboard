#!/usr/bin/env bash
# ==============================================================================
# Script de Instalación Automatizada para Ubuntu Server / Ubuntu Server Pro
# Dashboard de Monitoreo en Tiempo Real y Auto-Escáner de Servicios Docker & Host
# ==============================================================================

set -e

# Colores para la terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}==============================================================${NC}"
echo -e "${CYAN}   🚀 INSTALADOR AUTOMÁTICO: MONITOR UBUNTU SERVER & DOCKER   ${NC}"
echo -e "${CYAN}==============================================================${NC}"
echo ""

# 1. Comprobar permisos de superusuario
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Por favor ejecuta este script con privilegios de superusuario:${NC}"
  echo -e "    sudo bash install.sh"
  exit 1
fi

TARGET_USER=${SUDO_USER:-$USER}

# 2. Detección de Ubuntu
if [ -f /etc/os-release ]; then
  . /etc/os-release
  echo -e "${BLUE}[*] Sistema detectado:${NC} $PRETTY_NAME"
else
  echo -e "${YELLOW}[!] Advertencia: No se pudo verificar /etc/os-release. Continuando...${NC}"
fi

# 3. Comprobar e instalar Docker y Docker Compose si no están instalados
echo -e "${BLUE}[*] Verificando Docker Engine y Docker Compose...${NC}"
if ! command -v docker &> /dev/null; then
  echo -e "${YELLOW}[+] Docker no está instalado. Instalando Docker oficialmente vía get.docker.com...${NC}"
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
  echo -e "${GREEN}[✓] Docker instalado correctamente.${NC}"
else
  echo -e "${GREEN}[✓] Docker ya está instalado ($(docker --version)).${NC}"
fi

# Verificar plugin compose
if ! docker compose version &> /dev/null; then
  echo -e "${YELLOW}[+] Instalando plugin de Docker Compose...${NC}"
  apt-get update -qq
  apt-get install -y -qq docker-compose-plugin
  echo -e "${GREEN}[✓] Docker Compose plugin instalado.${NC}"
else
  echo -e "${GREEN}[✓] Docker Compose disponible ($(docker compose version)).${NC}"
fi

# 4. Asegurar servicio Docker activo
systemctl enable --now docker.service

# 5. Agregar usuario al grupo docker
if [ "$TARGET_USER" != "root" ]; then
  echo -e "${BLUE}[*] Agregando al usuario ${TARGET_USER} al grupo docker...${NC}"
  usermod -aG docker "$TARGET_USER" || true
fi

# 6. Desplegar el contenedor con docker compose
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${BLUE}[*] Construyendo y levantando el contenedor en segundo plano...${NC}"
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d --build

# 7. Obtener la IP principal del servidor
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(hostname -I | awk '{print $1}')
fi
if [ -z "$SERVER_IP" ]; then
  SERVER_IP="<IP-DE-TU-SERVIDOR>"
fi

# 8. Leer puerto configurado
PORT_CONFIG=$(grep -E '^PORT=' .env 2>/dev/null | cut -d '=' -f 2 | tr -d '\r' | tr -d ' ' || echo "8090")
PORT_CONFIG=${PORT_CONFIG:-8090}

echo ""
echo -e "${GREEN}==============================================================${NC}"
echo -e "${GREEN}    ✅ ¡INSTALACIÓN COMPLETADA Y EN EJECUCIÓN EXITOSA!        ${NC}"
echo -e "${GREEN}==============================================================${NC}"
echo ""
echo -e " El dashboard está activo y escaneando tu servidor automáticamente."
echo -e " ${CYAN}No necesitas hacer nada más:${NC} cada contenedor o servicio que"
echo -e " inicies en Ubuntu se detectará en vivo en la pantalla."
echo ""
echo -e " 🌐 Accede ahora desde cualquier navegador a:"
echo -e "    ${YELLOW}👉 http://${SERVER_IP}:${PORT_CONFIG}${NC}"
echo ""
echo -e " ⚙️ Comandos útiles de gestión:"
echo -e "    - Ver logs:     ${CYAN}docker compose logs -f${NC}"
echo -e "    - Detener:      ${CYAN}docker compose down${NC}"
echo -e "    - Reiniciar:    ${CYAN}docker compose restart${NC}"
echo ""
echo -e "${GREEN}==============================================================${NC}"
