# 🚀 Server & Docker Live Monitor Dashboard (Ubuntu Server Pro)

Un dashboard web moderno, reactivo y de ultra bajo consumo diseñado para **Ubuntu Server y Ubuntu Server Pro** que escanea y monitorea de manera **100% autónoma** todos los contenedores Docker y servicios activos del servidor sin necesidad de configuración manual.

![Dashboard Preview](https://img.shields.io/badge/Status-Live-emerald?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu_Server_Pro-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)

---

## ✨ Características y Auto-Escaneo Autónomo

- **Radar de Auto-Escaneo Autónomo (Sin tocar nada)**:
  - Escanea dinámicamente cada 2 segundos el socket `/var/run/docker.sock` y la pila de red del servidor.
  - Detecta automáticamente nuevos contenedores cuando se inician o detienen y los muestra en la pantalla de inmediato.
  - Clasifica automáticamente los servicios por categoría: 🌐 Web / API, 🗄️ Base de Datos, 📊 Monitoreo, 🎬 Multimedia, 🧠 IA & Automatización, 🛡️ Red/VPN.
  - Proporciona botones de acceso directo **"Abrir Servicio ↗"** para cualquier puerto web expuesto (`http://<ip-servidor>:<puerto>`).
- **Métricas de Rendimiento del Host (psutil)**:
  - CPU global, frecuencia en MHz, número de núcleos y *Load Averages* (1m, 5m, 15m).
  - Memoria RAM (utilizada vs total en GB y %).
  - Espacio en Disco Raíz (`/`) del servidor anfitrión.
- **Gráficas en Vivo con Chart.js**:
  - Gráficas de área fluidas en Dark Mode con gradientes de color, alimentadas por **WebSockets** cada 2 segundos.
- **Inspección Individual de Contenedores**:
  - Consumo en vivo de CPU (%) y RAM (MB / %) de cada contenedor.
  - Indicador de estado: **verde neón pulsante** si está activo (`running`), **rojo** si está detenido (`exited`).
  - Barra de búsqueda y filtrado instantáneo por nombre, imagen o puerto.

---

## ⚡ Instalación en 1 Solo Paso en Ubuntu Server Pro

Para desplegarlo en tu servidor Ubuntu Server Pro sin preocuparte por instalar dependencias manualmente:

### Paso Único: Ejecutar el Instalador Automático
Copia o clona esta carpeta a tu servidor Ubuntu y ejecuta:

```bash
sudo bash install.sh
```

**¿Qué hace automáticamente el instalador por ti?**
1. Comprueba si Docker y Docker Compose están instalados (si faltan, los instala oficialmente).
2. Habilita el servicio de Docker e integra al usuario en el grupo de permisos.
3. Configura y levanta el contenedor con `docker compose up -d --build`.
4. Obtiene la dirección IP de tu servidor y te entrega el enlace listo para abrir:
   ```
   👉 http://<IP-DE-TU-SERVIDOR>:8080
   ```

---

## 🐳 Despliegue Manual con Docker Compose

Si prefieres ejecutar el comando tú mismo:

```bash
# Iniciar en segundo plano
docker compose up -d --build

# Ver logs en vivo
docker compose logs -f

# Detener el servicio
docker compose down
```

### Configuración del Contenedor (`docker-compose.yml`)
- **Modo de Red**: `network_mode: "host"` (permite al contenedor escanear directamente todos los puertos y servicios locales de Ubuntu Server sin proxy intermedio).
- **Seguridad**: El socket `/var/run/docker.sock` se monta en modo estricto de solo lectura (`:ro`).
- **Bajo Consumo**: Limitado a un máximo de **0.50 CPU** y **256 MB de RAM**.

---

## 📡 Canales y API REST

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/` | Interfaz Web SPA completa (Dark Mode) |
| `GET` | `/api/status` | Consolidado de estado del host, contenedores y servicios descubiertos |
| `GET` | `/api/system` | Métricas del sistema Ubuntu (CPU, RAM, Disco) |
| `GET` | `/api/docker` | Lista y estadísticas de contenedores Docker |
| `GET` | `/api/ping` | Health check |
| `WS` | `/ws/stats` | Transmisión WebSocket en tiempo real cada 2s |

---

## 🎯 Resultado: Cero Intervención
Una vez encendido, no necesitas registrar puertos ni editar archivos de configuración:
Cada vez que hagas un `docker run` o levantes un `docker compose` con cualquier aplicación (Nginx, PostgreSQL, Redis, Nextcloud, Grafana, etc.), **el dashboard lo detecta y lo añade automáticamente a la pantalla**.
