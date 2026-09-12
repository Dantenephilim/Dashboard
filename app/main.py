import asyncio
import json
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.monitor import get_full_metrics, get_system_metrics, get_docker_metrics

# Configuración de logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dashboard")

# Directorios de la aplicación
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="Ubuntu & Docker Live Dashboard",
    description="Dashboard ligero en tiempo real para monitoreo de Ubuntu y Docker",
    version="1.0.0"
)

# CORS para máxima compatibilidad si se usa detrás de proxies o durante desarrollo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montar archivos estáticos
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Buffer circular para el historial de métricas (últimos 30 puntos = ~60 segundos)
HISTORY_MAX_POINTS = 30
metrics_history = deque(maxlen=HISTORY_MAX_POINTS)

# Conjunto de conexiones WebSocket activas
active_connections: Set[WebSocket] = set()

# Últimas métricas cacheadas
latest_metrics = {}


async def broadcast_metrics(payload: dict):
    """Transmite métricas a todos los clientes WebSocket conectados."""
    if not active_connections:
        return
    
    dead_connections = set()
    message_text = json.dumps(payload)

    for connection in list(active_connections):
        try:
            await connection.send_text(message_text)
        except Exception:
            dead_connections.add(connection)

    for dead in dead_connections:
        active_connections.discard(dead)


async def metrics_collector_loop():
    """Bucle en segundo plano que recolecta métricas cada 2 segundos."""
    global latest_metrics
    logger.info("Iniciando bucle de recolección de métricas cada 2s...")
    
    while True:
        try:
            # Ejecutar en thread pool para evitar bloquear el event loop de asyncio
            metrics = await asyncio.to_thread(get_full_metrics)
            latest_metrics = metrics

            # Añadir punto histórico
            now = datetime.now()
            history_entry = {
                "time": now.strftime("%H:%M:%S"),
                "cpu": metrics["system"]["cpu"]["percent"],
                "memory": metrics["system"]["memory"]["percent"]
            }
            metrics_history.append(history_entry)

            # Transmitir a WebSockets
            update_payload = {
                "type": "update",
                "metrics": metrics,
                "history_point": history_entry
            }
            await broadcast_metrics(update_payload)

        except Exception as e:
            logger.error(f"Error en metrics_collector_loop: {e}", exc_info=True)

        await asyncio.sleep(2)


@app.on_event("startup")
async def startup_event():
    # Inicializar primera recolección de métricas
    global latest_metrics
    try:
        latest_metrics = get_full_metrics()
        now = datetime.now()
        metrics_history.append({
            "time": now.strftime("%H:%M:%S"),
            "cpu": latest_metrics["system"]["cpu"]["percent"],
            "memory": latest_metrics["system"]["memory"]["percent"]
        })
    except Exception as e:
        logger.warning(f"Error inicializando métricas en startup: {e}")

    # Iniciar tarea asíncrona de recolección continua
    asyncio.create_task(metrics_collector_loop())


@app.get("/")
async def root():
    """Sirve la interfaz web principal."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse(status_code=404, content={"error": "index.html no encontrado"})


@app.get("/api/status")
async def api_status():
    """Retorna estado actual completo y el historial de métricas."""
    global latest_metrics
    if not latest_metrics:
        latest_metrics = get_full_metrics()
    return {
        "status": "online",
        "metrics": latest_metrics,
        "history": list(metrics_history)
    }


@app.get("/api/system")
async def api_system():
    """Métricas del sistema anfitrión."""
    return await asyncio.to_thread(get_system_metrics)


@app.get("/api/docker")
async def api_docker():
    """Métricas de Docker y lista de contenedores."""
    return await asyncio.to_thread(get_docker_metrics)


def get_current_commit() -> str:
    import subprocess
    from app import __version__
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, timeout=2)
        return out.decode("utf-8").strip()
    except Exception:
        return "v" + __version__


def check_github_updates() -> dict:
    import urllib.request
    from app import __version__
    current_commit = get_current_commit()
    result = {
        "version": __version__,
        "current_commit": current_commit,
        "update_available": False,
        "latest_commit": current_commit,
        "latest_message": "Sistema al día",
        "update_command": "sudo bash update.sh",
        "error": None
    }
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/Dantenephilim/Dashboard/commits/main",
            headers={"User-Agent": "Ubuntu-Dashboard-Monitor"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                remote_sha = data.get("sha", "")[:7]
                commit_msg = data.get("commit", {}).get("message", "").split("\n")[0]
                result["latest_commit"] = remote_sha
                result["latest_message"] = commit_msg
                if remote_sha and current_commit and not current_commit.startswith("v") and remote_sha != current_commit:
                    result["update_available"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


@app.get("/api/updates")
async def api_updates():
    """Verifica si hay actualizaciones disponibles en GitHub."""
    return await asyncio.to_thread(check_github_updates)


@app.get("/api/ping")
async def api_ping():
    """Health check simple."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.websocket("/ws/stats")
async def websocket_endpoint(websocket: WebSocket):
    """Canal WebSocket para transmisión en tiempo real."""
    await websocket.accept()
    active_connections.add(websocket)
    logger.info(f"Cliente WebSocket conectado. Conexiones activas: {len(active_connections)}")

    try:
        # Enviar estado inicial completo con el historial para renderizar gráficas de inmediato
        initial_payload = {
            "type": "initial",
            "metrics": latest_metrics if latest_metrics else get_full_metrics(),
            "history": list(metrics_history)
        }
        await websocket.send_text(json.dumps(initial_payload))

        # Mantener el socket abierto escuchando posibles pings o mensajes del cliente
        while True:
            data = await websocket.receive_text()
            # Si el cliente solicita un refresh inmediato
            if data == "refresh":
                fresh_metrics = await asyncio.to_thread(get_full_metrics)
                await websocket.send_text(json.dumps({
                    "type": "update",
                    "metrics": fresh_metrics,
                    "history_point": {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "cpu": fresh_metrics["system"]["cpu"]["percent"],
                        "memory": fresh_metrics["system"]["memory"]["percent"]
                    }
                }))

    except WebSocketDisconnect:
        active_connections.discard(websocket)
        logger.info(f"Cliente WebSocket desconectado. Conexiones activas: {len(active_connections)}")
    except Exception as e:
        active_connections.discard(websocket)
        logger.warning(f"Error en WebSocket: {e}")
