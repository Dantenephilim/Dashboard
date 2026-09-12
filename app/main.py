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

from app.monitor import get_full_metrics, get_system_metrics, get_docker_metrics, get_docker_client, container_action

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

# Buffer circular para el historial de métricas (últimos 30 puntos = ~30 segundos en tiempo real)
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
    """Bucle en segundo plano que recolecta métricas cada 1 segundo (ultra tiempo real sin delay)."""
    global latest_metrics
    logger.info("Iniciando bucle de recolección de métricas cada 1s...")
    
    while True:
        try:
            # Ejecutar en thread pool para evitar bloquear el event loop de asyncio
            metrics = await asyncio.to_thread(get_full_metrics)
            latest_metrics = metrics

            # Añadir punto histórico
            now = datetime.now()
            history_entry = {
                "time": now.strftime("%H:%M:%S"),
                "cpu": metrics.get("system", {}).get("cpu", {}).get("percent", 0.0),
                "memory": metrics.get("system", {}).get("memory", {}).get("percent", 0.0)
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

        await asyncio.sleep(1)


@app.on_event("startup")
async def startup_event():
    # Inicializar primera recolección de métricas
    global latest_metrics
    try:
        latest_metrics = await asyncio.to_thread(get_full_metrics)
        now = datetime.now()
        metrics_history.append({
            "time": now.strftime("%H:%M:%S"),
            "cpu": latest_metrics.get("system", {}).get("cpu", {}).get("percent", 0.0),
            "memory": latest_metrics.get("system", {}).get("memory", {}).get("percent", 0.0)
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
    """Retorna estado actual completo y el historial de métricas con tolerancia a fallos."""
    global latest_metrics
    if not latest_metrics:
        try:
            latest_metrics = await asyncio.to_thread(get_full_metrics)
        except Exception as e:
            logger.error(f"Error cargando métricas en /api/status: {e}")
    return {
        "status": "online",
        "metrics": latest_metrics or {},
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


@app.get("/api/containers/{container_id}/logs")
async def api_container_logs(container_id: str, tail: int = 120):
    """Obtiene los últimos logs de un contenedor."""
    client = get_docker_client()
    if not client:
        return {"logs": f"[DEMO MODO] Registros en tiempo real para el contenedor '{container_id}':\n[2026-09-12T05:20:00Z] Worker initialized successfully.\n[2026-09-12T05:20:01Z] Listening on 0.0.0.0.\n[2026-09-12T05:20:05Z] Heartbeat check: OK (latency 0.8ms).\n[2026-09-12T05:21:00Z] Servicing incoming requests. No anomalies detected."}
    try:
        container = client.containers.get(container_id)
        raw_logs = container.logs(tail=tail, timestamps=True)
        return {"logs": raw_logs.decode("utf-8", errors="replace")}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Error al leer logs: {str(e)}"})


@app.post("/api/containers/{container_id}/start")
async def api_container_start(container_id: str):
    """Inicia un contenedor específico."""
    res = await asyncio.to_thread(container_action, container_id, "start")
    if res.get("status") == "error":
        return JSONResponse(status_code=500, content=res)
    return res


@app.post("/api/containers/{container_id}/stop")
async def api_container_stop(container_id: str):
    """Detiene/apaga un contenedor específico."""
    res = await asyncio.to_thread(container_action, container_id, "stop")
    if res.get("status") == "error":
        return JSONResponse(status_code=500, content=res)
    return res


@app.post("/api/containers/{container_id}/restart")
async def api_container_restart(container_id: str):
    """Reinicia un contenedor específico."""
    res = await asyncio.to_thread(container_action, container_id, "restart")
    if res.get("status") == "error":
        return JSONResponse(status_code=500, content=res)
    return res


@app.post("/api/containers/restart-all")
async def api_restart_all_containers():
    """Reinicia todos los contenedores en ejecución."""
    client = get_docker_client()
    if not client:
        return {"success": True, "message": "[DEMO] Todos los contenedores reiniciados en segundo plano."}
    try:
        containers = client.containers.list()
        restarted = []
        for c in containers:
            try:
                c.restart(timeout=5)
                restarted.append(c.name)
            except Exception:
                pass
        return {"success": True, "restarted": restarted, "count": len(restarted)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


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


@app.post("/api/updates/apply")
async def api_apply_update():
    """Descarga los últimos cambios de GitHub y dispara la actualización del contenedor."""
    import subprocess
    try:
        update_script = BASE_DIR.parent / "update.sh"
        if update_script.exists():
            subprocess.Popen(["bash", str(update_script)], cwd=str(BASE_DIR.parent))
            return {
                "status": "ok",
                "message": "Actualización desde GitHub iniciada. El contenedor se reconstruirá en segundo plano."
            }

        subprocess.Popen(
            ["sh", "-c", "git fetch origin main && git reset --hard origin/main"],
            cwd=str(BASE_DIR.parent)
        )
        return {
            "status": "ok",
            "message": "Actualización descargada desde GitHub. Reiniciando servicio..."
        }
    except Exception as e:
        logger.error(f"Error al aplicar actualización: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


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
        metrics = latest_metrics if latest_metrics else await asyncio.to_thread(get_full_metrics)
        initial_payload = {
            "type": "initial",
            "metrics": metrics or {},
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
