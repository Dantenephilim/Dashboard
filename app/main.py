import asyncio
import json
import logging
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
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
    """Bucle en segundo plano que recolecta métricas en ultra tiempo real (500ms) sin retrasos."""
    global latest_metrics
    logger.info("Iniciando bucle de recolección de métricas en ultra tiempo real (cada 500ms)...")
    
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

        await asyncio.sleep(0.5)


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

    # Iniciar programador de actualizaciones automáticas
    asyncio.create_task(auto_update_scheduler_loop())


@app.get("/")
async def root():
    """Sirve la interfaz web principal con cabeceras no-cache para evitar que el navegador guarde versiones viejas."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        resp = FileResponse(str(index_file))
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
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
    # 1. Revisar version.json si existe
    version_file = BASE_DIR / "version.json"
    if version_file.exists():
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                vdata = json.load(f)
                if vdata.get("commit"):
                    return str(vdata["commit"])
        except Exception:
            pass

    # 2. Revisar git en el repositorio
    import subprocess
    from app import __version__
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, timeout=2)
        commit = out.decode("utf-8").strip()
        if commit:
            return commit
    except Exception:
        pass

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
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                remote_sha = data.get("sha", "")[:7]
                commit_msg = data.get("commit", {}).get("message", "").split("\n")[0]
                result["latest_commit"] = remote_sha
                result["latest_message"] = commit_msg
                if remote_sha and current_commit and remote_sha != current_commit:
                    result["update_available"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


@app.get("/api/updates")
async def api_updates():
    """Verifica si hay actualizaciones disponibles en GitHub."""
    return await asyncio.to_thread(check_github_updates)


def trigger_system_update() -> dict:
    """Descarga la última versión de GitHub y actualiza la aplicación."""
    import subprocess
    import shutil
    import os
    import threading
    import time
    import urllib.request
    import zipfile
    import io
    from datetime import datetime

    logger.info("Iniciando proceso de actualización desde GitHub...")

    # Si estamos corriendo fuera de Docker y existe update.sh, usar update.sh local
    is_in_docker = os.path.exists("/.dockerenv") or os.path.exists("/host")
    if not is_in_docker:
        update_script = BASE_DIR.parent / "update.sh"
        if update_script.exists():
            try:
                subprocess.Popen(["bash", str(update_script)], cwd=str(BASE_DIR.parent))
                return {
                    "status": "ok",
                    "message": "Actualización iniciada en el host con update.sh."
                }
            except Exception as e:
                logger.warning(f"No se pudo invocar update.sh en el host ({e}), procediendo con actualización directa...")

    # Obtener el commit remoto más reciente desde GitHub API
    latest_sha = "latest"
    try:
        req_sha = urllib.request.Request(
            "https://api.github.com/repos/Dantenephilim/Dashboard/commits/main",
            headers={"User-Agent": "Ubuntu-Dashboard-Monitor"}
        )
        with urllib.request.urlopen(req_sha, timeout=5) as r:
            if r.status == 200:
                data = json.loads(r.read().decode("utf-8"))
                latest_sha = data.get("sha", "latest")[:7]
    except Exception as e:
        logger.warning(f"No se pudo consultar el último commit en GitHub API: {e}")

    temp_dir = Path("/tmp/dashboard_zip_extract")
    updated = False
    error_details = []

    # Método 1: Descarga directa del ZIP desde GitHub (100% nativo en Python, sin dependencias de git)
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        temp_dir.mkdir(parents=True, exist_ok=True)

        zip_url = "https://github.com/Dantenephilim/Dashboard/archive/refs/heads/main.zip"
        logger.info(f"Descargando paquete de actualización desde {zip_url}...")
        req_zip = urllib.request.Request(
            zip_url,
            headers={"User-Agent": "Ubuntu-Dashboard-Monitor"}
        )
        with urllib.request.urlopen(req_zip, timeout=35) as resp:
            if resp.status == 200:
                zip_data = resp.read()
                with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                    zf.extractall(temp_dir)
                logger.info("Paquete ZIP extraído con éxito en directorio temporal.")

                # Ubicar la carpeta extraída (Dashboard-main)
                extracted_root = None
                for child in temp_dir.iterdir():
                    if child.is_dir() and "Dashboard" in child.name:
                        extracted_root = child
                        break
                if not extracted_root:
                    extracted_root = temp_dir

                src_app = extracted_root / "app"
                if src_app.exists():
                    # Copiar estáticos (index.html, css, js)
                    if (src_app / "static").exists():
                        shutil.copytree(src_app / "static", BASE_DIR / "static", dirs_exist_ok=True)
                        logger.info("Archivos estáticos (HTML/CSS/JS) actualizados con éxito.")

                    # Copiar módulos Python
                    for py_f in src_app.glob("*.py"):
                        shutil.copy2(py_f, BASE_DIR / py_f.name)
                        logger.info(f"Módulo Python '{py_f.name}' actualizado con éxito.")

                    # Copiar update.sh si existe
                    if (extracted_root / "update.sh").exists():
                        try:
                            shutil.copy2(extracted_root / "update.sh", BASE_DIR.parent / "update.sh")
                        except Exception:
                            pass

                    updated = True
            else:
                error_details.append(f"Descarga ZIP respondió con HTTP {resp.status}")
    except Exception as e:
        logger.warning(f"Error descargando ZIP desde GitHub ({e}). Probando fallback con git clone...")
        error_details.append(f"Fallo descarga ZIP: {e}")

    # Método 2 (Fallback): Git clone si el método ZIP falló
    if not updated:
        try:
            clone_dir = Path("/tmp/dashboard_git_clone")
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)
            logger.info("Intentando git clone como método de respaldo...")
            clone_res = subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/Dantenephilim/Dashboard.git", str(clone_dir)],
                capture_output=True,
                text=True,
                timeout=45
            )
            if clone_res.returncode == 0:
                src_app = clone_dir / "app"
                if src_app.exists():
                    if (src_app / "static").exists():
                        shutil.copytree(src_app / "static", BASE_DIR / "static", dirs_exist_ok=True)
                    for py_f in src_app.glob("*.py"):
                        shutil.copy2(py_f, BASE_DIR / py_f.name)
                    updated = True
            else:
                error_details.append(f"Git clone error: {clone_res.stderr.strip()}")
            shutil.rmtree(clone_dir, ignore_errors=True)
        except Exception as git_err:
            error_details.append(f"Fallo git clone: {git_err}")

    # Limpieza de temporales
    if temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)

    if not updated:
        return {
            "status": "error",
            "message": f"No se pudo descargar la actualización ({'; '.join(error_details)}). En tu terminal ejecuta: cd ~/Dashboard && sudo bash update.sh"
        }

    # Guardar version.json con el commit actualizado
    from app import __version__
    version_file = BASE_DIR / "version.json"
    try:
        with open(version_file, "w", encoding="utf-8") as f:
            json.dump({
                "commit": latest_sha,
                "updated_at": datetime.now().isoformat(),
                "version": __version__
            }, f, indent=2)
    except Exception as e:
        logger.warning(f"No se pudo guardar {version_file}: {e}")

    logger.info(f"Actualización completada a {latest_sha}. Programando reinicio del servidor...")

    # Reinicio seguro en segundo plano para que Docker reinicie el contenedor automáticamente
    def restart_worker():
        time.sleep(1.5)
        logger.info("Reiniciando proceso Uvicorn / Contenedor...")
        os._exit(0)

    threading.Thread(target=restart_worker, daemon=True).start()

    return {
        "status": "ok",
        "commit": latest_sha,
        "message": f"¡Actualizado exitosamente al commit {latest_sha}! El dashboard se reiniciará en 2 segundos."
    }


@app.post("/api/updates/apply")
async def api_apply_update():
    """Descarga los últimos cambios de GitHub y dispara la actualización del contenedor."""
    try:
        res = await asyncio.to_thread(trigger_system_update)
        status_code = 200 if res.get("status") == "ok" else 500
        return JSONResponse(status_code=status_code, content=res)
    except Exception as e:
        logger.error(f"Error al aplicar actualización: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


# =========================================================================
# PROGRAMADOR DE ACTUALIZACIONES AUTOMÁTICAS (AUTO-UPDATE SCHEDULER)
# =========================================================================
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SCHEDULE_FILE = DATA_DIR / "autoupdate.json"


def compute_next_run(time_str: str, frequency: str) -> str:
    """Calcula la próxima fecha/hora de ejecución según hora (HH:MM) y frecuencia."""
    try:
        parts = time_str.strip().split(":")
        target_hour = int(parts[0]) if len(parts) > 0 else 4
        target_minute = int(parts[1]) if len(parts) > 1 else 0
    except Exception:
        target_hour, target_minute = 4, 0

    now = datetime.now()
    target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)

    if frequency == "12h":
        while target <= now:
            target += timedelta(hours=12)
    elif frequency == "weekly":
        # Domingos (weekday() == 6)
        while target <= now or target.weekday() != 6:
            target += timedelta(days=1)
    else:
        # daily
        if target <= now:
            target += timedelta(days=1)

    return target.isoformat()


def build_cron_command(time_str: str, frequency: str) -> str:
    """Genera la sintaxis exacta de crontab para Ubuntu Server."""
    try:
        parts = time_str.strip().split(":")
        minute = int(parts[1]) if len(parts) > 1 else 0
        hour = int(parts[0]) if len(parts) > 0 else 4
    except Exception:
        minute, hour = 0, 4

    if frequency == "12h":
        h_str = f"{hour},{(hour + 12) % 24}"
        return f"{minute} {h_str} * * * root cd ~/Dashboard && bash update.sh >> /var/log/dashboard-autoupdate.log 2>&1"
    elif frequency == "weekly":
        return f"{minute} {hour} * * 0 root cd ~/Dashboard && bash update.sh >> /var/log/dashboard-autoupdate.log 2>&1"
    else:
        return f"{minute} {hour} * * * root cd ~/Dashboard && bash update.sh >> /var/log/dashboard-autoupdate.log 2>&1"


def load_autoupdate_config() -> dict:
    """Carga la configuración persistente del programador de actualizaciones."""
    if SCHEDULE_FILE.exists():
        try:
            with open(SCHEDULE_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                if "next_run" not in cfg or not cfg["next_run"]:
                    cfg["next_run"] = compute_next_run(cfg.get("time", "04:00"), cfg.get("frequency", "daily"))
                cfg["host_cron"] = build_cron_command(cfg.get("time", "04:00"), cfg.get("frequency", "daily"))
                return cfg
        except Exception as e:
            logger.warning(f"Error leyendo {SCHEDULE_FILE}: {e}")

    default_cfg = {
        "enabled": False,
        "time": "04:00",
        "frequency": "daily",
        "only_if_new": True,
        "last_run": None,
        "last_status": "Sin ejecuciones previas registradas",
        "next_run": compute_next_run("04:00", "daily"),
        "host_cron": build_cron_command("04:00", "daily")
    }
    save_autoupdate_config(default_cfg)
    return default_cfg


def save_autoupdate_config(cfg: dict):
    """Guarda la configuración del programador de actualizaciones en JSON."""
    try:
        with open(SCHEDULE_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error guardando {SCHEDULE_FILE}: {e}")


async def auto_update_scheduler_loop():
    """Bucle en segundo plano que revisa periódicamente si es momento de actualizar automáticamente."""
    logger.info("Iniciando servicio de actualizaciones automáticas programadas...")
    while True:
        try:
            cfg = load_autoupdate_config()
            if cfg.get("enabled"):
                next_run_str = cfg.get("next_run")
                if next_run_str:
                    try:
                        next_dt = datetime.fromisoformat(next_run_str)
                        now_dt = datetime.now()
                        if now_dt >= next_dt:
                            logger.info(f"[AutoUpdate] Hora programada alcanzada ({next_run_str}). Evaluando ciclo de actualización...")
                            should_run = True
                            if cfg.get("only_if_new", True):
                                up = await asyncio.to_thread(check_github_updates)
                                should_run = bool(up.get("update_available"))
                                if not should_run:
                                    logger.info("[AutoUpdate] GitHub ya está al día. Omitiendo reconstrucción.")
                                    cfg["last_status"] = f"Comprobado {now_dt.strftime('%d/%m %H:%M')} (Sistema al día)"

                            if should_run:
                                logger.info("[AutoUpdate] Aplicando actualización programada...")
                                await asyncio.to_thread(trigger_system_update)
                                cfg["last_run"] = now_dt.isoformat()
                                cfg["last_status"] = f"Actualizado con éxito el {now_dt.strftime('%d/%m/%Y %H:%M')}"

                            cfg["next_run"] = compute_next_run(cfg.get("time", "04:00"), cfg.get("frequency", "daily"))
                            save_autoupdate_config(cfg)
                    except Exception as parse_err:
                        logger.warning(f"Error parseando fecha en auto_update_scheduler: {parse_err}")
        except Exception as e:
            logger.error(f"Error en auto_update_scheduler_loop: {e}")

        await asyncio.sleep(30)


@app.get("/api/updates/schedule")
async def api_get_update_schedule():
    """Retorna la configuración y estado actual de las actualizaciones automáticas."""
    return load_autoupdate_config()


@app.post("/api/updates/schedule")
async def api_save_update_schedule(request: Request):
    """Guarda la configuración de las actualizaciones automáticas."""
    try:
        body = await request.json()
        cfg = load_autoupdate_config()

        if "enabled" in body:
            cfg["enabled"] = bool(body["enabled"])
        if "time" in body and body["time"]:
            cfg["time"] = str(body["time"]).strip()
        if "frequency" in body and body["frequency"]:
            cfg["frequency"] = str(body["frequency"]).strip()
        if "only_if_new" in body:
            cfg["only_if_new"] = bool(body["only_if_new"])

        cfg["next_run"] = compute_next_run(cfg["time"], cfg["frequency"])
        cfg["host_cron"] = build_cron_command(cfg["time"], cfg["frequency"])
        save_autoupdate_config(cfg)

        logger.info(f"Programación de actualizaciones actualizada: {cfg['frequency']} a las {cfg['time']} (Activo: {cfg['enabled']})")
        return {
            "status": "ok",
            "message": "Programación de actualización automática guardada con éxito.",
            "config": cfg
        }
    except Exception as e:
        logger.error(f"Error guardando programación de actualización: {e}")
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
