import os
import platform
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import psutil
import docker

# Initialize Docker client
_docker_client = None

def get_docker_client():
    global _docker_client
    if _docker_client is None:
        try:
            _docker_client = docker.from_env(timeout=3)
            _docker_client.ping()
        except Exception:
            _docker_client = None
    return _docker_client


def format_uptime(seconds: float) -> str:
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts) if parts else "< 1m"


def get_detailed_os() -> str:
    """Detecta el nombre detallado del SO, leyendo /etc/host-os-release si corre dentro de Docker en Ubuntu."""
    for path in ['/etc/host-os-release', '/etc/os-release']:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=', 1)[1].strip().strip('"')
            except Exception:
                pass
    return f"{platform.system()} {platform.release()}"


KNOWN_PORT_SERVICES = {
    22: ("SSH Remote Access", "system", "🔐"),
    53: ("DNS Server", "network", "🌐"),
    80: ("HTTP Web Server", "web", "🌍"),
    443: ("HTTPS Web Server", "web", "🔒"),
    3000: ("Web App / Dashboard", "web", "📊"),
    3306: ("MySQL Database", "database", "🗄️"),
    5000: ("Flask / Docker Registry", "web", "🚀"),
    5432: ("PostgreSQL Database", "database", "🐘"),
    6379: ("Redis In-Memory Cache", "database", "⚡"),
    8000: ("FastAPI / Web App", "web", "⚡"),
    8080: ("Monitor Dashboard Web", "web", "🖥️"),
    8443: ("HTTPS Alt Web", "web", "🔒"),
    9000: ("Portainer / Management", "monitoring", "🐳"),
    9090: ("Prometheus Metrics", "monitoring", "📈"),
    9443: ("Portainer HTTPS", "monitoring", "🐳"),
    27017: ("MongoDB Database", "database", "🍃"),
}


def categorize_service(image_name: str, name: str) -> dict:
    """Clasifica automáticamente el tipo de servicio según imagen y nombre."""
    image_lower = (image_name or "").lower()
    name_lower = (name or "").lower()
    combined = f"{image_lower} {name_lower}"

    if any(k in combined for k in ["postgres", "mysql", "mariadb", "mongo", "redis", "memcached", "sqlite", "clickhouse"]):
        return {"category": "database", "label": "Base de Datos", "badge_color": "indigo", "icon": "🗄️"}
    elif any(k in combined for k in ["grafana", "prometheus", "netdata", "portainer", "uptime-kuma", "loki", "jaeger", "cadvisor", "dozzle"]):
        return {"category": "monitoring", "label": "Monitoreo", "badge_color": "emerald", "icon": "📊"}
    elif any(k in combined for k in ["nginx", "apache", "caddy", "traefik", "node", "next", "vue", "react", "fastapi", "flask", "django", "wordpress", "ghost"]):
        return {"category": "web", "label": "Servicio Web", "badge_color": "sky", "icon": "🌐"}
    elif any(k in combined for k in ["ollama", "n8n", "open-webui", "comfyui", "stable-diffusion", "flowise", "langchain"]):
        return {"category": "ai", "label": "IA / Auto", "badge_color": "purple", "icon": "🧠"}
    elif any(k in combined for k in ["nextcloud", "owncloud", "minio", "s3", "seafile", "syncthing"]):
        return {"category": "storage", "label": "Cloud / Storage", "badge_color": "amber", "icon": "☁️"}
    elif any(k in combined for k in ["plex", "jellyfin", "emby", "radarr", "sonarr", "transmission", "qbittorrent"]):
        return {"category": "media", "label": "Multimedia", "badge_color": "rose", "icon": "🎬"}
    elif any(k in combined for k in ["wireguard", "tailscale", "pihole", "adguard", "openvpn", "cloudflared"]):
        return {"category": "network", "label": "Red / VPN", "badge_color": "teal", "icon": "🛡️"}
    else:
        return {"category": "general", "label": "Aplicación", "badge_color": "zinc", "icon": "📦"}


def scan_host_listening_services() -> list:
    """Escanea automáticamente los puertos TCP en escucha en el servidor."""
    discovered = []
    seen_ports = set()
    
    try:
        connections = psutil.net_connections(kind='tcp')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                laddr = conn.laddr
                port = laddr.port
                if port in seen_ports:
                    continue
                seen_ports.add(port)

                ip = laddr.ip if laddr.ip else "0.0.0.0"
                pid = conn.pid
                proc_name = "System"
                if pid:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                    except Exception:
                        proc_name = f"PID {pid}"

                known = KNOWN_PORT_SERVICES.get(port)
                service_desc = known[0] if known else f"Servicio en puerto {port}"
                category = known[1] if known else "general"
                icon = known[2] if known else "🔌"

                is_web = port in [80, 443, 3000, 5000, 8000, 8080, 8443, 9000, 9443] or category in ["web", "monitoring"]

                discovered.append({
                    "port": port,
                    "bind_ip": ip,
                    "protocol": "TCP",
                    "pid": pid,
                    "process": proc_name,
                    "description": service_desc,
                    "category": category,
                    "icon": icon,
                    "is_web": is_web,
                    "link_port": port if is_web else None
                })
    except Exception:
        pass

    discovered.sort(key=lambda x: x["port"])
    return discovered


def get_system_metrics() -> dict:
    """Recolecta las métricas de rendimiento del host en tiempo real."""
    # CPU usage
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_count = psutil.cpu_count(logical=True)
    cpu_freq = psutil.cpu_freq()
    freq_current = round(cpu_freq.current, 0) if cpu_freq else 0

    # Memory usage
    vm = psutil.virtual_memory()
    mem_total_gb = round(vm.total / (1024 ** 3), 2)
    mem_used_gb = round(vm.used / (1024 ** 3), 2)
    mem_available_gb = round(vm.available / (1024 ** 3), 2)
    mem_percent = vm.percent

    # Disk usage (check /host if mounted inside docker container, otherwise root / or windows drive)
    if os.path.exists('/host') and os.path.isdir('/host'):
        disk_path = '/host'
    elif os.name != 'nt':
        disk_path = '/'
    else:
        disk_path = os.path.splitdrive(os.getcwd())[0] + '\\'
    try:
        disk = psutil.disk_usage(disk_path)
        disk_total_gb = round(disk.total / (1024 ** 3), 2)
        disk_used_gb = round(disk.used / (1024 ** 3), 2)
        disk_free_gb = round(disk.free / (1024 ** 3), 2)
        disk_percent = disk.percent
    except Exception:
        disk_total_gb = 0
        disk_used_gb = 0
        disk_free_gb = 0
        disk_percent = 0

    # Load average (Linux/Unix)
    load_avg = [0.0, 0.0, 0.0]
    if hasattr(psutil, "getloadavg"):
        try:
            load_avg = [round(x, 2) for x in psutil.getloadavg()]
        except Exception:
            pass

    # Uptime
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time

    return {
        "hostname": socket.gethostname(),
        "os": get_detailed_os(),
        "uptime": format_uptime(uptime_seconds),
        "uptime_seconds": int(uptime_seconds),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu": {
            "percent": cpu_percent,
            "cores": cpu_count,
            "freq_mhz": freq_current,
            "load_avg": load_avg
        },
        "memory": {
            "total_gb": mem_total_gb,
            "used_gb": mem_used_gb,
            "available_gb": mem_available_gb,
            "percent": mem_percent
        },
        "disk": {
            "path": disk_path,
            "total_gb": disk_total_gb,
            "used_gb": disk_used_gb,
            "free_gb": disk_free_gb,
            "percent": disk_percent
        }
    }


def parse_ports(container_attrs: dict) -> list:
    """Extrae y formatea los puertos mapeados del contenedor."""
    ports_config = container_attrs.get("NetworkSettings", {}).get("Ports") or {}
    clean_ports = []
    
    for internal_proto, host_bindings in ports_config.items():
        parts = internal_proto.split("/")
        internal_port = parts[0]
        protocol = parts[1] if len(parts) > 1 else "tcp"

        if host_bindings:
            for binding in host_bindings:
                host_port = binding.get("HostPort")
                host_ip = binding.get("HostIp", "0.0.0.0")
                clean_ports.append({
                    "internal": internal_port,
                    "external": host_port,
                    "protocol": protocol,
                    "host_ip": host_ip,
                    "display": f"{host_port}:{internal_port}/{protocol}",
                    "link_port": host_port
                })
        else:
            clean_ports.append({
                "internal": internal_port,
                "external": None,
                "protocol": protocol,
                "host_ip": None,
                "display": f"{internal_port}/{protocol}",
                "link_port": None
            })

    # Sort so exposed ports with external mapping appear first
    clean_ports.sort(key=lambda p: (p["external"] is None, p["internal"]))
    return clean_ports


def calculate_cpu_percent(stats: dict) -> float:
    """Calcula el uso de CPU de un contenedor según la fórmula oficial de Docker."""
    try:
        cpu_stats = stats.get("cpu_stats", {})
        precpu_stats = stats.get("precpu_stats", {})

        cpu_usage = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        precpu_usage = precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        cpu_delta = cpu_usage - precpu_usage

        system_cpu = cpu_stats.get("system_cpu_usage", 0)
        precpu_system = precpu_stats.get("system_cpu_usage", 0)
        system_delta = system_cpu - precpu_system

        online_cpus = cpu_stats.get("online_cpus")
        if not online_cpus:
            percpu = cpu_stats.get("cpu_usage", {}).get("percpu_usage", [])
            online_cpus = len(percpu) if percpu else 1

        if system_delta > 0 and cpu_delta > 0:
            return round((cpu_delta / system_delta) * online_cpus * 100.0, 1)
        return 0.0
    except Exception:
        return 0.0


def calculate_memory_stats(stats: dict) -> dict:
    """Calcula uso de memoria (MB y porcentaje) de un contenedor."""
    try:
        mem = stats.get("memory_stats", {})
        usage = mem.get("usage", 0)
        details = mem.get("stats", {})
        # Restar caché según docker stats
        cache = details.get("inactive_file", details.get("cache", 0))
        used = max(0, usage - cache)
        limit = mem.get("limit", 1)
        percent = round((used / limit) * 100.0, 1) if limit > 0 else 0.0

        return {
            "used_mb": round(used / (1024 * 1024), 1),
            "limit_mb": round(limit / (1024 * 1024), 1),
            "percent": percent
        }
    except Exception:
        return {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0}


def fetch_container_stats(container) -> dict:
    """Obtiene estadísticas de un contenedor en ejecución con timeout."""
    try:
        raw_stats = container.stats(stream=False)
        cpu_pct = calculate_cpu_percent(raw_stats)
        mem_info = calculate_memory_stats(raw_stats)
        return {
            "cpu_percent": cpu_pct,
            "memory": mem_info
        }
    except Exception:
        return {
            "cpu_percent": 0.0,
            "memory": {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0}
        }


def get_demo_containers() -> list:
    """Retorna contenedores de demostración interactivos si Docker no está corriendo localmente."""
    import random
    containers = [
        {
            "id": "a1b2c3d4e5f6",
            "name": "web-nginx-proxy",
            "image": "nginx:alpine-slim",
            "status": "running",
            "state": "running",
            "created": "2026-09-10T10:00:00Z",
            "ports": [
                {"internal": "80", "external": "80", "protocol": "tcp", "display": "80:80/tcp", "link_port": "80"},
                {"internal": "443", "external": "443", "protocol": "tcp", "display": "443:443/tcp", "link_port": "443"}
            ],
            "cpu_percent": round(random.uniform(0.3, 1.8), 1),
            "memory": {"used_mb": 24.5, "limit_mb": 512.0, "percent": 4.8}
        },
        {
            "id": "b2c3d4e5f6a1",
            "name": "api-backend-fastapi",
            "image": "python:3.11-slim",
            "status": "running",
            "state": "running",
            "created": "2026-09-10T10:05:00Z",
            "ports": [
                {"internal": "8000", "external": "8080", "protocol": "tcp", "display": "8080:8000/tcp", "link_port": "8080"}
            ],
            "cpu_percent": round(random.uniform(1.2, 4.5), 1),
            "memory": {"used_mb": 88.2, "limit_mb": 1024.0, "percent": 8.6}
        },
        {
            "id": "c3d4e5f6a1b2",
            "name": "db-postgresql-16",
            "image": "postgres:16-alpine",
            "status": "running",
            "state": "running",
            "created": "2026-09-10T09:30:00Z",
            "ports": [
                {"internal": "5432", "external": "5432", "protocol": "tcp", "display": "5432:5432/tcp", "link_port": "5432"}
            ],
            "cpu_percent": round(random.uniform(0.8, 2.4), 1),
            "memory": {"used_mb": 142.0, "limit_mb": 2048.0, "percent": 6.9}
        },
        {
            "id": "d4e5f6a1b2c3",
            "name": "redis-cache-layer",
            "image": "redis:7-alpine",
            "status": "running",
            "state": "running",
            "created": "2026-09-10T09:30:00Z",
            "ports": [
                {"internal": "6379", "external": "6379", "protocol": "tcp", "display": "6379:6379/tcp", "link_port": "6379"}
            ],
            "cpu_percent": round(random.uniform(0.1, 0.6), 1),
            "memory": {"used_mb": 18.4, "limit_mb": 512.0, "percent": 3.6}
        },
        {
            "id": "e5f6a1b2c3d4",
            "name": "grafana-metrics",
            "image": "grafana/grafana:latest",
            "status": "running",
            "state": "running",
            "created": "2026-09-11T12:00:00Z",
            "ports": [
                {"internal": "3000", "external": "3000", "protocol": "tcp", "display": "3000:3000/tcp", "link_port": "3000"}
            ],
            "cpu_percent": round(random.uniform(0.4, 1.5), 1),
            "memory": {"used_mb": 94.6, "limit_mb": 1024.0, "percent": 9.2}
        },
        {
            "id": "f6a1b2c3d4e5",
            "name": "worker-batch-etl",
            "image": "python:3.11-alpine",
            "status": "exited",
            "state": "exited",
            "created": "2026-09-11T15:00:00Z",
            "ports": [],
            "cpu_percent": 0.0,
            "memory": {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0}
        }
    ]
    for c in containers:
        c["service_info"] = categorize_service(c["image"], c["name"])
    return containers


def get_docker_metrics() -> dict:
    """Recolecta lista de contenedores Docker y sus estadísticas de uso."""
    client = get_docker_client()

    if not client:
        # Intento de reconexión rápida
        try:
            client = docker.from_env(timeout=2)
            client.ping()
            global _docker_client
            _docker_client = client
        except Exception as e:
            demo_containers = get_demo_containers()
            running = sum(1 for c in demo_containers if c["status"] == "running")
            return {
                "available": False,
                "is_demo": True,
                "error": f"Docker daemon no detectado localmente. Mostrando contenedores de demostración interactivos.",
                "total": len(demo_containers),
                "running": running,
                "stopped": len(demo_containers) - running,
                "containers": demo_containers
            }

    try:
        raw_containers = client.containers.list(all=True)
    except Exception as e:
        demo_containers = get_demo_containers()
        running = sum(1 for c in demo_containers if c["status"] == "running")
        return {
            "available": False,
            "is_demo": True,
            "error": f"Error al listar contenedores ({str(e)}). Mostrando modo de demostración.",
            "total": len(demo_containers),
            "running": running,
            "stopped": len(demo_containers) - running,
            "containers": demo_containers
        }

    containers_data = []
    running_count = 0
    stopped_count = 0
    running_containers_to_stat = []

    for c in raw_containers:
        status = c.status.lower()
        is_running = status == "running"
        if is_running:
            running_count += 1
            running_containers_to_stat.append(c)
        else:
            stopped_count += 1

        name = c.name.lstrip("/")
        image_tags = c.image.tags
        image_name = image_tags[0] if image_tags else (c.attrs.get("Config", {}).get("Image") or c.image.short_id)
        ports = parse_ports(c.attrs)

        containers_data.append({
            "id": c.short_id,
            "full_id": c.id,
            "name": name,
            "image": image_name,
            "status": c.status,
            "state": c.attrs.get("State", {}).get("Status", c.status),
            "created": c.attrs.get("Created", ""),
            "ports": ports,
            "service_info": categorize_service(image_name, name),
            "cpu_percent": 0.0,
            "memory": {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0}
        })

    # Consulta concurrente de estadísticas para contenedores en ejecución
    stats_map = {}
    if running_containers_to_stat:
        with ThreadPoolExecutor(max_workers=min(10, len(running_containers_to_stat))) as executor:
            future_to_id = {
                executor.submit(fetch_container_stats, c): c.short_id
                for c in running_containers_to_stat
            }
            for future in as_completed(future_to_id, timeout=2.5):
                cid = future_to_id[future]
                try:
                    stats_map[cid] = future.result()
                except Exception:
                    stats_map[cid] = {
                        "cpu_percent": 0.0,
                        "memory": {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0}
                    }

    # Integrar estadísticas obtenidas
    for c_info in containers_data:
        cid = c_info["id"]
        if cid in stats_map:
            c_info["cpu_percent"] = stats_map[cid]["cpu_percent"]
            c_info["memory"] = stats_map[cid]["memory"]

    # Ordenar: primero los activos, luego alfabéticamente
    containers_data.sort(key=lambda x: (x["status"] != "running", x["name"].lower()))

    return {
        "available": True,
        "is_demo": False,
        "error": None,
        "total": len(containers_data),
        "running": running_count,
        "stopped": stopped_count,
        "containers": containers_data
    }


def get_full_metrics() -> dict:
    """Retorna el paquete consolidado de métricas de host, Docker y servicios autodetectados."""
    sys = get_system_metrics()
    doc = get_docker_metrics()
    host_services = scan_host_listening_services()

    # Consolidar escaneo de servicios web detectados (tanto de Docker como de Host)
    discovered_services = []
    seen_web_ports = set()

    # 1. Servicios descubiertos a partir de contenedores Docker en ejecución
    for c in doc.get("containers", []):
        if c.get("status", "").lower() == "running":
            # Asegurar que tenga service_info
            s_info = c.get("service_info") or categorize_service(c.get("image", ""), c.get("name", ""))
            for p in c.get("ports", []):
                ext_port = p.get("external")
                if ext_port:
                    try:
                        ext_num = int(ext_port)
                        seen_web_ports.add(ext_num)
                        discovered_services.append({
                            "name": c["name"],
                            "source": "docker",
                            "port": ext_num,
                            "display_port": p.get("display", f"{ext_num}/tcp"),
                            "category": s_info.get("category", "general"),
                            "category_label": s_info.get("label", "Docker App"),
                            "icon": s_info.get("icon", "🐳"),
                            "link_port": ext_num,
                            "status": "running"
                        })
                    except Exception:
                        pass

    # 2. Servicios nativos del Host notables o con puerto web que no estén ya cubiertos por Docker
    for h in host_services:
        if h["port"] not in seen_web_ports and (h["is_web"] or h["port"] in KNOWN_PORT_SERVICES):
            discovered_services.append({
                "name": h["process"] if h["process"] not in ["System", "Desconocido"] else h["description"],
                "source": "host",
                "port": h["port"],
                "display_port": f"{h['port']}/tcp",
                "category": h["category"],
                "category_label": "Servicio Host",
                "icon": h["icon"],
                "link_port": h["link_port"],
                "status": "listening"
            })

    # Ordenar servicios por número de puerto
    discovered_services.sort(key=lambda s: s["port"])

    return {
        "system": sys,
        "docker": doc,
        "host_services": host_services,
        "discovered_services": discovered_services
    }
