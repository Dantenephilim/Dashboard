import os
import platform
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import psutil
import docker

# Initialize Docker client and hot cache
_docker_client = None
_container_stats_cache = {}

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


def get_host_name() -> str:
    """Detecta el hostname real del host anfitrión si corre dentro de un contenedor Docker."""
    for path in ['/etc/host_hostname', '/host/etc/hostname', '/etc/hostname']:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    name = f.read().strip()
                    if name:
                        return name
            except Exception:
                pass
    return socket.gethostname()


def get_detailed_os() -> str:
    """Detecta el nombre detallado del SO, leyendo /etc/host-os-release si corre dentro de Docker en Ubuntu."""
    for path in ['/etc/host-os-release', '/host/etc/os-release', '/etc/os-release']:
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
    21: ("FTP File Transfer", "system", "📁"),
    22: ("SSH Remote Access", "system", "🔐"),
    53: ("DNS Server", "network", "🌐"),
    80: ("Apache / HTTP Web Server", "web", "🪶"),
    443: ("Apache / HTTPS Web Server", "web", "🔒"),
    3000: ("Node.js / Web App", "web", "📊"),
    3306: ("MySQL / MariaDB Database", "database", "🐬"),
    5000: ("Flask / Docker Registry", "web", "🚀"),
    5432: ("PostgreSQL Database", "database", "🐘"),
    5678: ("n8n Workflow Automation", "ai", "⚡"),
    6379: ("Redis In-Memory Cache", "database", "⚡"),
    8000: ("FastAPI / Web App", "web", "⚡"),
    8080: ("HTTP Proxy / Alt Web", "web", "🌐"),
    8090: ("Monitor Dashboard Web", "web", "🖥️"),
    8443: ("HTTPS Alt Web", "web", "🔒"),
    8834: ("Nessus Scanner Web", "security", "🛡️"),
    8888: ("Jupyter / Web App", "web", "🪐"),
    9000: ("Portainer / Management", "monitoring", "🐳"),
    9090: ("Prometheus / Cockpit", "monitoring", "📈"),
    9443: ("Portainer HTTPS", "monitoring", "🐳"),
    10000: ("Webmin Admin Panel", "system", "⚙️"),
    11434: ("Ollama AI LLM Service", "ai", "🦙"),
    27017: ("MongoDB Database", "database", "🍃"),
}


def categorize_service(image_name: str, name: str) -> dict:
    """Clasifica automáticamente el tipo de servicio según imagen y nombre."""
    image_lower = (image_name or "").lower()
    name_lower = (name or "").lower()
    combined = f"{image_lower} {name_lower}"

    if "nessus" in combined:
        return {"category": "security", "label": "Nessus Scanner", "badge_color": "amber", "icon": "🛡️"}
    elif "apache" in combined or "httpd" in combined:
        return {"category": "web", "label": "Apache Web Server", "badge_color": "rose", "icon": "🪶"}
    elif "wazuh" in combined:
        return {"category": "security", "label": "Wazuh SIEM", "badge_color": "blue", "icon": "🛡️"}
    elif "graylog" in combined:
        return {"category": "logging", "label": "Graylog Logs", "badge_color": "orange", "icon": "📜"}
    elif "ollama" in combined:
        return {"category": "ai", "label": "Ollama LLM", "badge_color": "purple", "icon": "🦙"}
    elif "open-webui" in combined:
        return {"category": "ai", "label": "Open-WebUI", "badge_color": "violet", "icon": "🤖"}
    elif "n8n" in combined:
        return {"category": "ai", "label": "n8n Automatización", "badge_color": "rose", "icon": "⚡"}
    elif "osiris" in combined:
        return {"category": "web", "label": "Osiris Web", "badge_color": "sky", "icon": "👁️"}
    elif "mcp" in combined:
        return {"category": "mcp", "label": "Servidor MCP", "badge_color": "teal", "icon": "🔌"}
    elif any(k in combined for k in ["postgres", "mysql", "mariadb", "mongo", "redis", "memcached", "sqlite", "clickhouse"]):
        return {"category": "database", "label": "Base de Datos", "badge_color": "indigo", "icon": "🐘" if "postgres" in combined else "🗄️"}
    elif any(k in combined for k in ["grafana", "prometheus", "netdata", "portainer", "uptime-kuma", "loki", "jaeger", "cadvisor", "dozzle"]):
        return {"category": "monitoring", "label": "Monitoreo", "badge_color": "emerald", "icon": "📊"}
    elif any(k in combined for k in ["nginx", "caddy", "traefik", "node", "next", "vue", "react", "fastapi", "flask", "django", "wordpress", "ghost"]):
        return {"category": "web", "label": "Servicio Web", "badge_color": "sky", "icon": "🌐"}
    elif any(k in combined for k in ["nextcloud", "owncloud", "minio", "s3", "seafile", "syncthing"]):
        return {"category": "storage", "label": "Cloud / Storage", "badge_color": "amber", "icon": "☁️"}
    elif any(k in combined for k in ["plex", "jellyfin", "emby", "radarr", "sonarr", "transmission", "qbittorrent"]):
        return {"category": "media", "label": "Multimedia", "badge_color": "rose", "icon": "🎬"}
    elif any(k in combined for k in ["wireguard", "tailscale", "pihole", "adguard", "openvpn", "cloudflared"]):
        return {"category": "network", "label": "Red / VPN", "badge_color": "teal", "icon": "🛡️"}
    else:
        return {"category": "general", "label": "Aplicación", "badge_color": "zinc", "icon": "📦"}


def parse_proc_net_tcp_ports() -> set:
    """Lee sockets en escucha (estado 0A = TCP_LISTEN) directamente desde el host Ubuntu."""
    ports = set()
    candidate_files = [
        '/host/proc/1/net/tcp',
        '/host/proc/1/net/tcp6',
        '/host/proc/net/tcp',
        '/host/proc/net/tcp6',
        '/proc/net/tcp',
        '/proc/net/tcp6'
    ]
    # Si /host/proc existe, buscar también en PIDs iniciales del host (systemd/init)
    if os.path.exists('/host/proc'):
        try:
            for pid_dir in os.listdir('/host/proc'):
                if pid_dir.isdigit() and int(pid_dir) in [1, 2]:
                    for sub in ['net/tcp', 'net/tcp6']:
                        tf = os.path.join('/host/proc', pid_dir, sub)
                        if tf not in candidate_files and os.path.exists(tf):
                            candidate_files.append(tf)
        except Exception:
            pass

    for p in candidate_files:
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        # parts[3] es el estado ('0A' == TCP_LISTEN)
                        if len(parts) >= 4 and parts[3] == '0A':
                            local_addr = parts[1]
                            if ':' in local_addr:
                                port_hex = local_addr.split(':')[1]
                                port_dec = int(port_hex, 16)
                                if 1 <= port_dec <= 65535:
                                    ports.add(port_dec)
            except Exception:
                pass
    return ports


def check_host_service_installed(service_name: str) -> bool:
    """Verifica si un paquete o servicio está instalado en el sistema operativo Ubuntu del host."""
    checks = {
        "apache": [
            "/host/etc/apache2",
            "/host/usr/sbin/apache2",
            "/host/etc/httpd",
            "/host/usr/sbin/httpd",
            "/host/lib/systemd/system/apache2.service",
            "/host/etc/init.d/apache2"
        ],
        "nessus": [
            "/host/opt/nessus",
            "/host/etc/init.d/nessusd",
            "/host/lib/systemd/system/nessusd.service",
            "/host/etc/systemd/system/nessusd.service"
        ],
        "nginx": [
            "/host/etc/nginx",
            "/host/usr/sbin/nginx",
            "/host/lib/systemd/system/nginx.service"
        ],
        "mysql": [
            "/host/etc/mysql",
            "/host/usr/sbin/mysqld",
            "/host/lib/systemd/system/mysql.service",
            "/host/lib/systemd/system/mariadb.service"
        ]
    }
    paths = checks.get(service_name, [])
    return any(os.path.exists(p) for p in paths)


def scan_host_processes() -> dict:
    """Detecta procesos nativos de Ubuntu corriendo en el host mediante /host/proc y psutil."""
    detected = {}
    proc_dir = '/host/proc' if os.path.exists('/host/proc') else '/proc'
    
    if os.path.exists(proc_dir):
        try:
            for entry in os.listdir(proc_dir):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                p_path = os.path.join(proc_dir, entry)
                
                comm = ""
                comm_file = os.path.join(p_path, 'comm')
                if os.path.exists(comm_file):
                    try:
                        with open(comm_file, 'r', errors='ignore') as f:
                            comm = f.read().strip().lower()
                    except Exception:
                        pass
                
                cmdline = ""
                cmd_file = os.path.join(p_path, 'cmdline')
                if os.path.exists(cmd_file):
                    try:
                        with open(cmd_file, 'r', errors='ignore') as f:
                            cmdline = f.read().replace('\0', ' ').strip().lower()
                    except Exception:
                        pass

                # Detectar Apache
                if comm in ['apache2', 'httpd'] or 'apache2' in cmdline or 'httpd' in cmdline:
                    if 'apache' not in detected:
                        detected['apache'] = {
                            'name': 'Apache HTTP Server',
                            'process': comm or 'apache2',
                            'pids': [pid],
                            'is_running': True,
                            'category': 'web',
                            'icon': '🪶',
                            'default_port': 80
                        }
                    else:
                        detected['apache']['pids'].append(pid)

                # Detectar Nessus
                elif 'nessusd' in comm or 'nessus-service' in comm or 'nessus' in cmdline:
                    if 'nessus' not in detected:
                        detected['nessus'] = {
                            'name': 'Tenable Nessus Scanner',
                            'process': comm or 'nessusd',
                            'pids': [pid],
                            'is_running': True,
                            'category': 'security',
                            'icon': '🛡️',
                            'default_port': 8834
                        }
                    else:
                        detected['nessus']['pids'].append(pid)

                # Detectar Nginx
                elif comm == 'nginx' or 'nginx' in cmdline:
                    if 'nginx' not in detected:
                        detected['nginx'] = {
                            'name': 'Nginx Web Server',
                            'process': 'nginx',
                            'pids': [pid],
                            'is_running': True,
                            'category': 'web',
                            'icon': '🌐',
                            'default_port': 80
                        }

                # Detectar MySQL / MariaDB
                elif comm in ['mysqld', 'mariadbd'] or 'mysqld' in cmdline:
                    if 'mysql' not in detected:
                        detected['mysql'] = {
                            'name': 'MySQL / MariaDB',
                            'process': comm,
                            'pids': [pid],
                            'is_running': True,
                            'category': 'database',
                            'icon': '🐬',
                            'default_port': 3306
                        }

                # Detectar SSH
                elif comm == 'sshd' or 'sshd' in cmdline:
                    if 'ssh' not in detected:
                        detected['ssh'] = {
                            'name': 'OpenSSH Server',
                            'process': 'sshd',
                            'pids': [pid],
                            'is_running': True,
                            'category': 'system',
                            'icon': '🔑',
                            'default_port': 22
                        }
        except Exception:
            pass

    # Fallback psutil
    if 'apache' not in detected or 'nessus' not in detected:
        try:
            for p in psutil.process_iter(['pid', 'name']):
                pname = (p.info.get('name') or '').lower()
                pid = p.info.get('pid')
                if ('apache' in pname or 'httpd' in pname) and 'apache' not in detected:
                    detected['apache'] = {'name': 'Apache HTTP Server', 'process': pname, 'pids': [pid], 'is_running': True, 'category': 'web', 'icon': '🪶', 'default_port': 80}
                elif 'nessus' in pname and 'nessus' not in detected:
                    detected['nessus'] = {'name': 'Tenable Nessus Scanner', 'process': pname, 'pids': [pid], 'is_running': True, 'category': 'security', 'icon': '🛡️', 'default_port': 8834}
        except Exception:
            pass

    return detected


def get_system_services(doc: dict, host_ports: set) -> dict:
    """Retorna el estado detallado de los servicios clave del sistema (Apache, Nessus, etc.)."""
    host_procs = scan_host_processes()
    
    # Revisar si corren dentro de contenedores Docker
    docker_containers = doc.get("containers", []) if isinstance(doc, dict) else []
    apache_in_docker = next((c for c in docker_containers if any(k in (c.get("name", "") + " " + c.get("image", "")).lower() for k in ["apache", "httpd"])), None)
    nessus_in_docker = next((c for c in docker_containers if "nessus" in (c.get("name", "") + " " + c.get("image", "")).lower()), None)
    
    # 1. Apache HTTP Server
    apache_installed = check_host_service_installed("apache") or bool(apache_in_docker)
    apache_proc = host_procs.get("apache")
    apache_port_active = 80 in host_ports or 443 in host_ports or 8080 in host_ports
    apache_docker_running = bool(apache_in_docker and apache_in_docker.get("status", "").lower() == "running")
    
    apache_running = bool(apache_proc) or apache_port_active or apache_docker_running
    apache_active_port = 80 if 80 in host_ports else (443 if 443 in host_ports else (8080 if 8080 in host_ports else 80))
    
    if apache_running:
        apache_status = "RUNNING"
        apache_color = "emerald"
        apache_source = "docker" if apache_docker_running else "host"
        apache_desc = f"Activo en puerto {apache_active_port} ({'Docker' if apache_docker_running else 'Ubuntu Service'})"
    elif apache_installed:
        apache_status = "STOPPED"
        apache_color = "rose"
        apache_source = "host"
        apache_desc = "Instalado en Ubuntu Server (Servicio detenido)"
    else:
        apache_status = "OFFLINE"
        apache_color = "slate"
        apache_source = "host"
        apache_desc = "Puerto 80/443 no detectado / Inactivo"

    # 2. Tenable Nessus Scanner
    nessus_installed = check_host_service_installed("nessus") or bool(nessus_in_docker)
    nessus_proc = host_procs.get("nessus")
    nessus_port_active = 8834 in host_ports
    nessus_docker_running = bool(nessus_in_docker and nessus_in_docker.get("status", "").lower() == "running")
    
    nessus_running = bool(nessus_proc) or nessus_port_active or nessus_docker_running
    nessus_active_port = 8834
    
    if nessus_running:
        nessus_status = "RUNNING"
        nessus_color = "emerald"
        nessus_source = "docker" if nessus_docker_running else "host"
        nessus_desc = f"Activo en puerto 8834 HTTPS ({'Docker' if nessus_docker_running else 'Ubuntu Service'})"
    elif nessus_installed:
        nessus_status = "STOPPED"
        nessus_color = "rose"
        nessus_source = "host"
        nessus_desc = "Nessus instalado en Ubuntu (Servicio nessusd detenido)"
    else:
        nessus_status = "OFFLINE"
        nessus_color = "slate"
        nessus_source = "host"
        nessus_desc = "Puerto 8834 cerrado / Inactivo"

    return {
        "apache": {
            "name": "Apache HTTP Server",
            "icon": "🪶",
            "category": "web",
            "status": apache_status,
            "color": apache_color,
            "running": apache_running,
            "installed": apache_installed,
            "port": apache_active_port,
            "protocol": "http",
            "source": apache_source,
            "description": apache_desc,
            "pids": apache_proc.get("pids", []) if apache_proc else []
        },
        "nessus": {
            "name": "Tenable Nessus Scanner",
            "icon": "🛡️",
            "category": "security",
            "status": nessus_status,
            "color": nessus_color,
            "running": nessus_running,
            "installed": nessus_installed,
            "port": nessus_active_port,
            "protocol": "https",
            "source": nessus_source,
            "description": nessus_desc,
            "pids": nessus_proc.get("pids", []) if nessus_proc else []
        }
    }


def scan_host_listening_services() -> list:
    """Escanea automáticamente los puertos TCP en escucha en el servidor (Apache, Nessus y cualquier puerto nuevo)."""
    discovered = []
    seen_ports = set()
    
    # 1. Escaneo vía psutil (si tiene permisos)
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
                category = known[1] if known else "web"
                icon = known[2] if known else "🌐"

                is_web = port in [80, 443, 3000, 5000, 8000, 8080, 8090, 8443, 8834, 8888, 9000, 9443] or category in ["web", "monitoring", "security"]

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

    # 2. Escaneo complementario vía /proc/net/tcp del host (detecta Apache, Nessus o sitios nuevos sin restricciones)
    try:
        host_ports = parse_proc_net_tcp_ports()
        for port in sorted(host_ports):
            if port not in seen_ports:
                seen_ports.add(port)
                known = KNOWN_PORT_SERVICES.get(port)
                if known:
                    desc, cat, ico = known[0], known[1], known[2]
                else:
                    desc = f"Servicio Web / Puerto {port}"
                    cat = "web"
                    ico = "🌐"

                discovered.append({
                    "port": port,
                    "bind_ip": "0.0.0.0",
                    "protocol": "TCP",
                    "pid": None,
                    "process": "Host Service",
                    "description": desc,
                    "category": cat,
                    "icon": ico,
                    "is_web": True,
                    "link_port": port
                })
    except Exception:
        pass

    discovered.sort(key=lambda x: x["port"])
    return discovered


_last_io_time = None
_last_disk_io = None
_last_net_io = None

def get_io_rates() -> tuple:
    """Calcula tasas de transferencia en tiempo real para disco y red (KB/s)."""
    global _last_io_time, _last_disk_io, _last_net_io
    now = time.time()
    disk_rates = {"read_kbps": 0.0, "write_kbps": 0.0, "read_mb": 0.0, "write_mb": 0.0}
    net_rates = {"in_kbps": 0.0, "out_kbps": 0.0, "in_mb": 0.0, "out_mb": 0.0}

    try:
        curr_disk = psutil.disk_io_counters()
        curr_net = psutil.net_io_counters()

        if curr_disk:
            disk_rates["read_mb"] = round(curr_disk.read_bytes / (1024 * 1024), 1)
            disk_rates["write_mb"] = round(curr_disk.write_bytes / (1024 * 1024), 1)

        if curr_net:
            net_rates["in_mb"] = round(curr_net.bytes_recv / (1024 * 1024), 1)
            net_rates["out_mb"] = round(curr_net.bytes_sent / (1024 * 1024), 1)

        if _last_io_time is not None:
            dt = max(0.5, now - _last_io_time)
            if curr_disk and _last_disk_io:
                disk_rates["read_kbps"] = round(max(0, curr_disk.read_bytes - _last_disk_io.read_bytes) / (1024 * dt), 1)
                disk_rates["write_kbps"] = round(max(0, curr_disk.write_bytes - _last_disk_io.write_bytes) / (1024 * dt), 1)
            if curr_net and _last_net_io:
                net_rates["in_kbps"] = round(max(0, curr_net.bytes_recv - _last_net_io.bytes_recv) / (1024 * dt), 1)
                net_rates["out_kbps"] = round(max(0, curr_net.bytes_sent - _last_net_io.bytes_sent) / (1024 * dt), 1)

        _last_io_time = now
        _last_disk_io = curr_disk
        _last_net_io = curr_net
    except Exception:
        pass

    return disk_rates, net_rates


def get_system_metrics() -> dict:
    """Recolecta las métricas de rendimiento del host en tiempo real con máxima tolerancia a fallos."""
    # CPU usage general y por núcleo
    try:
        cpu_percent = float(psutil.cpu_percent(interval=None))
    except Exception:
        cpu_percent = 0.0

    try:
        cpu_cores = psutil.cpu_percent(interval=None, percpu=True)
        if not cpu_cores:
            cpu_cores = [cpu_percent]
    except Exception:
        cpu_cores = [cpu_percent]

    try:
        cpu_count = psutil.cpu_count(logical=True) or len(cpu_cores) or 1
    except Exception:
        cpu_count = len(cpu_cores) or 1

    freq_current = 0
    try:
        cf = psutil.cpu_freq()
        if cf and hasattr(cf, 'current') and cf.current:
            freq_current = round(cf.current, 0)
    except Exception:
        freq_current = 0

    # Memory usage detallado
    try:
        vm = psutil.virtual_memory()
        mem_total_gb = round(vm.total / (1024 ** 3), 2)
        mem_used_gb = round(vm.used / (1024 ** 3), 2)
        mem_available_gb = round(vm.available / (1024 ** 3), 2)
        cached_bytes = getattr(vm, 'cached', 0) or getattr(vm, 'buffers', 0) or 0
        mem_cached_mb = round(cached_bytes / (1024 * 1024), 1)
        mem_free_mb = round(vm.free / (1024 * 1024), 1)
        mem_used_mb = round(vm.used / (1024 * 1024), 1)
        mem_percent = float(vm.percent)
    except Exception:
        mem_total_gb, mem_used_gb, mem_available_gb = 0.0, 0.0, 0.0
        mem_cached_mb, mem_free_mb, mem_used_mb, mem_percent = 0.0, 0.0, 0.0, 0.0

    # Disk usage (check /host if mounted inside docker container, otherwise root / or windows drive)
    disk_path = '/'
    if os.path.exists('/host') and os.path.isdir('/host'):
        disk_path = '/host'
    elif os.name == 'nt':
        disk_path = os.path.splitdrive(os.getcwd())[0] + '\\'

    try:
        disk = psutil.disk_usage(disk_path)
        disk_total_gb = round(disk.total / (1024 ** 3), 2)
        disk_used_gb = round(disk.used / (1024 ** 3), 2)
        disk_free_gb = round(disk.free / (1024 ** 3), 2)
        disk_percent = float(disk.percent)
    except Exception:
        disk_total_gb, disk_used_gb, disk_free_gb, disk_percent = 0.0, 0.0, 0.0, 0.0

    # Load average (Linux/Unix)
    load_avg = [0.0, 0.0, 0.0]
    if hasattr(psutil, "getloadavg"):
        try:
            load_avg = [round(float(x), 2) for x in psutil.getloadavg()]
        except Exception:
            load_avg = [0.0, 0.0, 0.0]

    # Tasas de I/O de disco y tráfico de red
    try:
        disk_io, net_io = get_io_rates()
    except Exception:
        disk_io = {"read_kbps": 0.0, "write_kbps": 0.0}
        net_io = {"in_kbps": 0.0, "out_kbps": 0.0}

    # Uptime
    uptime_seconds = 0
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = max(0, time.time() - boot_time)
    except Exception:
        uptime_seconds = 0

    return {
        "hostname": get_host_name(),
        "os": get_detailed_os(),
        "kernel": f"{platform.system()} {platform.release()}",
        "uptime": format_uptime(uptime_seconds),
        "uptime_seconds": int(uptime_seconds),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu": {
            "percent": cpu_percent,
            "cores": cpu_count,
            "cores_percent": cpu_cores,
            "freq_mhz": freq_current,
            "load_avg": load_avg
        },
        "memory": {
            "total_gb": mem_total_gb,
            "used_gb": mem_used_gb,
            "available_gb": mem_available_gb,
            "used_mb": mem_used_mb,
            "cached_mb": mem_cached_mb,
            "free_mb": mem_free_mb,
            "percent": mem_percent
        },
        "disk": {
            "path": disk_path,
            "total_gb": disk_total_gb,
            "used_gb": disk_used_gb,
            "free_gb": disk_free_gb,
            "percent": disk_percent,
            "io": disk_io
        },
        "network": {
            "io": net_io
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
            "id": "wz01a2b3c4d5",
            "name": "single-node-wazuh.dashboard-1",
            "image": "wazuh/wazuh-dashboard:4.9.0",
            "status": "running",
            "state": "running",
            "health": "healthy",
            "created": "2026-09-10T08:00:00Z",
            "ports": [
                {"internal": "5601", "external": "8443", "protocol": "tcp", "display": "8443:5601/tcp", "link_port": "8443"}
            ],
            "cpu_percent": round(random.uniform(1.1, 3.2), 1),
            "memory": {"used_mb": 486.2, "limit_mb": 2048.0, "percent": 23.7}
        },
        {
            "id": "gl02b3c4d5e6",
            "name": "graylog-graylog-1",
            "image": "graylog/graylog:6.0",
            "status": "running",
            "state": "running",
            "health": "unhealthy",
            "created": "2026-09-10T08:15:00Z",
            "ports": [
                {"internal": "9000", "external": "9000", "protocol": "tcp", "display": "9000:9000/tcp", "link_port": "9000"}
            ],
            "cpu_percent": round(random.uniform(2.4, 5.8), 1),
            "memory": {"used_mb": 1120.4, "limit_mb": 4096.0, "percent": 27.3}
        },
        {
            "id": "ol03c4d5e6f7",
            "name": "ollama-llm-service",
            "image": "ollama/ollama:latest",
            "status": "running",
            "state": "running",
            "health": "healthy",
            "created": "2026-09-10T09:00:00Z",
            "ports": [
                {"internal": "11434", "external": "11434", "protocol": "tcp", "display": "11434:11434/tcp", "link_port": "11434"}
            ],
            "cpu_percent": round(random.uniform(0.5, 2.0), 1),
            "memory": {"used_mb": 780.0, "limit_mb": 8192.0, "percent": 9.5}
        },
        {
            "id": "ui04d5e6f7a1",
            "name": "open-webui",
            "image": "ghcr.io/open-webui/open-webui:main",
            "status": "running",
            "state": "running",
            "health": "healthy",
            "created": "2026-09-10T09:05:00Z",
            "ports": [
                {"internal": "8080", "external": "3000", "protocol": "tcp", "display": "3000:8080/tcp", "link_port": "3000"}
            ],
            "cpu_percent": round(random.uniform(0.6, 1.8), 1),
            "memory": {"used_mb": 265.8, "limit_mb": 2048.0, "percent": 12.9}
        },
        {
            "id": "n805e6f7a1b2",
            "name": "n8n-nexotech",
            "image": "n8nio/n8n:latest",
            "status": "running",
            "state": "running",
            "health": "healthy",
            "created": "2026-09-10T09:10:00Z",
            "ports": [
                {"internal": "5678", "external": "5678", "protocol": "tcp", "display": "5678:5678/tcp", "link_port": "5678"}
            ],
            "cpu_percent": round(random.uniform(0.8, 2.3), 1),
            "memory": {"used_mb": 340.5, "limit_mb": 2048.0, "percent": 16.6}
        },
        {
            "id": "pg06f7a1b2c3",
            "name": "postgres-db",
            "image": "postgres:16-alpine",
            "status": "running",
            "state": "running",
            "health": "healthy",
            "created": "2026-09-10T07:30:00Z",
            "ports": [
                {"internal": "5432", "external": "5432", "protocol": "tcp", "display": "5432:5432/tcp", "link_port": "5432"}
            ],
            "cpu_percent": round(random.uniform(0.4, 1.2), 1),
            "memory": {"used_mb": 145.0, "limit_mb": 4096.0, "percent": 3.5}
        },
        {
            "id": "os07a1b2c3d4",
            "name": "osiris-portal",
            "image": "nexotech/osiris:latest",
            "status": "running",
            "state": "running",
            "health": "healthy",
            "created": "2026-09-11T12:00:00Z",
            "ports": [
                {"internal": "80", "external": "8080", "protocol": "tcp", "display": "8080:80/tcp", "link_port": "8080"}
            ],
            "cpu_percent": round(random.uniform(0.3, 1.4), 1),
            "memory": {"used_mb": 88.0, "limit_mb": 1024.0, "percent": 8.5}
        },
        {
            "id": "mc08b2c3d4e5",
            "name": "mcp-filesystem-server",
            "image": "node:18-slim",
            "status": "restarting",
            "state": "restarting",
            "health": None,
            "created": "2026-09-11T15:00:00Z",
            "ports": [],
            "cpu_percent": 0.0,
            "memory": {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0}
        },
        {
            "id": "db09c3d4e5f6",
            "name": "dashboard-monitor",
            "image": "dashboard-dashboard:latest",
            "status": "running",
            "state": "running",
            "health": "healthy",
            "created": "2026-09-12T00:00:00Z",
            "ports": [
                {"internal": "8090", "external": "8090", "protocol": "tcp", "display": "8090:8090/tcp", "link_port": "8090"}
            ],
            "cpu_percent": round(random.uniform(0.2, 0.9), 1),
            "memory": {"used_mb": 42.1, "limit_mb": 512.0, "percent": 8.2}
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
        try:
            status = getattr(c, 'status', 'unknown').lower()
            is_running = status == "running"
            if is_running:
                running_count += 1
                running_containers_to_stat.append(c)
            else:
                stopped_count += 1

            name = getattr(c, 'name', 'container').lstrip("/")
            attrs = getattr(c, 'attrs', {}) or {}
            
            # Obtención ultra-segura de imagen sin llamar a Docker API si no es necesario
            image_name = "unknown"
            try:
                cfg_image = attrs.get("Config", {}).get("Image")
                if cfg_image:
                    image_name = cfg_image
                elif hasattr(c, 'image') and c.image:
                    tags = getattr(c.image, 'tags', [])
                    image_name = tags[0] if tags else getattr(c.image, 'short_id', 'unknown')
            except Exception:
                image_name = attrs.get("Config", {}).get("Image") or "unknown"

            health_info = attrs.get("State", {}).get("Health", {}) if attrs else {}
            health_status = health_info.get("Status") if health_info else None
            ports = parse_ports(attrs)

            containers_data.append({
                "id": getattr(c, 'short_id', name),
                "full_id": getattr(c, 'id', name),
                "name": name,
                "image": image_name,
                "status": getattr(c, 'status', 'unknown'),
                "state": attrs.get("State", {}).get("Status", getattr(c, 'status', 'unknown')),
                "health": health_status,
                "created": attrs.get("Created", ""),
                "ports": ports,
                "service_info": categorize_service(image_name, name),
                "cpu_percent": 0.0,
                "memory": {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0}
            })
        except Exception:
            continue

    # Consulta concurrente de estadísticas con timeout protegido (0.8s) y caché en caliente
    stats_map = {}
    if running_containers_to_stat:
        try:
            with ThreadPoolExecutor(max_workers=min(16, len(running_containers_to_stat))) as executor:
                future_to_id = {
                    executor.submit(fetch_container_stats, c): getattr(c, 'short_id', getattr(c, 'name', 'unknown'))
                    for c in running_containers_to_stat
                }
                try:
                    for future in as_completed(future_to_id, timeout=0.8):
                        cid = future_to_id[future]
                        try:
                            res = future.result()
                            stats_map[cid] = res
                            _container_stats_cache[cid] = res
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

    # Integrar estadísticas obtenidas con fallback instantáneo a caché (sin parpadeos ni delay)
    for c_info in containers_data:
        cid = c_info["id"]
        if cid in stats_map:
            c_info["cpu_percent"] = stats_map[cid].get("cpu_percent", 0.0)
            c_info["memory"] = stats_map[cid].get("memory", {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0})
        elif cid in _container_stats_cache:
            c_info["cpu_percent"] = _container_stats_cache[cid].get("cpu_percent", 0.0)
            c_info["memory"] = _container_stats_cache[cid].get("memory", {"used_mb": 0.0, "limit_mb": 0.0, "percent": 0.0})

    # Ordenar: primero los activos, luego alfabéticamente
    containers_data.sort(key=lambda x: (x["status"].lower() != "running", x["name"].lower()))

    return {
        "available": True,
        "is_demo": False,
        "error": None,
        "total": len(containers_data),
        "running": running_count,
        "stopped": stopped_count,
        "containers": containers_data
    }


def compute_alerts(system: dict, docker: dict) -> dict:
    """Calcula alertas operacionales críticas y advertencias en base al estado del host y contenedores."""
    alerts = []
    
    # 1. Alertas de CPU del Host
    cpu_pct = system.get("cpu", {}).get("percent", 0)
    if cpu_pct >= 90:
        alerts.append({
            "id": "alert-cpu-crit",
            "level": "critical",
            "source": "Host CPU",
            "title": "Uso Crítico de CPU",
            "message": f"El uso global de CPU alcanzó el {cpu_pct:.1f}%. Posible sobrecarga de procesos.",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })
    elif cpu_pct >= 75:
        alerts.append({
            "id": "alert-cpu-warn",
            "level": "warning",
            "source": "Host CPU",
            "title": "Uso Elevado de CPU",
            "message": f"El uso de CPU está en {cpu_pct:.1f}%.",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })

    # 2. Alertas de Memoria RAM
    mem_pct = system.get("memory", {}).get("percent", 0)
    if mem_pct >= 90:
        alerts.append({
            "id": "alert-mem-crit",
            "level": "critical",
            "source": "Host Memoria",
            "title": "Memoria RAM Crítica",
            "message": f"La memoria RAM ocupada está al {mem_pct:.1f}%. Riesgo de activación de OOM-killer.",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })
    elif mem_pct >= 80:
        alerts.append({
            "id": "alert-mem-warn",
            "level": "warning",
            "source": "Host Memoria",
            "title": "Memoria RAM Elevada",
            "message": f"La memoria RAM ocupada está al {mem_pct:.1f}%.",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })

    # 3. Alertas de Almacenamiento
    disk_pct = system.get("disk", {}).get("percent", 0)
    if disk_pct >= 90:
        alerts.append({
            "id": "alert-disk-crit",
            "level": "critical",
            "source": "Almacenamiento",
            "title": "Disco Casi Lleno",
            "message": f"Espacio en disco ocupado al {disk_pct:.1f}%. Libere espacio inmediatamente.",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })
    elif disk_pct >= 80:
        alerts.append({
            "id": "alert-disk-warn",
            "level": "warning",
            "source": "Almacenamiento",
            "title": "Espacio en Disco Limitado",
            "message": f"Espacio en disco ocupado al {disk_pct:.1f}%.",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })

    # 4. Alertas de Carga del Sistema (Load Average)
    cores = system.get("cpu", {}).get("cores", 1) or 1
    load_1m = (system.get("cpu", {}).get("load_avg") or [0])[0]
    if load_1m > (cores * 2.0):
        alerts.append({
            "id": "alert-load-crit",
            "level": "critical",
            "source": "Host Load",
            "title": "Sobrecarga Severa del Sistema",
            "message": f"Load avg 1min ({load_1m:.2f}) supera el 200% de la capacidad de núcleos ({cores}).",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })
    elif load_1m > (cores * 1.2):
        alerts.append({
            "id": "alert-load-warn",
            "level": "warning",
            "source": "Host Load",
            "title": "Carga de Sistema Elevada",
            "message": f"Load avg 1min ({load_1m:.2f}) excede los núcleos físicos disponibles ({cores}).",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
        })

    # 5. Alertas de Contenedores Docker
    for c in docker.get("containers", []):
        c_name = c.get("name", "Contenedor")
        c_status = (c.get("status") or "").lower()
        c_health = (c.get("health") or "").lower()
        cat = (c.get("service_info") or {}).get("category", "")

        if c_health == "unhealthy":
            alerts.append({
                "id": f"alert-{c.get('id', c_name)}-unhealthy",
                "level": "critical",
                "source": "Docker Container",
                "title": f"Salud Comprometida: {c_name}",
                "message": f"El healthcheck de '{c_name}' falló repetidamente (UNHEALTHY). Requiere verificación.",
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
            })

        if c_status == "restarting":
            alerts.append({
                "id": f"alert-{c.get('id', c_name)}-restart",
                "level": "warning",
                "source": "Docker Container",
                "title": f"Bucle de Reinicio: {c_name}",
                "message": f"El contenedor '{c_name}' está en un ciclo inestable de reinicios continuos.",
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
            })
        elif c_status in ["dead", "exited"] and cat in ["security", "database", "ai", "logging"]:
            alerts.append({
                "id": f"alert-{c.get('id', c_name)}-stopped",
                "level": "warning",
                "source": "Docker Container",
                "title": f"Servicio Esencial Detenido: {c_name}",
                "message": f"El servicio crítico '{c_name}' ({cat.upper()}) está detenido.",
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")
            })

    critical_count = sum(1 for a in alerts if a["level"] == "critical")
    warning_count = sum(1 for a in alerts if a["level"] == "warning")

    return {
        "critical_count": critical_count,
        "warning_count": warning_count,
        "total_count": len(alerts),
        "items": alerts
    }


def get_full_metrics() -> dict:
    """Retorna el paquete consolidado de métricas de host, Docker y servicios autodetectados con tolerancia a fallos."""
    try:
        sys = get_system_metrics()
    except Exception as e:
        sys = {
            "hostname": get_host_name(),
            "os": get_detailed_os(),
            "kernel": f"{platform.system()} {platform.release()}",
            "uptime": "0m",
            "uptime_seconds": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu": {"percent": 0.0, "cores": 1, "cores_percent": [0.0], "freq_mhz": 0, "load_avg": [0.0, 0.0, 0.0]},
            "memory": {"total_gb": 0.0, "used_gb": 0.0, "available_gb": 0.0, "used_mb": 0.0, "cached_mb": 0.0, "free_mb": 0.0, "percent": 0.0},
            "disk": {"path": "/", "total_gb": 0.0, "used_gb": 0.0, "free_gb": 0.0, "percent": 0.0, "io": {"read_kbps": 0.0, "write_kbps": 0.0}},
            "network": {"io": {"in_kbps": 0.0, "out_kbps": 0.0}}
        }

    try:
        doc = get_docker_metrics()
    except Exception as e:
        demo_containers = get_demo_containers()
        doc = {
            "available": False,
            "is_demo": True,
            "error": str(e),
            "total": len(demo_containers),
            "running": len(demo_containers),
            "stopped": 0,
            "containers": demo_containers
        }

    try:
        host_ports = parse_proc_net_tcp_ports()
    except Exception:
        host_ports = set()

    try:
        host_services = scan_host_listening_services()
    except Exception:
        host_services = []

    try:
        system_services = get_system_services(doc, host_ports)
    except Exception:
        system_services = {}

    try:
        alerts = compute_alerts(sys, doc)
    except Exception:
        alerts = {"critical_count": 0, "warning_count": 0, "total_count": 0, "items": []}

    # Consolidar escaneo de servicios web detectados (tanto de Docker como de Host)
    discovered_services = []
    seen_web_ports = set()

    try:
        # 1. Servicios descubiertos a partir de contenedores Docker en ejecución
        for c in doc.get("containers", []):
            if c.get("status", "").lower() == "running":
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
                                "protocol": "http",
                                "status": "running"
                            })
                        except Exception:
                            pass

        # 2. Servicios nativos del Host notables o con puerto web que no estén ya cubiertos por Docker
        for h in host_services:
            if h["port"] not in seen_web_ports and (h.get("is_web") or h["port"] in KNOWN_PORT_SERVICES):
                seen_web_ports.add(h["port"])
                discovered_services.append({
                    "name": h["process"] if h.get("process") not in ["System", "Desconocido"] else h.get("description", "Servicio"),
                    "source": "host",
                    "port": h["port"],
                    "display_port": f"{h['port']}/tcp",
                    "category": h.get("category", "general"),
                    "category_label": "Servicio Host",
                    "icon": h.get("icon", "🔌"),
                    "link_port": h.get("link_port"),
                    "protocol": "https" if h["port"] in [443, 8443, 8834, 9443] else "http",
                    "status": "listening"
                })

        # 3. Asegurar que Apache y Nessus estén representados en discovered_services si están activos
        if system_services.get("apache", {}).get("running") and 80 not in seen_web_ports and 443 not in seen_web_ports:
            ap = system_services["apache"]
            discovered_services.append({
                "name": ap["name"],
                "source": ap["source"],
                "port": ap["port"],
                "display_port": f"{ap['port']}/tcp",
                "category": "web",
                "category_label": "Servidor Web",
                "icon": "🪶",
                "link_port": ap["port"],
                "protocol": "http",
                "status": "running"
            })
            seen_web_ports.add(ap["port"])

        if system_services.get("nessus", {}).get("running") and 8834 not in seen_web_ports:
            ns = system_services["nessus"]
            discovered_services.append({
                "name": ns["name"],
                "source": ns["source"],
                "port": 8834,
                "display_port": "8834/tcp",
                "category": "security",
                "category_label": "Escáner Vulnerabilidades",
                "icon": "🛡️",
                "link_port": 8834,
                "protocol": "https",
                "status": "running"
            })
            seen_web_ports.add(8834)

        # Ordenar servicios por número de puerto
        discovered_services.sort(key=lambda s: s["port"])
    except Exception:
        pass

    return {
        "system": sys,
        "docker": doc,
        "system_services": system_services,
        "host_services": host_services,
        "discovered_services": discovered_services,
        "alerts": alerts
    }


def container_action(container_id: str, action: str) -> dict:
    """Ejecuta start, stop o restart sobre un contenedor Docker de forma segura."""
    client = get_docker_client()
    if not client:
        try:
            client = docker.from_env(timeout=3)
            client.ping()
            global _docker_client
            _docker_client = client
        except Exception:
            return {"status": "error", "message": "Docker daemon no accesible o permisos insuficientes en docker.sock."}

    try:
        container = client.containers.get(container_id)
        name = getattr(container, 'name', container_id)

        if action == "start":
            container.start()
            return {"status": "ok", "action": "start", "container": name, "message": f"Contenedor '{name}' iniciado exitosamente."}
        elif action == "stop":
            container.stop(timeout=10)
            return {"status": "ok", "action": "stop", "container": name, "message": f"Contenedor '{name}' detenido correctamente."}
        elif action == "restart":
            container.restart(timeout=10)
            return {"status": "ok", "action": "restart", "container": name, "message": f"Contenedor '{name}' reiniciado correctamente."}
        else:
            return {"status": "error", "message": f"Acción '{action}' inválida. Use start, stop o restart."}
    except docker.errors.NotFound:
        return {"status": "error", "message": f"Contenedor '{container_id}' no encontrado en Docker."}
    except docker.errors.APIError as e:
        return {"status": "error", "message": f"Error de Docker: {getattr(e, 'explanation', str(e))}"}
    except Exception as e:
        return {"status": "error", "message": f"Error al ejecutar '{action}': {str(e)}"}
