#!/usr/bin/env python3
import psutil, docker, json, requests, socket, time, subprocess, os

# =============== CONFIGURATION ===============
# INTERVAL = int(os.getenv("INTERVAL", 3))       # seconds between reports
INTERVAL = int(os.getenv("INTERVAL", 0.25))       # update new interval for real time and more precise
CPU_THRESHOLD = int(os.getenv("CPU_THRESHOLD", 85))
MEM_THRESHOLD = int(os.getenv("MEM_THRESHOLD", 80))
CPU_ALERT_THRESHOLD = int(os.getenv("CPU_ALERT_THRESHOLD", 70))
MEM_ALERT_THRESHOLD = int(os.getenv("MEM_ALERT_THRESHOLD", 80))
ALERT_WINDOW = int(os.getenv("ALERT_WINDOW", 30))  # seconds to keep scanning containers
NET_IFACE = os.getenv("NET_IFACE")  # can be passed via environment variable
MANAGER_METRICS_URL = os.getenv("MANAGER_URL", "http://pymonnet-server:6969/metrics")
MANAGER_BASE_URL = os.getenv("MANAGER_BASE_URL")
if not MANAGER_BASE_URL:
    if MANAGER_METRICS_URL.endswith("/metrics"):
        MANAGER_BASE_URL = MANAGER_METRICS_URL[: -len("/metrics")]
    else:
        MANAGER_BASE_URL = MANAGER_METRICS_URL.rsplit("/", 1)[0]
MANAGER_CONTAINER_URL = f"{MANAGER_BASE_URL}/container-metrics"
# =============================================

psutil.PROCFS_PATH = "/host/proc"
docker_client = docker.from_env()

# ---------------- Node Identity ----------------
def get_node_info():
    """Detect real Swarm node name + role."""
    try:
        info = docker_client.info()
        name = info.get("Name", socket.gethostname())
        role = "manager" if info.get("Swarm", {}).get("ControlAvailable", False) else "worker"
        return name, role
    except Exception:
        return socket.gethostname(), "unknown"

node_name, node_role = get_node_info()
print(f"🖥️ Node detected → {node_name} ({node_role})")

# ---------------- Network Interface ----------------
def detect_active_interface():
    """Auto-detect the most active non-loopback interface."""
    try:
        ifaces = psutil.net_if_stats()
        for name, stats in ifaces.items():
            if stats.isup and not name.startswith("lo"):
                print(f"🧭 Auto-selected network interface: {name}")
                return name
    except Exception as e:
        print(f"⚠️ Failed to detect active interface: {e}")
    return "eth0"

if not NET_IFACE:
    NET_IFACE = detect_active_interface()
else:
    print(f"🌐 Using specified interface: {NET_IFACE}")

prev_rx, prev_tx = None, None
prev_ts = None

container_prev_net = {}
alert_active_until = 0

# ---------------- Metrics Collection ----------------
# def get_node_metrics():
#     """Collect CPU, memory, and network traffic (Mbps)."""
#     global prev_rx, prev_tx, prev_ts, NET_IFACE
#     cpu = psutil.cpu_percent(interval=1)
#     mem = psutil.virtual_memory().percent

#     net_all = psutil.net_io_counters(pernic=True)
#     net = net_all.get(NET_IFACE)

#     if net is None:
#         fallback = detect_active_interface()
#         if fallback and fallback != NET_IFACE:
#             print(f"🔁 Switching network interface to: {fallback}")
#             NET_IFACE = fallback
#             net = net_all.get(NET_IFACE)
#             prev_rx = prev_tx = prev_ts = None

#     if net:
#         rx, tx = net.bytes_recv, net.bytes_sent
#         now = time.time()
#         if prev_rx is None or prev_tx is None or prev_ts is None:
#             net_in = net_out = 0.0
#         else:
#             elapsed = max(now - prev_ts, 1e-3)
#             diff_rx = rx - prev_rx
#             diff_tx = tx - prev_tx
#             if diff_rx < 0 or diff_tx < 0:
#                 # interface counters reset; skip this interval
#                 diff_rx = diff_tx = 0
#             net_in = (diff_rx * 8) / (elapsed * 1024 * 1024)
#             net_out = (diff_tx * 8) / (elapsed * 1024 * 1024)
#         prev_rx, prev_tx, prev_ts = rx, tx, now
#     else:
#         net_in = net_out = 0.0

#     return {
#         "cpu": round(cpu, 2),
#         "mem": round(mem, 2),
#         "net_in": round(max(net_in, 0.0), 4),
#         "net_out": round(max(net_out, 0.0), 4)
#     }

def _read_sysfs_bytes(iface, direction):
    path = f"/host/sys/class/net/{iface}/statistics/{direction}_bytes"
    try:
        with open(path) as f:
            return int(f.read())
    except Exception:
        return None


def get_node_metrics():
    """Collect CPU, memory, and network traffic (Mbps)."""
    global prev_rx, prev_tx, prev_ts, NET_IFACE

    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent

    iface = NET_IFACE or "eth0"
    rx = tx = None

    try:
        net = psutil.net_io_counters(pernic=True).get(iface)
        if net:
            rx, tx = net.bytes_recv, net.bytes_sent
    except Exception as e:
        print(f"⚠️ psutil net stats failed for {iface}: {e}")

    if rx is None or tx is None:
        rx = _read_sysfs_bytes(iface, "rx")
        tx = _read_sysfs_bytes(iface, "tx")

    if rx is None or tx is None:
        print(f"⚠️ Unable to determine NIC counters for {iface}; reporting 0 Mbps")
        rx = tx = 0

    now = time.time()
    if prev_rx is None or prev_tx is None or prev_ts is None:
        net_in = net_out = 0.0
    else:
        elapsed = max(now - prev_ts, 1e-3)
        diff_rx = rx - prev_rx
        diff_tx = tx - prev_tx
        if diff_rx < 0:
            diff_rx = 0
        if diff_tx < 0:
            diff_tx = 0
        net_in = (diff_rx * 8) / (elapsed * 1024 * 1024)
        net_out = (diff_tx * 8) / (elapsed * 1024 * 1024)

    prev_rx, prev_tx, prev_ts = rx, tx, now

    return {
        "cpu": round(cpu, 2),
        "mem": round(mem, 2),
        "net_in": round(max(net_in, 0.0), 4),
        "net_out": round(max(net_out, 0.0), 4),
    }


def calculate_container_cpu(stats):
    """Compute container CPU percentage using Docker stats payload."""
    try:
        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        system_delta = stats["cpu_stats"].get("system_cpu_usage", 0) - stats["precpu_stats"].get("system_cpu_usage", 0)
        percpu = stats["cpu_stats"]["cpu_usage"].get("percpu_usage") or []
        cores = len(percpu) if percpu else 1
        if system_delta > 0 and cpu_delta >= 0:
            return round((cpu_delta / system_delta) * cores * 100.0, 2)
    except Exception:
        pass
    return 0.0


def calculate_container_memory(stats):
    """Return memory usage percentage for container."""
    try:
        usage = stats["memory_stats"].get("usage", 0)
        limit = stats["memory_stats"].get("limit", 0)
        if limit > 0:
            return round((usage / limit) * 100.0, 2)
    except Exception:
        pass
    return 0.0


# def calculate_container_network(container_id, stats, now):
#     """Compute container network throughput in Mbps using previous snapshot."""
#     networks = stats.get("networks") or {}
#     total_rx = total_tx = 0
#     for iface_stats in networks.values():
#         total_rx += iface_stats.get("rx_bytes", 0)
#         total_tx += iface_stats.get("tx_bytes", 0)

#     prev = container_prev_net.get(container_id)
#     if not prev:
#         container_prev_net[container_id] = {"rx": total_rx, "tx": total_tx, "time": now}
#         return 0.0, 0.0

#     elapsed = max(now - prev["time"], 1e-3)
#     diff_rx = total_rx - prev["rx"]
#     diff_tx = total_tx - prev["tx"]
#     if diff_rx < 0:
#         diff_rx = 0
#     if diff_tx < 0:
#         diff_tx = 0

#     container_prev_net[container_id] = {"rx": total_rx, "tx": total_tx, "time": now}

#     net_in = (diff_rx * 8) / (elapsed * 1024 * 1024)
#     net_out = (diff_tx * 8) / (elapsed * 1024 * 1024)
#     return round(max(net_in, 0.0), 3), round(max(net_out, 0.0), 3)

def calculate_container_network(container_id, stats, now):
    """Compute container network throughput in Mbps using previous snapshot, fallback to host NIC if needed."""
    networks = stats.get("networks") or {}
    total_rx = total_tx = 0
    for iface_stats in networks.values():
        total_rx += iface_stats.get("rx_bytes", 0)
        total_tx += iface_stats.get("tx_bytes", 0)

    # fallback if Docker stats network empty
    if total_rx == 0 and total_tx == 0:
        try:
            iface = os.getenv("NET_IFACE", "eth0")
            net_all = psutil.net_io_counters(pernic=True)
            net = net_all.get(iface)
            if net:
                total_rx = net.bytes_recv
                total_tx = net.bytes_sent
        except Exception as e:
            print(f"⚠️ Fallback net read failed: {e}")

    prev = container_prev_net.get(container_id)
    if not prev:
        container_prev_net[container_id] = {"rx": total_rx, "tx": total_tx, "time": now}
        return 0.0, 0.0

    elapsed = max(now - prev["time"], 1e-3)
    diff_rx = total_rx - prev["rx"]
    diff_tx = total_tx - prev["tx"]
    if diff_rx < 0:
        diff_rx = 0
    if diff_tx < 0:
        diff_tx = 0

    container_prev_net[container_id] = {"rx": total_rx, "tx": total_tx, "time": now}

    net_in = (diff_rx * 8) / (elapsed * 1024 * 1024)
    net_out = (diff_tx * 8) / (elapsed * 1024 * 1024)
    return round(max(net_in, 0.0), 3), round(max(net_out, 0.0), 3)

def monitor_containers_if_high_load():
    """Collect per-container metrics when node is under high load and push to server."""
    try:
        containers = docker_client.containers.list()
    except Exception as err:
        print(f"⚠️ Failed to list containers: {err}")
        return

    now = time.time()
    payload = []
    active_ids = set()

    for container in containers:
        try:
            stats = container.stats(stream=False)
        except Exception as err:
            print(f"⚠️ Failed to fetch stats for {container.name}: {err}")
            continue

        cpu = calculate_container_cpu(stats)
        mem = calculate_container_memory(stats)
        net_in, net_out = calculate_container_network(container.id, stats, now)
        active_ids.add(container.id)

        payload.append({
            "node": node_name,
            "role": node_role,
            "container": container.name,
            "container_id": container.short_id,
            "cpu": cpu,
            "mem": mem,
            "net_in": net_in,
            "net_out": net_out
        })

    # cleanup old containers from cache
    obsolete = set(container_prev_net.keys()) - active_ids
    for cid in obsolete:
        container_prev_net.pop(cid, None)

    if not payload:
        return

    try:
        resp = requests.post(MANAGER_CONTAINER_URL, json=payload, timeout=5)
        if resp.status_code != 200:
            print(f"⚠️ Manager container metrics response {resp.status_code}: {resp.text}")
    except Exception as err:
        print(f"⚠️ Failed to send container metrics: {err}")

# ---------------- Main Loop ----------------
while True:
    try:
        metrics = get_node_metrics()
        now_ts = time.time()
        data = {
            "node": node_name,
            "role": node_role,
            **metrics,
            "status": "high_load" if (metrics["cpu"] > CPU_THRESHOLD or metrics["mem"] > MEM_THRESHOLD) else "normal"
        }

        # high_load = metrics["cpu"] > CPU_ALERT_THRESHOLD or metrics["mem"] > MEM_ALERT_THRESHOLD
        # if high_load:
        #     alert_active_until = now_ts + ALERT_WINDOW

        # if now_ts < alert_active_until:
        #     monitor_containers_if_high_load()
        
        if metrics["cpu"] > CPU_THRESHOLD or metrics["mem"] > MEM_THRESHOLD:
            monitor_containers_if_high_load()

        resp = requests.post(MANAGER_METRICS_URL, json=data, timeout=5)
        if resp.status_code == 200:
			# print once per second (4Hz sampling = 4x per sec)
            if int(time.time() * 4) % 4 == 0:
                print(f"[{time.strftime('%X')}] ✅ Sent → {MANAGER_METRICS_URL}: {data}")
        else:
            print(f"⚠️ Manager responded {resp.status_code}: {resp.text}")

    except Exception as e:
        print(f"[{time.strftime('%X')}] error: {e}")

    time.sleep(INTERVAL)
