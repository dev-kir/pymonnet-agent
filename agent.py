#!/usr/bin/env python3
import psutil, docker, json, requests, socket, time, subprocess, os

# =============== CONFIGURATION ===============
INTERVAL = int(os.getenv("INTERVAL", 3))       # seconds between reports
CPU_THRESHOLD = int(os.getenv("CPU_THRESHOLD", 85))
MEM_THRESHOLD = int(os.getenv("MEM_THRESHOLD", 80))
NET_IFACE = os.getenv("NET_IFACE")  # can be passed via environment variable
MANAGER_URL = "http://pymonnet-server:6969/metrics"
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

# ---------------- Metrics Collection ----------------
def get_node_metrics():
    """Collect CPU, memory, and network traffic (Mbps)."""
    global prev_rx, prev_tx, prev_ts, NET_IFACE
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent

    net_all = psutil.net_io_counters(pernic=True)
    net = net_all.get(NET_IFACE)

    if net is None:
        fallback = detect_active_interface()
        if fallback and fallback != NET_IFACE:
            print(f"🔁 Switching network interface to: {fallback}")
            NET_IFACE = fallback
            net = net_all.get(NET_IFACE)
            prev_rx = prev_tx = prev_ts = None

    if net:
        rx, tx = net.bytes_recv, net.bytes_sent
        now = time.time()
        if prev_rx is None or prev_tx is None or prev_ts is None:
            net_in = net_out = 0.0
        else:
            elapsed = max(now - prev_ts, 1e-3)
            diff_rx = rx - prev_rx
            diff_tx = tx - prev_tx
            if diff_rx < 0 or diff_tx < 0:
                # interface counters reset; skip this interval
                diff_rx = diff_tx = 0
            net_in = (diff_rx * 8) / (elapsed * 1024 * 1024)
            net_out = (diff_tx * 8) / (elapsed * 1024 * 1024)
        prev_rx, prev_tx, prev_ts = rx, tx, now
    else:
        net_in = net_out = 0.0

    return {
        "cpu": round(cpu, 2),
        "mem": round(mem, 2),
        "net_in": round(max(net_in, 0.0), 4),
        "net_out": round(max(net_out, 0.0), 4)
    }

# ---------------- Main Loop ----------------
while True:
    try:
        metrics = get_node_metrics()
        data = {
            "node": node_name,
            "role": node_role,
            **metrics,
            "status": "high_load" if (metrics["cpu"] > CPU_THRESHOLD or metrics["mem"] > MEM_THRESHOLD) else "normal"
        }

        resp = requests.post(MANAGER_URL, json=data, timeout=5)
        if resp.status_code == 200:
            print(f"[{time.strftime('%X')}] ✅ Sent → {MANAGER_URL}: {data}")
        else:
            print(f"⚠️ Manager responded {resp.status_code}: {resp.text}")

    except Exception as e:
        print(f"[{time.strftime('%X')}] error: {e}")

    time.sleep(INTERVAL)
