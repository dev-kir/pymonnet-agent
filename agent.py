#!/usr/bin/env python3
import psutil, docker, json, requests, socket, time, subprocess, os

# =============== CONFIGURATION ===============
INTERVAL = int(os.getenv("INTERVAL", 3))       # seconds between reports
CPU_THRESHOLD = int(os.getenv("CPU_THRESHOLD", 85))
MEM_THRESHOLD = int(os.getenv("MEM_THRESHOLD", 80))
NET_IFACE = os.getenv("NET_IFACE")  # can be passed via environment variable
# =============================================

psutil.PROCFS_PATH = "/host/proc"
docker_client = docker.from_env()

# Detect actual Swarm node hostname
def get_real_node_name():
    try:
        info = docker_client.info()
        return info.get("Name", socket.gethostname())
    except Exception:
        return socket.gethostname()

node_name = get_real_node_name()

prev_rx, prev_tx = 0, 0


# ---------------- Network Interface Detection ----------------
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
# ---------------------------------------------------------------

if not NET_IFACE:
    NET_IFACE = detect_active_interface()
else:
    print(f"🌐 Using specified interface: {NET_IFACE}")


# ---------------- Metrics Collection ----------------
def get_node_metrics():
    """Collect CPU, memory, and network traffic (Mbps)."""
    global prev_rx, prev_tx
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent

    net = psutil.net_io_counters(pernic=True).get(NET_IFACE)
    if net:
        rx, tx = net.bytes_recv, net.bytes_sent
        if prev_rx == 0 and prev_tx == 0:
            net_in, net_out = 0.0, 0.0
        else:
            net_in = (rx - prev_rx) * 8 / (INTERVAL * 1024 * 1024)
            net_out = (tx - prev_tx) * 8 / (INTERVAL * 1024 * 1024)
        prev_rx, prev_tx = rx, tx
    else:
        net_in = net_out = 0.0

    return {
        "cpu": round(cpu, 2),
        "mem": round(mem, 2),
        "net_in": round(net_in, 2),
        "net_out": round(net_out, 2)
    }


# ---------------- Main Loop ----------------
while True:
    try:
        manager_url = "http://pymonnet-server:6969/metrics"
        node_metrics = get_node_metrics()
        data = {"node": node_name, **node_metrics}

        if (node_metrics["cpu"] > CPU_THRESHOLD or node_metrics["mem"] > MEM_THRESHOLD):
            data["status"] = "high_load"
        else:
            data["status"] = "normal"

        resp = requests.post(manager_url, json=data, timeout=5)
        if resp.status_code == 200:
            print(f"[{time.strftime('%X')}] sent → {manager_url}: {data}")
        else:
            print(f"⚠️ Manager responded {resp.status_code}: {resp.text}")

    except Exception as e:
        print(f"[{time.strftime('%X')}] error: {e}")

    time.sleep(INTERVAL)
