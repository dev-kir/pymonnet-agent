#!/usr/bin/env python3
import psutil, docker, json, requests, socket, time, subprocess, os

# =============== CONFIGURATION ===============
INTERVAL = int(os.getenv("INTERVAL", 3))       # seconds between reports
CPU_THRESHOLD = int(os.getenv("CPU_THRESHOLD", 85))
MEM_THRESHOLD = int(os.getenv("MEM_THRESHOLD", 80))
NET_IFACE = os.getenv("NET_IFACE")  # can be passed via environment variable
# =============================================

psutil.PROCFS_PATH = "/host/proc"   # access host /proc for real node metrics
docker_client = docker.from_env()
node_name = socket.gethostname()

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
    return "eth0"  # fallback
# ---------------------------------------------------------------

if not NET_IFACE:
    NET_IFACE = detect_active_interface()
else:
    print(f"🌐 Using specified interface: {NET_IFACE}")


# ---------------- Leader Detection ----------------
def get_leader_ip():
    """Detect the current Swarm leader's hostname and resolve to IP."""
    try:
        result = subprocess.check_output(
            ["docker", "node", "ls", "--format", "{{.Hostname}} {{.ManagerStatus}}"]
        ).decode()
        for line in result.splitlines():
            if "Leader" in line:
                leader_hostname = line.split()[0]
                try:
                    leader_ip = socket.gethostbyname(leader_hostname)
                    return leader_ip
                except socket.gaierror:
                    print(f"⚠️ Cannot resolve leader hostname '{leader_hostname}' to IP.")
                    return None
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Failed to detect leader via docker: {e}")
    return None
# ---------------------------------------------------


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
            net_in = (rx - prev_rx) * 8 / (INTERVAL * 1024 * 1024)   # Mbps
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


def calc_cpu_percent(stats):
    cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                stats["precpu_stats"]["cpu_usage"]["total_usage"]
    system_delta = stats["cpu_stats"].get("system_cpu_usage", 0) - \
                   stats["precpu_stats"].get("system_cpu_usage", 0)
    if cpu_delta > 0 and system_delta > 0:
        cores = len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [])) or 1
        return round((cpu_delta / system_delta) * 100 * cores, 2)
    return 0.0


def calc_mem_percent(stats):
    used = stats["memory_stats"]["usage"] - stats["memory_stats"]["stats"].get("cache", 0)
    limit = stats["memory_stats"].get("limit", 1)
    return round((used / limit) * 100, 2)


def calc_net_mbps(stats, interval=INTERVAL):
    """Estimate per-container network throughput in Mbps."""
    total_rx = total_tx = 0
    nets = stats.get("networks", {})
    for iface in nets.values():
        total_rx += iface.get("rx_bytes", 0)
        total_tx += iface.get("tx_bytes", 0)
    return total_rx * 8 / (interval * 1024 * 1024), total_tx * 8 / (interval * 1024 * 1024)


def get_top_containers(limit=3):
    """Return top containers by CPU usage (and include memory + traffic)."""
    containers = []
    for c in docker_client.containers.list():
        try:
            stats = c.stats(stream=False)
            cpu = calc_cpu_percent(stats)
            mem = calc_mem_percent(stats)
            net_in, net_out = calc_net_mbps(stats)
            containers.append({
                "name": c.name,
                "cpu": cpu,
                "mem": mem,
                "net_in": round(net_in, 2),
                "net_out": round(net_out, 2)
            })
        except Exception:
            continue
    containers.sort(key=lambda x: x["cpu"], reverse=True)
    return containers[:limit]
# ---------------------------------------------------


# ---------------- Main Loop ----------------
leader_ip = None
while True:
    try:
        # auto-detect leader if not known or unreachable
        if not leader_ip:
            leader_ip = get_leader_ip()
            if leader_ip:
                print(f"🧭 Detected leader at {leader_ip}")
            else:
                print("❌ No leader detected. Retrying...")
                time.sleep(5)
                continue

        manager_url = f"http://{leader_ip}:6969/metrics"
        node_metrics = get_node_metrics()
        data = {"node": node_name, **node_metrics}

        # determine status
        if (node_metrics["cpu"] > CPU_THRESHOLD or node_metrics["mem"] > MEM_THRESHOLD):
            data["status"] = "high_load"
            data["top_containers"] = get_top_containers()
        else:
            data["status"] = "normal"

        # send metrics
        resp = requests.post(manager_url, json=data, timeout=5)
        if resp.status_code != 200:
            print(f"⚠️ Manager responded {resp.status_code}: {resp.text}")
            if resp.status_code in (403, 502):
                print("🔄 Possible leader change. Clearing leader cache.")
                leader_ip = None
        else:
            print(f"[{time.strftime('%X')}] sent → {leader_ip}: {data}")

    except Exception as e:
        print(f"[{time.strftime('%X')}] error: {e}")
        leader_ip = None  # force rediscovery next loop

    time.sleep(INTERVAL)
# ---------------------------------------------------
