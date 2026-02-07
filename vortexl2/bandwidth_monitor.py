"""
VortexL2 Bandwidth & Performance Monitor

Provides live bandwidth monitoring across three network layers:
  1. L2TP layer (l2tpethX interfaces)
  2. WireGuard layer (wg_vortex interface)
  3. Application/port layer (per-port traffic via iptables accounting)

Also performs bottleneck analysis with optimization recommendations.
All data is read from kernel sources — no extra dependencies required.
"""

import os
import time
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

# Severity levels for bottleneck analysis
SEVERITY_OK = "OK"
SEVERITY_WARN = "WARN"
SEVERITY_CRIT = "CRIT"


def _run(cmd: str, timeout: int = 10) -> Tuple[bool, str, str]:
    """Execute a shell command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return False, "", str(e)


# ------------------------------------------------------------------
# Interface stats from /sys/class/net/
# ------------------------------------------------------------------

def read_interface_stats(iface: str) -> Optional[Dict]:
    """
    Read interface statistics from /sys/class/net/<iface>/statistics/.

    Returns dict with rx_bytes, tx_bytes, rx_packets, tx_packets,
    rx_errors, tx_errors, rx_dropped, tx_dropped, or None if interface
    doesn't exist.
    """
    stats_dir = Path(f"/sys/class/net/{iface}/statistics")
    if not stats_dir.exists():
        return None

    stats = {}
    for key in ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                 "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"]:
        path = stats_dir / key
        try:
            stats[key] = int(path.read_text().strip())
        except (FileNotFoundError, ValueError):
            stats[key] = 0

    return stats


def get_bandwidth(iface: str, interval: float = 1.0) -> Optional[Dict]:
    """
    Measure bandwidth on an interface by polling twice with a delay.

    Returns dict with rx_bps, tx_bps (bytes per second),
    plus the raw stats from the second reading.
    Returns None if interface doesn't exist.
    """
    stats1 = read_interface_stats(iface)
    if stats1 is None:
        return None

    time.sleep(interval)

    stats2 = read_interface_stats(iface)
    if stats2 is None:
        return None

    rx_bps = (stats2["rx_bytes"] - stats1["rx_bytes"]) / interval
    tx_bps = (stats2["tx_bytes"] - stats1["tx_bytes"]) / interval

    return {
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "rx_bytes_total": stats2["rx_bytes"],
        "tx_bytes_total": stats2["tx_bytes"],
        "rx_packets": stats2["rx_packets"],
        "tx_packets": stats2["tx_packets"],
        "rx_errors": stats2["rx_errors"],
        "tx_errors": stats2["tx_errors"],
        "rx_dropped": stats2["rx_dropped"],
        "tx_dropped": stats2["tx_dropped"],
    }


# ------------------------------------------------------------------
# Per-port traffic tracking via iptables accounting chains
# ------------------------------------------------------------------

def setup_port_accounting(ports: List[int]) -> bool:
    """
    Setup iptables accounting rules for per-port traffic tracking.
    Creates a VORTEX_MONITOR chain with rules for each port.
    Idempotent — safe to call multiple times.
    """
    # Create chain if it doesn't exist
    _run("iptables -N VORTEX_MONITOR 2>/dev/null")

    # Ensure chain is referenced from INPUT and OUTPUT
    ok, out, _ = _run("iptables -L INPUT -n")
    if ok and "VORTEX_MONITOR" not in out:
        _run("iptables -I INPUT -j VORTEX_MONITOR")
    ok, out, _ = _run("iptables -L OUTPUT -n")
    if ok and "VORTEX_MONITOR" not in out:
        _run("iptables -I OUTPUT -j VORTEX_MONITOR")
    ok, out, _ = _run("iptables -L FORWARD -n")
    if ok and "VORTEX_MONITOR" not in out:
        _run("iptables -I FORWARD -j VORTEX_MONITOR")

    # Add per-port rules (skip if already exists)
    for port in ports:
        # Incoming traffic to this port
        _run(f"iptables -C VORTEX_MONITOR -p tcp --dport {port} 2>/dev/null || "
             f"iptables -A VORTEX_MONITOR -p tcp --dport {port}")
        # Outgoing traffic from this port
        _run(f"iptables -C VORTEX_MONITOR -p tcp --sport {port} 2>/dev/null || "
             f"iptables -A VORTEX_MONITOR -p tcp --sport {port}")

    return True


def read_port_stats() -> Dict[int, Dict]:
    """
    Read per-port traffic from iptables VORTEX_MONITOR chain.

    Returns {port: {"rx_bytes": N, "tx_bytes": N, "rx_packets": N, "tx_packets": N}}
    """
    port_stats = {}

    ok, out, _ = _run("iptables -L VORTEX_MONITOR -n -v -x")
    if not ok or not out:
        return port_stats

    for line in out.split('\n'):
        parts = line.split()
        if len(parts) < 10:
            continue

        try:
            packets = int(parts[0])
            bytes_val = int(parts[1])
        except ValueError:
            continue

        # Parse dport (incoming) and sport (outgoing)
        for part in parts:
            if part.startswith("dpt:"):
                port = int(part.split(":")[1])
                if port not in port_stats:
                    port_stats[port] = {"rx_bytes": 0, "tx_bytes": 0,
                                        "rx_packets": 0, "tx_packets": 0}
                port_stats[port]["rx_bytes"] += bytes_val
                port_stats[port]["rx_packets"] += packets
            elif part.startswith("spt:"):
                port = int(part.split(":")[1])
                if port not in port_stats:
                    port_stats[port] = {"rx_bytes": 0, "tx_bytes": 0,
                                        "rx_packets": 0, "tx_packets": 0}
                port_stats[port]["tx_bytes"] += bytes_val
                port_stats[port]["tx_packets"] += packets

    return port_stats


def get_port_bandwidth(ports: List[int], interval: float = 1.0) -> Dict[int, Dict]:
    """
    Measure per-port bandwidth by reading iptables counters twice.

    Returns {port: {"rx_bps": N, "tx_bps": N, "rx_bytes_total": N, "tx_bytes_total": N}}
    """
    stats1 = read_port_stats()
    time.sleep(interval)
    stats2 = read_port_stats()

    result = {}
    for port in ports:
        s1 = stats1.get(port, {"rx_bytes": 0, "tx_bytes": 0})
        s2 = stats2.get(port, {"rx_bytes": 0, "tx_bytes": 0})
        result[port] = {
            "rx_bps": (s2["rx_bytes"] - s1["rx_bytes"]) / interval,
            "tx_bps": (s2["tx_bytes"] - s1["tx_bytes"]) / interval,
            "rx_bytes_total": s2["rx_bytes"],
            "tx_bytes_total": s2["tx_bytes"],
        }

    return result


# ------------------------------------------------------------------
# Snapshot: all layers at once
# ------------------------------------------------------------------

def get_all_layer_stats(tunnel_configs: list) -> Dict:
    """
    Get a one-shot snapshot of all layer statistics.

    Returns dict with:
      "l2tp": {iface: stats_dict, ...}
      "wireguard": stats_dict or None
      "ports": {port: stats_dict, ...}
      "timestamp": float
    """
    result = {
        "l2tp": {},
        "wireguard": None,
        "ports": {},
        "timestamp": time.time(),
    }

    # L2TP interfaces
    for config in tunnel_configs:
        iface = config.interface_name
        stats = read_interface_stats(iface)
        if stats:
            result["l2tp"][iface] = stats

    # WireGuard interface
    wg_stats = read_interface_stats("wg_vortex")
    if wg_stats:
        result["wireguard"] = wg_stats

    # Per-port stats
    result["ports"] = read_port_stats()

    return result


# ------------------------------------------------------------------
# Live monitor (returns data each tick for Rich Live to display)
# ------------------------------------------------------------------

def live_monitor_tick(tunnel_configs: list, prev_stats: Optional[Dict],
                      interval: float) -> Tuple[Dict, Dict]:
    """
    Single tick of the live monitor. Compares current stats with previous
    to compute bandwidth.

    Returns (current_stats, bandwidth_dict) where bandwidth_dict has:
      "l2tp": {iface: {"rx_bps": N, "tx_bps": N, ...}, ...}
      "wireguard": {"rx_bps": N, "tx_bps": N, ...} or None
      "ports": {port: {"rx_bps": N, "tx_bps": N, ...}, ...}
    """
    current = get_all_layer_stats(tunnel_configs)

    bandwidth = {
        "l2tp": {},
        "wireguard": None,
        "ports": {},
    }

    if prev_stats is None:
        return current, bandwidth

    elapsed = current["timestamp"] - prev_stats["timestamp"]
    if elapsed <= 0:
        elapsed = interval

    # L2TP bandwidth
    for iface, stats in current["l2tp"].items():
        prev = prev_stats.get("l2tp", {}).get(iface)
        if prev:
            bandwidth["l2tp"][iface] = {
                "rx_bps": (stats["rx_bytes"] - prev["rx_bytes"]) / elapsed,
                "tx_bps": (stats["tx_bytes"] - prev["tx_bytes"]) / elapsed,
                "rx_bytes_total": stats["rx_bytes"],
                "tx_bytes_total": stats["tx_bytes"],
                "rx_errors": stats["rx_errors"],
                "tx_errors": stats["tx_errors"],
                "rx_dropped": stats["rx_dropped"],
                "tx_dropped": stats["tx_dropped"],
            }

    # WireGuard bandwidth
    wg = current.get("wireguard")
    wg_prev = prev_stats.get("wireguard")
    if wg and wg_prev:
        bandwidth["wireguard"] = {
            "rx_bps": (wg["rx_bytes"] - wg_prev["rx_bytes"]) / elapsed,
            "tx_bps": (wg["tx_bytes"] - wg_prev["tx_bytes"]) / elapsed,
            "rx_bytes_total": wg["rx_bytes"],
            "tx_bytes_total": wg["tx_bytes"],
            "rx_errors": wg["rx_errors"],
            "tx_errors": wg["tx_errors"],
            "rx_dropped": wg["rx_dropped"],
            "tx_dropped": wg["tx_dropped"],
        }

    # Per-port bandwidth
    for port, stats in current.get("ports", {}).items():
        prev_p = prev_stats.get("ports", {}).get(port)
        if prev_p:
            bandwidth["ports"][port] = {
                "rx_bps": (stats["rx_bytes"] - prev_p["rx_bytes"]) / elapsed,
                "tx_bps": (stats["tx_bytes"] - prev_p["tx_bytes"]) / elapsed,
                "rx_bytes_total": stats["rx_bytes"],
                "tx_bytes_total": stats["tx_bytes"],
            }

    return current, bandwidth


# ------------------------------------------------------------------
# Bottleneck analysis
# ------------------------------------------------------------------

def analyze_bottleneck(tunnel_configs: list) -> List[Tuple[str, str, str]]:
    """
    Analyze system for performance bottlenecks and return recommendations.

    Returns list of (severity, finding, recommendation) tuples.
    Severity is one of: OK, WARN, CRIT
    """
    findings = []

    # --- 1. Check BBR congestion control ---
    ok, out, _ = _run("sysctl net.ipv4.tcp_congestion_control")
    if ok and "bbr" in out:
        findings.append((SEVERITY_OK, "BBR congestion control enabled", "Optimal for long-distance links"))
    else:
        findings.append((SEVERITY_WARN, "BBR not enabled",
                         "Enable via WireGuard menu (option 6) or: sysctl -w net.ipv4.tcp_congestion_control=bbr"))

    # --- 2. Check MTU settings ---
    for config in tunnel_configs:
        iface = config.interface_name
        ok, out, _ = _run(f"ip link show {iface}")
        if ok:
            import re
            mtu_match = re.search(r'mtu\s+(\d+)', out)
            if mtu_match:
                mtu = int(mtu_match.group(1))
                wg_enabled = getattr(config, 'wireguard_enabled', False)
                if wg_enabled:
                    if mtu >= 1400 and mtu <= 1500:
                        findings.append((SEVERITY_OK, f"L2TP MTU={mtu} on {iface}",
                                         "Optimal for WireGuard overlay"))
                    else:
                        findings.append((SEVERITY_WARN, f"L2TP MTU={mtu} on {iface} (expected ~1450)",
                                         "Set MTU to 1450: ip link set dev {iface} mtu 1450"))
                else:
                    findings.append((SEVERITY_OK, f"L2TP MTU={mtu} on {iface}", "Standard configuration"))

    # WireGuard MTU
    ok, out, _ = _run("ip link show wg_vortex")
    if ok:
        import re
        mtu_match = re.search(r'mtu\s+(\d+)', out)
        if mtu_match:
            wg_mtu = int(mtu_match.group(1))
            if 1300 <= wg_mtu <= 1400:
                findings.append((SEVERITY_OK, f"WireGuard MTU={wg_mtu}", "Optimal for encrypted overlay"))
            else:
                findings.append((SEVERITY_WARN, f"WireGuard MTU={wg_mtu} (expected ~1380)",
                                 "Consider: ip link set dev wg_vortex mtu 1380"))

    # --- 3. Check interface errors and drops ---
    all_ifaces = [c.interface_name for c in tunnel_configs] + ["wg_vortex"]
    for iface in all_ifaces:
        stats = read_interface_stats(iface)
        if stats is None:
            continue
        total_errors = stats["rx_errors"] + stats["tx_errors"]
        total_drops = stats["rx_dropped"] + stats["tx_dropped"]
        total_packets = stats["rx_packets"] + stats["tx_packets"]

        if total_packets == 0:
            findings.append((SEVERITY_OK, f"No traffic on {iface}", "Interface idle"))
            continue

        error_rate = total_errors / max(total_packets, 1) * 100
        drop_rate = total_drops / max(total_packets, 1) * 100

        if error_rate > 1.0:
            findings.append((SEVERITY_CRIT, f"High error rate on {iface}: {error_rate:.2f}%",
                             "Check physical link or tunnel stability"))
        elif total_errors > 0:
            findings.append((SEVERITY_WARN, f"{total_errors} errors on {iface}",
                             "Monitor for increasing errors"))
        else:
            findings.append((SEVERITY_OK, f"No errors on {iface}", "Interface healthy"))

        if drop_rate > 1.0:
            findings.append((SEVERITY_CRIT, f"High drop rate on {iface}: {drop_rate:.2f}%",
                             "Increase netdev_budget or check buffer sizes"))
        elif total_drops > 0:
            findings.append((SEVERITY_WARN, f"{total_drops} drops on {iface}",
                             "Monitor for increasing drops"))

    # --- 4. Check CPU utilization ---
    ok, out, _ = _run("grep -c ^processor /proc/cpuinfo")
    cpu_count = int(out) if ok and out.isdigit() else 1

    ok, out, _ = _run("cat /proc/loadavg")
    if ok:
        load1 = float(out.split()[0])
        load_pct = (load1 / cpu_count) * 100
        if load_pct > 80:
            findings.append((SEVERITY_CRIT, f"CPU load very high: {load1:.1f} ({load_pct:.0f}%)",
                             "WireGuard encryption is CPU-bound; consider a more powerful server"))
        elif load_pct > 50:
            findings.append((SEVERITY_WARN, f"CPU load moderate: {load1:.1f} ({load_pct:.0f}%)",
                             "Monitor under peak traffic; encryption adds CPU overhead"))
        else:
            findings.append((SEVERITY_OK, f"CPU load normal: {load1:.1f} ({load_pct:.0f}%)",
                             "Sufficient headroom for encryption"))

    # --- 5. Check TCP buffer sizes ---
    ok, out, _ = _run("sysctl net.core.rmem_max")
    if ok:
        rmem_max = int(out.split("=")[-1].strip())
        if rmem_max < 4194304:  # 4MB
            findings.append((SEVERITY_WARN, f"TCP receive buffer max={_fmt_bytes(rmem_max)}",
                             "Increase: sysctl -w net.core.rmem_max=16777216"))
        else:
            findings.append((SEVERITY_OK, f"TCP receive buffer max={_fmt_bytes(rmem_max)}", "Adequate"))

    ok, out, _ = _run("sysctl net.core.wmem_max")
    if ok:
        wmem_max = int(out.split("=")[-1].strip())
        if wmem_max < 4194304:
            findings.append((SEVERITY_WARN, f"TCP send buffer max={_fmt_bytes(wmem_max)}",
                             "Increase: sysctl -w net.core.wmem_max=16777216"))
        else:
            findings.append((SEVERITY_OK, f"TCP send buffer max={_fmt_bytes(wmem_max)}", "Adequate"))

    # --- 6. Check conntrack table ---
    ok, out, _ = _run("sysctl net.netfilter.nf_conntrack_count 2>/dev/null")
    if ok:
        ct_count = int(out.split("=")[-1].strip())
        ok2, out2, _ = _run("sysctl net.netfilter.nf_conntrack_max 2>/dev/null")
        if ok2:
            ct_max = int(out2.split("=")[-1].strip())
            usage_pct = (ct_count / max(ct_max, 1)) * 100
            if usage_pct > 80:
                findings.append((SEVERITY_CRIT,
                                 f"Conntrack table {usage_pct:.0f}% full ({ct_count}/{ct_max})",
                                 "Increase: sysctl -w net.netfilter.nf_conntrack_max=262144"))
            elif usage_pct > 50:
                findings.append((SEVERITY_WARN,
                                 f"Conntrack table {usage_pct:.0f}% ({ct_count}/{ct_max})",
                                 "Monitor under load"))
            else:
                findings.append((SEVERITY_OK,
                                 f"Conntrack table {usage_pct:.0f}% ({ct_count}/{ct_max})",
                                 "Healthy"))

    # --- 7. Check qdisc (queue discipline) ---
    ok, out, _ = _run("sysctl net.core.default_qdisc")
    if ok:
        qdisc = out.split("=")[-1].strip()
        if qdisc == "fq":
            findings.append((SEVERITY_OK, f"Queue discipline: {qdisc}", "Optimal for BBR"))
        else:
            findings.append((SEVERITY_WARN, f"Queue discipline: {qdisc} (expected 'fq')",
                             "Set: sysctl -w net.core.default_qdisc=fq"))

    # --- 8. Check IP forwarding ---
    ok, out, _ = _run("sysctl net.ipv4.ip_forward")
    if ok:
        fwd = out.split("=")[-1].strip()
        if fwd == "1":
            findings.append((SEVERITY_OK, "IP forwarding enabled", "Required for port forwarding"))
        else:
            findings.append((SEVERITY_WARN, "IP forwarding disabled",
                             "Enable: sysctl -w net.ipv4.ip_forward=1"))

    # --- 9. Check TCP Fast Open ---
    ok, out, _ = _run("sysctl net.ipv4.tcp_fastopen")
    if ok:
        tfo = int(out.split("=")[-1].strip())
        if tfo >= 3:
            findings.append((SEVERITY_OK, "TCP Fast Open enabled (client+server)",
                             "Saves 1 RTT on repeat connections"))
        elif tfo > 0:
            findings.append((SEVERITY_WARN, f"TCP Fast Open partial (value={tfo})",
                             "Set to 3 for full client+server: sysctl -w net.ipv4.tcp_fastopen=3"))
        else:
            findings.append((SEVERITY_WARN, "TCP Fast Open disabled",
                             "Enable: sysctl -w net.ipv4.tcp_fastopen=3 (saves 1 RTT)"))

    # --- 10. Check TCP keepalive ---
    ok, out, _ = _run("sysctl net.ipv4.tcp_keepalive_time")
    if ok:
        keepalive = int(out.split("=")[-1].strip())
        if keepalive <= 120:
            findings.append((SEVERITY_OK, f"TCP keepalive time={keepalive}s", "Connections stay alive"))
        elif keepalive <= 600:
            findings.append((SEVERITY_WARN, f"TCP keepalive time={keepalive}s (high)",
                             "Reduce to 60: sysctl -w net.ipv4.tcp_keepalive_time=60"))
        else:
            findings.append((SEVERITY_WARN, f"TCP keepalive time={keepalive}s (very high)",
                             "Reduce to 60s to keep tunnel connections alive longer"))

    # --- 11. Check TCP FIN timeout ---
    ok, out, _ = _run("sysctl net.ipv4.tcp_fin_timeout")
    if ok:
        fin = int(out.split("=")[-1].strip())
        if fin <= 20:
            findings.append((SEVERITY_OK, f"TCP FIN timeout={fin}s", "Fast port recycling"))
        else:
            findings.append((SEVERITY_WARN, f"TCP FIN timeout={fin}s (slow port recycling)",
                             "Reduce: sysctl -w net.ipv4.tcp_fin_timeout=15"))

    # --- 12. Check DNS cache ---
    ok53, out53, _ = _run("ss -lntu | grep ':53 '")
    if ok53 and ":53 " in out53:
        findings.append((SEVERITY_OK, "DNS server running on port 53", "Local DNS caching available"))
    else:
        findings.append((SEVERITY_WARN, "No local DNS cache",
                         "Use menu option 5 (Setup DNS Cache) to reduce DNS latency"))

    return findings


# ------------------------------------------------------------------
# TCP Auto-Optimization
# ------------------------------------------------------------------

SYSCTL_CONF_PATH = "/etc/sysctl.d/99-vortexl2-tcp.conf"

TCP_OPTIMIZATIONS = {
    # TCP Fast Open (client+server) — saves 1 RTT on repeat connections
    "net.ipv4.tcp_fastopen": "3",
    # TCP keepalive — keep connections alive longer
    "net.ipv4.tcp_keepalive_time": "60",
    "net.ipv4.tcp_keepalive_intvl": "10",
    "net.ipv4.tcp_keepalive_probes": "6",
    # TCP buffer sizes
    "net.core.rmem_max": "16777216",
    "net.core.wmem_max": "16777216",
    "net.ipv4.tcp_rmem": "4096 131072 16777216",
    "net.ipv4.tcp_wmem": "4096 16384 16777216",
    # Window scaling and timestamps
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_timestamps": "1",
    # BBR + fq qdisc
    "net.core.default_qdisc": "fq",
    "net.ipv4.tcp_congestion_control": "bbr",
    # Forwarding
    "net.ipv4.ip_forward": "1",
    # Reduce TIME_WAIT
    "net.ipv4.tcp_fin_timeout": "15",
    "net.ipv4.tcp_tw_reuse": "1",
}


def get_optimization_preview() -> List[Tuple[str, str, str]]:
    """
    Preview what TCP optimizations would be applied.
    Returns list of (parameter, current_value, new_value) tuples.
    """
    changes = []
    for param, target in TCP_OPTIMIZATIONS.items():
        ok, out, _ = _run(f"sysctl {param}")
        if ok:
            current = out.split("=")[-1].strip()
            if current != target:
                changes.append((param, current, target))
            else:
                changes.append((param, current, "(already set)"))
        else:
            changes.append((param, "(unknown)", target))
    return changes


def apply_tcp_optimizations() -> Tuple[bool, str]:
    """
    Apply all TCP optimizations persistently.

    Writes to /etc/sysctl.d/99-vortexl2-tcp.conf and applies immediately.
    Also sets initcwnd/initrwnd on the default route.

    Returns (success, message).
    """
    # Build the sysctl config file
    lines = [
        "# VortexL2 TCP Optimizations",
        "# Auto-generated — do not edit manually",
        "# Re-apply via: sudo vortexl2 → Bandwidth Monitor → Auto-Optimize",
        "",
    ]

    for param, value in TCP_OPTIMIZATIONS.items():
        lines.append(f"{param} = {value}")

    conf_content = "\n".join(lines) + "\n"

    try:
        with open(SYSCTL_CONF_PATH, 'w') as f:
            f.write(conf_content)
    except IOError as e:
        return False, f"Failed to write {SYSCTL_CONF_PATH}: {e}"

    # Apply sysctl settings
    ok, out, err = _run(f"sysctl -p {SYSCTL_CONF_PATH}")
    if not ok:
        logger.warning(f"sysctl apply warnings: {err}")

    # Set initial congestion window on default route
    ok, out, _ = _run("ip route show default")
    if ok and out:
        # Get the first default route
        default_route = out.split('\n')[0]
        _run(f"ip route change {default_route} initcwnd 32 initrwnd 32")

    # Also apply to tunnel routes if present
    ok, out, _ = _run("ip route show | grep l2tpeth")
    if ok and out:
        for route in out.strip().split('\n'):
            if route.strip():
                _run(f"ip route change {route.strip()} initcwnd 32 initrwnd 32")

    return True, f"TCP optimizations applied and persisted to {SYSCTL_CONF_PATH}"


# ------------------------------------------------------------------
# DNS Cache Setup
# ------------------------------------------------------------------

DNSMASQ_CONF_PATH = "/etc/dnsmasq.d/vortexl2.conf"


def get_dns_cache_status() -> Dict:
    """
    Get the current DNS cache status.

    Returns a dict with keys:
        installed: bool
        running: bool
        config_exists: bool
        server_type: str (e.g. 'dnsmasq', 'AdGuard Home', 'none')
        listen_addresses: list[str]
        upstream_servers: list[str]
        cache_size: int or None
        cache_stats: dict or None (insertions, evictions, hits, misses)
        role: str ('iran', 'kharej', 'unknown')
    """
    status = {
        "installed": False,
        "running": False,
        "config_exists": False,
        "server_type": "none",
        "listen_addresses": [],
        "upstream_servers": [],
        "cache_size": None,
        "cache_stats": None,
        "role": "unknown",
    }

    # Check if dnsmasq is installed
    ok, _, _ = _run("which dnsmasq")
    status["installed"] = ok

    # Check if anything is listening on port 53
    existing = detect_existing_dns()
    if existing:
        status["server_type"] = existing["name"]
        status["running"] = True

    # Check if our config file exists
    import os
    if os.path.exists(DNSMASQ_CONF_PATH):
        status["config_exists"] = True
        try:
            with open(DNSMASQ_CONF_PATH, 'r') as f:
                conf = f.read()

            # Parse listen addresses
            for line in conf.splitlines():
                line = line.strip()
                if line.startswith("listen-address="):
                    addrs = line.split("=", 1)[1]
                    status["listen_addresses"] = [a.strip() for a in addrs.split(",")]
                elif line.startswith("server=") and not line.startswith("server=/"):
                    # Upstream DNS server (e.g. server=8.8.8.8 or server=10.8.0.2#53)
                    status["upstream_servers"].append(line.split("=", 1)[1])
                elif line.startswith("cache-size="):
                    status["cache_size"] = int(line.split("=", 1)[1])

            # Detect role from config content
            if "Iran Server" in conf:
                status["role"] = "iran"
            elif "Kharej Server" in conf:
                status["role"] = "kharej"

        except IOError:
            pass

    # Get dnsmasq cache statistics if running
    if status["running"] and status["server_type"] == "dnsmasq":
        # Send SIGUSR1 to dnsmasq to dump stats to syslog, then read them
        _run("kill -USR1 $(pidof dnsmasq) 2>/dev/null")
        import time
        time.sleep(0.2)
        ok, out, _ = _run("journalctl -u dnsmasq --no-pager -n 20 --output=cat 2>/dev/null")
        if ok and out:
            stats = {}
            for line in out.splitlines():
                if "queries forwarded" in line.lower():
                    import re
                    m = re.search(r'(\d+)', line)
                    if m:
                        stats["forwarded"] = int(m.group(1))
                elif "cache hits" in line.lower():
                    import re
                    m = re.search(r'(\d+)', line)
                    if m:
                        stats["hits"] = int(m.group(1))
                elif "cache size" in line.lower():
                    import re
                    m = re.search(r'(\d+)/(\d+)', line)
                    if m:
                        stats["used"] = int(m.group(1))
                        stats["max"] = int(m.group(2))
            if stats:
                status["cache_stats"] = stats

    return status


def detect_existing_dns() -> Optional[Dict]:
    """
    Detect if an existing DNS server is running on port 53.
    Returns dict with 'name' and 'process' keys, or None.
    """
    ok, out, _ = _run("ss -lntp | grep ':53 '")
    if not ok or not out:
        return None

    # Try to identify the DNS server
    dns_servers = {
        "AdGuardHome": "AdGuard Home",
        "adguardhome": "AdGuard Home",
        "pihole-FTL": "Pi-hole",
        "pihole": "Pi-hole",
        "unbound": "Unbound",
        "named": "BIND",
        "dnsmasq": "dnsmasq",
        "systemd-resolve": "systemd-resolved",
    }

    for proc_name, display_name in dns_servers.items():
        if proc_name.lower() in out.lower():
            return {"name": display_name, "process": proc_name}

    # Something is listening on 53 but we don't recognize it
    return {"name": "Unknown DNS server", "process": "unknown"}


def _get_public_ip() -> Optional[str]:
    """Detect this server's public-facing IP from the default route."""
    ok, out, _ = _run("ip route get 1.1.1.1 | head -1")
    if ok:
        import re
        match = re.search(r'src\s+([\d.]+)', out)
        if match:
            return match.group(1)
    return None


def _disable_resolved_stub() -> bool:
    """
    Disable systemd-resolved stub listener on port 53 if active.
    This prevents conflicts with dnsmasq.
    Backs up /etc/resolv.conf before making changes.
    """
    ok, out, _ = _run("ss -lntp | grep ':53 ' | grep systemd-resolve")
    if not ok or "systemd-resolve" not in (out or ""):
        return True  # Not running, nothing to do

    logger.info("Disabling systemd-resolved stub listener on port 53")

    # Backup resolv.conf before touching anything
    import os
    if os.path.exists("/etc/resolv.conf"):
        _run("cp /etc/resolv.conf /etc/resolv.conf.vortexl2.bak")

    # Create override to disable stub listener
    resolved_conf = "/etc/systemd/resolved.conf.d/vortexl2.conf"
    _run(f"mkdir -p /etc/systemd/resolved.conf.d")

    try:
        with open(resolved_conf, 'w') as f:
            f.write("[Resolve]\n")
            f.write("DNSStubListener=no\n")
    except IOError:
        return False

    _run("systemctl restart systemd-resolved")
    # Remove the symlink if it exists (common on Ubuntu)
    _run("rm -f /etc/resolv.conf")
    try:
        with open("/etc/resolv.conf", 'w') as f:
            f.write("nameserver 127.0.0.1\n")
    except IOError:
        pass

    return True


def _restore_dns_fallback():
    """
    Restore DNS to a working state if dnsmasq fails to start.
    Uses the backup or falls back to public DNS.
    """
    import os
    logger.warning("Restoring DNS fallback after dnsmasq failure")

    if os.path.exists("/etc/resolv.conf.vortexl2.bak"):
        _run("cp /etc/resolv.conf.vortexl2.bak /etc/resolv.conf")
    else:
        try:
            with open("/etc/resolv.conf", 'w') as f:
                f.write("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
        except IOError:
            pass

    # Re-enable systemd-resolved stub if we disabled it
    resolved_conf = "/etc/systemd/resolved.conf.d/vortexl2.conf"
    if os.path.exists(resolved_conf):
        _run(f"rm -f {resolved_conf}")
        _run("systemctl restart systemd-resolved")


def setup_dns_cache_iran(wireguard_peer_ip: str = "10.8.0.2") -> Tuple[bool, str, List[str]]:
    """
    Setup DNS cache on the Iran server.
    Installs dnsmasq, configures it to forward through tunnel.

    Returns (success, message, instructions_for_user).
    """
    # Strip CIDR if present
    wireguard_peer_ip = wireguard_peer_ip.split('/')[0]
    instructions = []

    # Install dnsmasq
    ok, _, err = _run("apt-get install -y dnsmasq", timeout=60)
    if not ok:
        return False, f"Failed to install dnsmasq: {err}", []

    # Detect public IP (before touching DNS)
    public_ip = _get_public_ip()
    listen_addresses = "127.0.0.1"
    if public_ip:
        listen_addresses += f",{public_ip}"

    # Write dnsmasq config
    conf = f"""# VortexL2 DNS Cache — Iran Server
# Auto-generated — forwards DNS through WireGuard tunnel
# Cache misses go to Kharej server's DNS via tunnel

# Listen on localhost and public IP
listen-address={listen_addresses}
bind-interfaces

# Forward DNS through the tunnel to Kharej
server={wireguard_peer_ip}#53

# Aggressive caching
cache-size=10000
min-cache-ttl=300

# Don't read /etc/resolv.conf (we set our own upstreams)
no-resolv

# Don't forward plain names (no dots)
domain-needed
bogus-priv

# Log queries for debugging (comment out in production)
# log-queries

# Port (default 53)
port=53
"""

    try:
        with open(DNSMASQ_CONF_PATH, 'w') as f:
            f.write(conf)
    except IOError as e:
        return False, f"Failed to write {DNSMASQ_CONF_PATH}: {e}", []

    # Disable default dnsmasq config that may conflict
    _run("mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null")
    _run("touch /etc/dnsmasq.conf")

    # Disable systemd-resolved stub ONLY right before starting dnsmasq
    _disable_resolved_stub()

    # Enable and restart dnsmasq
    _run("systemctl enable dnsmasq")
    ok, _, err = _run("systemctl restart dnsmasq")
    if not ok:
        # CRITICAL: restore DNS so the server isn't left broken
        _restore_dns_fallback()
        return False, f"dnsmasq failed to start (DNS restored to fallback): {err}", []

    # Build instructions
    instructions.append(f"DNS cache running on {listen_addresses}:53")
    instructions.append(f"Forwarding cache misses to {wireguard_peer_ip}:53 (via tunnel)")
    if public_ip:
        instructions.append(f"")
        instructions.append(f"CLIENT SETUP:")
        instructions.append(f"  Set DNS server to: {public_ip}")
        instructions.append(f"  Or in V2Ray client config, set DNS to {public_ip}")

    return True, "DNS cache configured on Iran server", instructions


def setup_dns_cache_kharej(wireguard_ip: str = "10.8.0.2") -> Tuple[bool, str, List[str]]:
    """
    Setup DNS resolver on the Kharej server.
    Checks for existing DNS server first; installs dnsmasq if none found.

    Returns (success, message, instructions_for_user).
    """
    instructions = []

    # Check for existing DNS server
    existing = detect_existing_dns()

    if existing and existing["name"] != "systemd-resolved":
        # Found an existing DNS server (not just systemd-resolved)
        name = existing["name"]

        if name == "dnsmasq":
            # dnsmasq already installed — just update config
            return _configure_kharej_dnsmasq(wireguard_ip)

        # External DNS server found (AdGuard Home, Pi-hole, etc.)
        instructions.append(f"Detected: {name} is running on port 53")
        instructions.append(f"")
        instructions.append(f"Please configure {name} to also listen on {wireguard_ip}:")
        instructions.append(f"")

        if "AdGuard" in name:
            instructions.append(f"  AdGuard Home → Settings → DNS Settings → Listen addresses")
            instructions.append(f"  Add: {wireguard_ip}:53")
        elif "Pi-hole" in name:
            instructions.append(f"  Pi-hole → Settings → DNS → Interface settings")
            instructions.append(f"  Bind to: {wireguard_ip}")
        elif "Unbound" in name:
            instructions.append(f"  Edit /etc/unbound/unbound.conf:")
            instructions.append(f"    interface: {wireguard_ip}")
        elif "BIND" in name:
            instructions.append(f"  Edit /etc/bind/named.conf.options:")
            instructions.append(f"    listen-on {{ {wireguard_ip}; }};")
        else:
            instructions.append(f"  Configure your DNS server to listen on {wireguard_ip}:53")

        instructions.append(f"")
        instructions.append(f"This makes it accessible from the Iran server through the tunnel.")

        return True, f"{name} detected — manual configuration needed", instructions

    # No external DNS server found — install dnsmasq
    return _configure_kharej_dnsmasq(wireguard_ip)


def _configure_kharej_dnsmasq(wireguard_ip: str) -> Tuple[bool, str, List[str]]:
    """Install and configure dnsmasq on Kharej server."""
    instructions = []

    # Install dnsmasq
    ok, _, err = _run("apt-get install -y dnsmasq", timeout=60)
    if not ok:
        return False, f"Failed to install dnsmasq: {err}", []

    # Write dnsmasq config (BEFORE disabling resolved)
    # Strip CIDR if present
    wireguard_ip = wireguard_ip.split('/')[0]

    conf = f"""# VortexL2 DNS Resolver — Kharej Server
# Auto-generated — resolves DNS for Iran server via tunnel
# Only listens on WireGuard IP (not exposed publicly)

# Listen only on the WireGuard tunnel interface
listen-address={wireguard_ip}
# bind-dynamic allows starting even if the interface/IP isn't up yet
bind-dynamic

# Upstream public DNS servers
server=8.8.8.8
server=1.1.1.1
server=8.8.4.4

# Caching
cache-size=5000

# Don't read /etc/resolv.conf
no-resolv

# Security
domain-needed
bogus-priv

# Port (default 53)
port=53
"""

    try:
        with open(DNSMASQ_CONF_PATH, 'w') as f:
            f.write(conf)
    except IOError as e:
        return False, f"Failed to write {DNSMASQ_CONF_PATH}: {e}", []

    # Disable default dnsmasq config
    _run("mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null")
    _run("touch /etc/dnsmasq.conf")

    # Disable systemd-resolved stub ONLY right before starting dnsmasq
    _disable_resolved_stub()

    # Enable and restart
    _run("systemctl enable dnsmasq")
    ok, _, err = _run("systemctl restart dnsmasq")
    if not ok:
        # CRITICAL: restore DNS so the server isn't left broken
        _restore_dns_fallback()
        return False, f"dnsmasq failed to start (DNS restored to fallback): {err}", []

    # Kharej needs working system DNS for its own outbound connections
    # Ensure resolv.conf has localhost (dnsmasq) + public fallback
    try:
        with open("/etc/resolv.conf", 'w') as f:
            f.write("nameserver 127.0.0.1\nnameserver 8.8.8.8\n")
    except IOError:
        pass

    instructions.append(f"dnsmasq running on {wireguard_ip}:53")
    instructions.append(f"Resolving via: 8.8.8.8, 1.1.1.1, 8.8.4.4")
    instructions.append(f"Only accessible from inside the tunnel (not exposed publicly)")

    return True, "DNS resolver configured on Kharej server", instructions


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _fmt_bytes(b: float) -> str:
    """Format bytes to human-readable string."""
    if b < 0:
        b = 0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(b) < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} PB"


def _fmt_speed(bps: float) -> str:
    """Format bytes/sec to human-readable speed."""
    if bps < 0:
        bps = 0
    for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
        if abs(bps) < 1024.0:
            return f"{bps:.1f} {unit}"
        bps /= 1024.0
    return f"{bps:.1f} TB/s"
