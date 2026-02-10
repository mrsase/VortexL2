"""
VortexL2 MTU Finder & Auto-Configurator

Discovers the optimal MTU for the physical link via binary search + stability
testing, then computes and applies the correct MTU/MSS for each tunnel layer
(L2TP, WireGuard).

Based on mtu-finder.py v5.0 — adapted for integration with VortexL2.
"""

import logging
import platform
import shutil
import statistics
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# --- Constants ---
IP_HEADER = 20
ICMP_HEADER = 8
HEADERS_SIZE = IP_HEADER + ICMP_HEADER  # 28 bytes
SYS_PLATFORM = platform.system().lower()

# Overhead added by each encapsulation layer (bytes)
L2TP_UDP_ENCAP_OVERHEAD = 26   # L2TPv3 over UDP
L2TP_IP_ENCAP_OVERHEAD = 16    # L2TPv3 raw IP protocol 115
WIREGUARD_OVERHEAD = 60        # WireGuard IPv4
TCP_HEADER_OVERHEAD = 40       # TCP/IP headers (for MSS calculation)

# --- Tunnel Protocol Table (for informational display) ---
TUNNEL_OVERHEADS = {
    "IPIP (IP-in-IP)": 20,
    "Shadowsocks": 20,
    "GRE (Generic)": 24,
    "OpenVPN (UDP)": 28,
    "V2Ray/VMess (TCP)": 30,
    "Trojan": 30,
    "OpenVPN (TCP)": 40,
    "L7 Tunnel (Gost/Rathole)": 40,
    "VXLAN (L2)": 50,
    "Geneve": 50,
    "V2Ray/VMess (WebSocket)": 50,
    "WireGuard (IPv4)": 60,
    "SSTP": 60,
    "IPSec (IKEv2/ESP)": 62,
    "L2TP/IPSec": 62,
    "GRE + IPSec (ESP)": 74,
    "WireGuard (IPv6)": 80,
}

# --- Ping Targets ---
FOREIGN_CANDIDATES = [
    "1.1.1.1", "8.8.8.8", "4.2.2.4", "4.2.2.5",
    "209.244.0.3", "208.67.222.222", "9.9.9.9",
]

IRAN_CANDIDATES = [
    "178.22.122.100", "185.51.200.2", "10.202.10.202",
    "217.218.127.127", "85.15.1.12", "185.55.225.25",
    "78.157.42.100", "94.103.125.157",
]


@dataclass
class MtuTestResult:
    """Stores detailed MTU test results."""
    mtu: int
    success_rate: float
    avg_latency: float
    max_latency: float
    jitter: float
    packet_loss: float


@dataclass
class MtuRecommendation:
    """Final MTU/MSS recommendation for each layer."""
    physical_mtu: int
    l2tp_mtu: int
    wireguard_mtu: int
    tcp_mss: int
    test_result: Optional[MtuTestResult] = None


def _run(cmd: str, timeout: int = 30) -> Tuple[bool, str, str]:
    """Execute a shell command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


# ------------------------------------------------------------------
# Ping helpers
# ------------------------------------------------------------------

def ping_target(
    target: str,
    payload_size: int = 56,
    count: int = 1,
    timeout: float = 2.0,
    interval: float = None,
) -> Tuple[bool, float, List[float]]:
    """
    Ping with DF flag and parse results.
    Returns: (success, packet_loss_percent, latencies_ms)
    """
    cmd = ["ping", "-c", str(count), "-W", str(int(timeout))]

    if "linux" in SYS_PLATFORM:
        cmd.extend(["-M", "do", "-s", str(payload_size)])
    elif "darwin" in SYS_PLATFORM:
        cmd.extend(["-D", "-s", str(payload_size)])
    else:
        cmd.extend(["-s", str(payload_size)])

    if interval:
        cmd.extend(["-i", str(interval)])

    cmd.append(target)

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout * count + 2,
        )
        loss = 100.0
        latencies = []

        for line in result.stdout.splitlines():
            if "packet loss" in line.lower():
                parts = line.split(",")
                for part in parts:
                    if "loss" in part.lower():
                        loss_str = part.strip().split("%")[0].split()[-1]
                        try:
                            loss = float(loss_str)
                        except ValueError:
                            pass
            if "time=" in line:
                try:
                    time_part = line.split("time=")[1].split()[0]
                    latencies.append(float(time_part))
                except (IndexError, ValueError):
                    pass

        return result.returncode == 0 and loss < 100, loss, latencies
    except (subprocess.TimeoutExpired, Exception):
        return False, 100.0, []


def find_best_target(candidates: List[str]) -> Optional[str]:
    """Find the most responsive target from a list of IPs."""
    best_target = None
    best_latency = float("inf")

    for ip in candidates:
        success, loss, latencies = ping_target(ip, count=2, timeout=2)
        if success and loss == 0 and latencies:
            avg = statistics.mean(latencies)
            if avg < best_latency:
                best_latency = avg
                best_target = ip

    return best_target


# ------------------------------------------------------------------
# MTU Discovery
# ------------------------------------------------------------------

def find_theoretical_max(target: str, progress_cb=None) -> int:
    """Binary search for maximum passable MTU (payload size).

    Args:
        target: IP to ping
        progress_cb: optional callable(percent, status_msg)

    Returns:
        Discovered physical-link MTU (payload + headers), or 0 on failure.
    """
    low = 500
    high = 1472  # max payload for 1500 MTU
    optimal_payload = 0
    iterations = 0
    max_iterations = 15

    while low <= high and iterations < max_iterations:
        mid = (low + high) // 2
        iterations += 1

        success, loss, _ = ping_target(target, mid, count=2, timeout=1.5)

        if progress_cb:
            pct = int((iterations / max_iterations) * 100)
            progress_cb(pct, f"Binary search [{low}-{high}] testing {mid + HEADERS_SIZE}")

        if success and loss == 0:
            optimal_payload = mid
            low = mid + 1
        else:
            high = mid - 1

        time.sleep(0.1)

    if optimal_payload == 0:
        return 0
    return optimal_payload + HEADERS_SIZE


def test_mtu_stability(
    target: str,
    mtu: int,
    test_packets: int = 200,
    test_duration: int = 20,
    progress_cb=None,
) -> MtuTestResult:
    """Send many packets at the given MTU and measure reliability.

    Args:
        progress_cb: optional callable(percent, status_msg)
    """
    payload_size = mtu - HEADERS_SIZE
    chunk_size = 10
    chunks = test_packets // chunk_size

    all_latencies: List[float] = []
    total_sent = 0
    total_lost = 0
    start_time = time.time()

    for i in range(chunks):
        if time.time() - start_time > test_duration:
            break

        interval = 0.02 if i % 3 == 0 else 0.05
        success, loss, latencies = ping_target(
            target, payload_size, count=chunk_size, timeout=2.0, interval=interval,
        )

        total_sent += chunk_size
        if latencies:
            all_latencies.extend(latencies)
        total_lost += chunk_size - len(latencies)

        current_loss = (total_lost / total_sent) * 100

        if progress_cb:
            pct = int(((i + 1) / chunks) * 100)
            status = f"Loss: {current_loss:.1f}%"
            if latencies:
                status += f" | Lat: {statistics.mean(latencies):.1f}ms"
            progress_cb(pct, status)

        if current_loss > 2.0:
            break
        time.sleep(0.05)

    if all_latencies:
        avg_latency = statistics.mean(all_latencies)
        max_latency = max(all_latencies)
        jitter = statistics.stdev(all_latencies) if len(all_latencies) > 1 else 0
    else:
        avg_latency = max_latency = jitter = 0

    packet_loss = (total_lost / total_sent) * 100 if total_sent > 0 else 100

    return MtuTestResult(
        mtu=mtu,
        success_rate=100 - packet_loss,
        avg_latency=avg_latency,
        max_latency=max_latency,
        jitter=jitter,
        packet_loss=packet_loss,
    )


def find_stable_mtu(
    target: str,
    start_mtu: int,
    conservative: bool = True,
    progress_cb=None,
) -> Tuple[int, Optional[MtuTestResult]]:
    """Step down from start_mtu until a stable value is found.

    Returns (stable_mtu, test_result) or (0, None) on failure.
    """
    test_packets = 300 if conservative else 200
    max_loss = 1.0 if conservative else 2.0

    current_mtu = start_mtu

    while current_mtu >= 1280:
        result = test_mtu_stability(
            target, current_mtu, test_packets=test_packets,
            test_duration=30, progress_cb=progress_cb,
        )

        if result.packet_loss <= max_loss:
            # Verification pass
            verify = test_mtu_stability(
                target, current_mtu, test_packets=100,
                test_duration=10, progress_cb=progress_cb,
            )
            if verify.packet_loss <= max_loss:
                return current_mtu, result
            # Verification failed — keep stepping down

        # Adaptive step
        if result.packet_loss > 20:
            step = 50
        elif result.packet_loss > 10:
            step = 20
        elif result.packet_loss > 5:
            step = 10
        else:
            step = 4

        current_mtu -= step

    return 0, None


# ------------------------------------------------------------------
# Full discovery + recommendation
# ------------------------------------------------------------------

def discover_mtu(
    target: str = None,
    use_iran_mode: bool = False,
    conservative: bool = True,
    progress_cb=None,
) -> Optional[MtuRecommendation]:
    """Run the full MTU discovery process.

    Args:
        target: specific IP to test (auto-detected if None)
        use_iran_mode: if True, tests both foreign and domestic routes
        conservative: stricter stability criteria
        progress_cb: optional callable(phase, percent, status_msg)
            phase is one of: "target", "binary", "stability"

    Returns:
        MtuRecommendation with computed values for every layer, or None.
    """
    def _pcb(phase):
        """Wrap progress_cb to inject phase."""
        if not progress_cb:
            return None
        return lambda pct, msg: progress_cb(phase, pct, msg)

    final_mtu = 0
    final_result = None

    if target:
        # Single-target mode
        theoretical = find_theoretical_max(target, _pcb("binary"))
        if not theoretical:
            return None
        final_mtu, final_result = find_stable_mtu(
            target, theoretical, conservative, _pcb("stability"),
        )
    elif use_iran_mode:
        # Dual-route mode: test foreign + domestic, use bottleneck
        results = []

        foreign_ip = find_best_target(FOREIGN_CANDIDATES)
        if foreign_ip:
            t = find_theoretical_max(foreign_ip, _pcb("binary"))
            if t:
                mtu, res = find_stable_mtu(foreign_ip, t, conservative, _pcb("stability"))
                if mtu:
                    results.append((mtu, res))

        domestic_ip = find_best_target(IRAN_CANDIDATES)
        if domestic_ip:
            t = find_theoretical_max(domestic_ip, _pcb("binary"))
            if t:
                mtu, res = find_stable_mtu(domestic_ip, t, conservative, _pcb("stability"))
                if mtu:
                    results.append((mtu, res))

        if results:
            final_mtu = min(r[0] for r in results)
            final_result = next(r[1] for r in results if r[0] == final_mtu)
    else:
        # Default: test 8.8.8.8
        target = find_best_target(FOREIGN_CANDIDATES) or "8.8.8.8"
        theoretical = find_theoretical_max(target, _pcb("binary"))
        if not theoretical:
            return None
        final_mtu, final_result = find_stable_mtu(
            target, theoretical, conservative, _pcb("stability"),
        )

    if not final_mtu:
        return None

    return compute_recommendation(final_mtu, final_result)


def compute_recommendation(
    physical_mtu: int,
    test_result: Optional[MtuTestResult] = None,
    encap_type: str = "udp",
    wireguard_enabled: bool = True,
) -> MtuRecommendation:
    """Compute L2TP, WireGuard, and MSS values from a physical MTU.

    Args:
        physical_mtu: stable MTU of the physical link
        encap_type: "udp" or "ip" L2TP encapsulation
        wireguard_enabled: whether WireGuard layer is active
    """
    l2tp_overhead = L2TP_UDP_ENCAP_OVERHEAD if encap_type == "udp" else L2TP_IP_ENCAP_OVERHEAD
    l2tp_mtu = physical_mtu - l2tp_overhead

    if wireguard_enabled:
        wg_mtu = l2tp_mtu - WIREGUARD_OVERHEAD
    else:
        wg_mtu = 0

    # MSS = innermost MTU minus TCP/IP headers
    inner_mtu = wg_mtu if wireguard_enabled else l2tp_mtu
    tcp_mss = inner_mtu - TCP_HEADER_OVERHEAD

    return MtuRecommendation(
        physical_mtu=physical_mtu,
        l2tp_mtu=l2tp_mtu,
        wireguard_mtu=wg_mtu,
        tcp_mss=tcp_mss,
        test_result=test_result,
    )


def get_protocol_table(physical_mtu: int) -> List[Dict]:
    """Return a list of dicts with protocol overhead, tunnel MTU, MSS."""
    rows = []
    for proto, overhead in sorted(TUNNEL_OVERHEADS.items(), key=lambda x: x[1]):
        tunnel_mtu = physical_mtu - overhead
        mss = tunnel_mtu - TCP_HEADER_OVERHEAD
        rows.append({
            "protocol": proto,
            "overhead": overhead,
            "mtu": tunnel_mtu,
            "mss": mss,
        })
    return rows


# ------------------------------------------------------------------
# Apply MTU/MSS to running system
# ------------------------------------------------------------------

def apply_mtu(
    rec: MtuRecommendation,
    l2tp_interface: str = "l2tpeth0",
    wg_interface: str = "wg_vortex",
) -> List[Tuple[str, bool, str]]:
    """Apply the recommended MTU and MSS clamp to the system.

    Returns list of (description, success, detail).
    """
    results: List[Tuple[str, bool, str]] = []

    # 1. Set L2TP interface MTU
    ok, _, err = _run(f"ip link set {l2tp_interface} mtu {rec.l2tp_mtu}")
    results.append((
        f"Set {l2tp_interface} MTU → {rec.l2tp_mtu}",
        ok,
        err if not ok else "applied",
    ))

    # 2. Set WireGuard interface MTU (if applicable)
    if rec.wireguard_mtu > 0:
        ok, _, err = _run(f"ip link set {wg_interface} mtu {rec.wireguard_mtu}")
        results.append((
            f"Set {wg_interface} MTU → {rec.wireguard_mtu}",
            ok,
            err if not ok else "applied",
        ))

        # 3. MSS clamp on WireGuard interface
        for direction in ("-o", "-i"):
            # Remove existing rule first (ignore errors)
            _run(
                f"iptables -t mangle -D FORWARD {direction} {wg_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {rec.tcp_mss}"
            )
            ok, _, err = _run(
                f"iptables -t mangle -A FORWARD {direction} {wg_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {rec.tcp_mss}"
            )
            label = "outbound" if direction == "-o" else "inbound"
            results.append((
                f"MSS clamp {label} on {wg_interface} → {rec.tcp_mss}",
                ok,
                err if not ok else "applied",
            ))
    else:
        # No WireGuard — clamp MSS on L2TP interface
        for direction in ("-o", "-i"):
            _run(
                f"iptables -t mangle -D FORWARD {direction} {l2tp_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {rec.tcp_mss}"
            )
            ok, _, err = _run(
                f"iptables -t mangle -A FORWARD {direction} {l2tp_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {rec.tcp_mss}"
            )
            label = "outbound" if direction == "-o" else "inbound"
            results.append((
                f"MSS clamp {label} on {l2tp_interface} → {rec.tcp_mss}",
                ok,
                err if not ok else "applied",
            ))

    return results


def get_current_mtu(interface: str) -> Optional[int]:
    """Read the current MTU of a network interface."""
    ok, out, _ = _run(f"cat /sys/class/net/{interface}/mtu")
    if ok and out:
        try:
            return int(out.strip())
        except ValueError:
            pass
    return None
