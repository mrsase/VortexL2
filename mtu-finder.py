#!/usr/bin/env python3
"""
MTU Finder v5.0 - Production-Grade Reliability
Optimized for VPN tuning in Iran with comprehensive stability testing.
"""

import argparse
import platform
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

# --- Constants ---
IP_HEADER = 20
ICMP_HEADER = 8
HEADERS_SIZE = IP_HEADER + ICMP_HEADER  # 28 bytes
SYS_PLATFORM = platform.system().lower()

# --- Tunnel Overheads (Bytes) ---
TUNNEL_OVERHEADS = {
    "IPIP (IP-in-IP)": 20,
    "GRE (Generic)": 24,
    "GRE + IPSec (ESP)": 24 + 50,
    "WireGuard (IPv4)": 60,
    "WireGuard (IPv6)": 80,
    "OpenVPN (UDP)": 28,
    "OpenVPN (TCP)": 40,
    "VXLAN (L2)": 50,
    "Geneve": 50,
    "IPSec (IKEv2/ESP)": 62,
    "L2TP/IPSec": 62,
    "SSTP": 60,
    "L7 Tunnel (Gost/Rathole)": 40,
    "V2Ray/VMess (TCP)": 30,
    "V2Ray/VMess (WebSocket)": 50,
    "Shadowsocks": 20,
    "Trojan": 30,
}

# --- Targets ---
FOREIGN_CANDIDATES = [
    "1.1.1.1",  # Cloudflare - Usually fast
    "8.8.8.8",  # Google DNS
    "4.2.2.4",  # Level 3
    "4.2.2.5",  # Level 3
    "209.244.0.3",  # Level 3
    "209.244.0.4",  # Level 3
    "208.67.222.222",  # OpenDNS
    "9.9.9.9",  # Quad9
    "46.151.208.154",
    "156.154.70.1",
    "216.146.35.35",
    "47.143.125.174",
    "81.214.55.192",
    "78.188.88.16",
    "75.181.133.44",
    "63.228.227.208",
    "209.180.103.117",
    "173.249.48.36",
    "80.156.145.201",
    "87.191.168.7",
    "217.79.177.220",
    "130.180.61.162",
    "62.55.223.169",
    "176.9.1.117",
    "88.79.149.4",
]

IRAN_CANDIDATES = [
    "178.22.122.100",  # Shecan DNS
    "185.51.200.2",  # Shecan DNS
    "10.202.10.202",  # 403
    "10.202.10.102",  # 403
    "217.218.127.127",  # zirsakht
    "217.218.155.155",  # zirsakht
    "85.15.1.12",  # IranServer DNS
    "185.55.225.25",  # begzar
    "185.55.226.26",  # begzar
    "10.202.10.10",  # radar
    "10.202.10.11",  # radar
    "78.157.42.100",  # electro
    "78.157.42.101",  # electro
    "94.103.125.157",  # shelter
    "94.103.125.158",  # shelter
    "181.41.194.177",  # beshkan
    "181.41.194.186",  # beshkan
    "5.202.100.100",  # pishgaman
    "5.202.100.101 ",  # pishgaman
    "85.15.1.14",  # shatel
    "85.15.1.15",  # shatel
    "208.67.222.222",  # mci
    "208.67.220.200",  # mci
    "74.82.42.42",  # irancell
    "89.223.43.71",  # ritel
]


@dataclass
class TestResult:
    """Store detailed test results"""

    mtu: int
    success_rate: float
    avg_latency: float
    max_latency: float
    jitter: float
    packet_loss: float


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def print_status(msg, color=Colors.RESET, end="\n"):
    """Print colored status message"""
    sys.stdout.write(f"{color}{msg}{Colors.RESET}{end}")
    sys.stdout.flush()


def draw_progress(percent, width=30, prefix="", status=""):
    """Enhanced progress bar with status"""
    filled = int(width * percent / 100)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(
        f"\r{prefix} [{Colors.CYAN}{bar}{Colors.RESET}] {percent:3d}% {status}  "
    )
    sys.stdout.flush()


def check_dependencies():
    """Verify required system commands exist"""
    if not shutil.which("ping"):
        print_status("❌ Error: 'ping' command not found.", Colors.RED)
        sys.exit(1)


def ping_target_detailed(
    target: str,
    payload_size: int = 56,
    count: int = 1,
    timeout: float = 2.0,
    interval: float = None,
    interface: str = None,
) -> Tuple[bool, float, List[float]]:
    """
    Ping with detailed statistics
    Returns: (success, packet_loss, latencies)
    """
    cmd = ["ping", "-c", str(count), "-W", str(int(timeout))]

    if "linux" in SYS_PLATFORM:
        cmd.extend(["-M", "do", "-s", str(payload_size)])
    elif "darwin" in SYS_PLATFORM:
        cmd.extend(["-D", "-s", str(payload_size)])
    else:
        cmd.extend(["-s", str(payload_size)])

    if interface:
        cmd.extend(["-I", interface])
    if interval:
        cmd.extend(["-i", str(interval)])

    cmd.append(target)

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout * count + 2,
        )

        loss = 100.0
        latencies = []

        for line in result.stdout.splitlines():
            # Parse packet loss
            if "packet loss" in line.lower():
                parts = line.split(",")
                for part in parts:
                    if "packet loss" in part.lower() or "loss" in part.lower():
                        loss_str = part.strip().split("%")[0].split()[-1]
                        try:
                            loss = float(loss_str)
                        except ValueError:
                            pass

            # Parse latency (time=X.X ms)
            if "time=" in line:
                try:
                    time_part = line.split("time=")[1].split()[0]
                    latency = float(time_part)
                    latencies.append(latency)
                except (IndexError, ValueError):
                    pass

        success = result.returncode == 0 and loss < 100
        return success, loss, latencies

    except subprocess.TimeoutExpired:
        return False, 100.0, []
    except Exception:
        return False, 100.0, []


def find_best_target(candidates: List[str], label: str) -> Optional[str]:
    """Find most reliable target with latency check"""
    print_status(f"🔍 Scanning for reliable {label} target...", Colors.YELLOW)

    best_target = None
    best_score = float("inf")

    for ip in candidates:
        success, loss, latencies = ping_target_detailed(ip, count=3, timeout=2)

        if success and loss == 0 and latencies:
            avg_latency = statistics.mean(latencies)
            score = avg_latency  # Lower is better

            print_status(
                f"   ├─ {ip}: {Colors.GREEN}✓{Colors.RESET} "
                f"({avg_latency:.1f}ms avg)",
                Colors.DIM,
            )

            if score < best_score:
                best_score = score
                best_target = ip
        else:
            print_status(
                f"   ├─ {ip}: {Colors.RED}✗{Colors.RESET} (unreachable)", Colors.DIM
            )

    if best_target:
        print_status(
            f"   └─ Selected: {best_target} ({best_score:.1f}ms)", Colors.GREEN
        )
    else:
        print_status(f"   └─ No reachable targets found", Colors.RED)

    return best_target


def find_theoretical_max(target: str, interface: str = None) -> int:
    """Binary search for maximum passable MTU"""
    print_status(
        f"   ▸ Phase 1: Finding Theoretical Maximum (Binary Search)...", Colors.CYAN
    )

    low = 500
    high = 1472  # Max payload for 1500 MTU
    optimal_payload = 0

    iterations = 0
    max_iterations = 15

    while low <= high and iterations < max_iterations:
        mid = (low + high) // 2
        iterations += 1

        # Quick test with 2 packets
        success, loss, _ = ping_target_detailed(
            target, mid, count=2, timeout=1.5, interface=interface
        )

        status = f"Testing {mid + HEADERS_SIZE}..."
        draw_progress(
            int((iterations / max_iterations) * 100),
            prefix=f"      Binary Search [{low}-{high}]",
            status=status,
        )

        if success and loss == 0:
            optimal_payload = mid
            low = mid + 1
        else:
            high = mid - 1

        time.sleep(0.1)  # Small delay for stability

    sys.stdout.write("\n")

    if optimal_payload == 0:
        return 0

    theoretical_mtu = optimal_payload + HEADERS_SIZE
    print_status(f"      → Theoretical Max: {theoretical_mtu} bytes", Colors.GREEN)
    return theoretical_mtu


def test_mtu_stability(
    target: str,
    mtu: int,
    interface: str = None,
    test_packets: int = 200,
    test_duration: int = 20,
) -> TestResult:
    """
    Comprehensive stability test with real-world simulation

    Args:
        target: IP to test
        mtu: MTU value to test
        interface: Network interface
        test_packets: Total packets to send
        test_duration: Duration in seconds (we'll use whichever comes first)
    """
    payload_size = mtu - HEADERS_SIZE

    # Adaptive packet sending
    # For stability, we need to simulate real traffic patterns
    chunk_size = 10
    chunks = test_packets // chunk_size

    all_latencies = []
    total_sent = 0
    total_lost = 0

    start_time = time.time()

    for i in range(chunks):
        # Check if we've exceeded time limit
        elapsed = time.time() - start_time
        if elapsed > test_duration:
            break

        percent = int(((i + 1) / chunks) * 100)

        # Vary the interval slightly to simulate real traffic
        # Faster bursts to catch instability
        interval = 0.02 if i % 3 == 0 else 0.05

        success, loss, latencies = ping_target_detailed(
            target,
            payload_size,
            count=chunk_size,
            timeout=2.0,
            interval=interval,
            interface=interface,
        )

        total_sent += chunk_size

        if latencies:
            all_latencies.extend(latencies)

        # Calculate actual loss
        packets_received = len(latencies)
        packets_lost = chunk_size - packets_received
        total_lost += packets_lost

        current_loss = (total_lost / total_sent) * 100

        status = f"Loss: {current_loss:.1f}%"
        if latencies:
            status += f" | Latency: {statistics.mean(latencies):.1f}ms"

        draw_progress(
            percent,
            prefix=f"      Testing MTU {Colors.BOLD}{mtu}{Colors.RESET}",
            status=status,
        )

        # Early termination if significant packet loss detected
        if current_loss > 2.0:  # More than 2% loss = unstable
            break

        # Small random delay to simulate real-world conditions
        time.sleep(0.05)

    sys.stdout.write("\n")

    # Calculate statistics
    if all_latencies:
        avg_latency = statistics.mean(all_latencies)
        max_latency = max(all_latencies)
        jitter = statistics.stdev(all_latencies) if len(all_latencies) > 1 else 0
    else:
        avg_latency = max_latency = jitter = 0

    packet_loss = (total_lost / total_sent) * 100 if total_sent > 0 else 100
    success_rate = 100 - packet_loss

    return TestResult(
        mtu=mtu,
        success_rate=success_rate,
        avg_latency=avg_latency,
        max_latency=max_latency,
        jitter=jitter,
        packet_loss=packet_loss,
    )


def find_stable_mtu(
    target: str, start_mtu: int, interface: str = None, conservative: bool = True
) -> Tuple[int, TestResult]:
    """
    Find stable MTU through rigorous testing

    Args:
        conservative: If True, use stricter criteria (recommended for VPN)
    """
    print_status(f"   ▸ Phase 2: Comprehensive Stability Testing...", Colors.CYAN)

    if conservative:
        print_status(
            f"      Mode: Conservative (300 packets, <1% loss tolerance)", Colors.DIM
        )
        test_packets = 300
        max_loss = 1.0  # 1% max loss
    else:
        print_status(
            f"      Mode: Standard (200 packets, <2% loss tolerance)", Colors.DIM
        )
        test_packets = 200
        max_loss = 2.0

    current_mtu = start_mtu
    best_stable_mtu = 0
    best_result = None

    # Start testing from theoretical max and step down
    tested_mtus = []

    while current_mtu >= 1280:  # IPv6 minimum MTU
        # Skip if we've already tested this MTU
        if current_mtu in tested_mtus:
            current_mtu -= 8
            continue

        tested_mtus.append(current_mtu)

        print_status(
            f"\n   ┌─ Testing MTU: {Colors.BOLD}{current_mtu}{Colors.RESET}",
            Colors.YELLOW,
        )

        result = test_mtu_stability(
            target, current_mtu, interface, test_packets=test_packets, test_duration=30
        )

        # Detailed results
        if result.packet_loss <= max_loss:
            print_status(
                f"   ├─ {Colors.GREEN}✓ STABLE{Colors.RESET} | "
                f"Loss: {result.packet_loss:.2f}% | "
                f"Latency: {result.avg_latency:.1f}±{result.jitter:.1f}ms | "
                f"Max: {result.max_latency:.1f}ms",
                Colors.GREEN,
            )
            best_stable_mtu = current_mtu
            best_result = result

            # Found stable MTU, do one more verification at this size
            print_status(f"   └─ Verification test...", Colors.CYAN)
            verify_result = test_mtu_stability(
                target, current_mtu, interface, test_packets=100, test_duration=10
            )

            if verify_result.packet_loss <= max_loss:
                print_status(f"      ✓ Verified stable at {current_mtu}", Colors.GREEN)
                break
            else:
                print_status(
                    f"      ✗ Verification failed, continuing search...", Colors.YELLOW
                )
                best_stable_mtu = 0

        else:
            print_status(
                f"   ├─ {Colors.RED}✗ UNSTABLE{Colors.RESET} | "
                f"Loss: {result.packet_loss:.2f}% | "
                f"Latency: {result.avg_latency:.1f}±{result.jitter:.1f}ms",
                Colors.RED,
            )
            print_status(f"   └─ Reducing MTU...", Colors.YELLOW)

        # Adaptive step size based on packet loss
        if result.packet_loss > 20:
            step = 50  # Large loss = big step down
        elif result.packet_loss > 10:
            step = 20
        elif result.packet_loss > 5:
            step = 10
        else:
            step = 4  # Fine-tuning

        current_mtu -= step

        # Safety check
        if current_mtu < 1280:
            break

    return best_stable_mtu, best_result


def print_smart_calculations(phys_mtu: int, test_result: TestResult = None):
    """Print tunnel MTU recommendations"""
    print(f"\n{Colors.BOLD}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SMART TUNNEL CONFIGURATION GUIDE{Colors.RESET}")
    print(f"{Colors.BOLD}{'═'*60}{Colors.RESET}")
    print(f"\nStable Physical MTU: {Colors.GREEN}{Colors.BOLD}{phys_mtu}{Colors.RESET}")

    if test_result:
        print(
            f"Reliability: {Colors.GREEN}{test_result.success_rate:.1f}%{Colors.RESET}"
        )
        print(
            f"Avg Latency: {test_result.avg_latency:.1f}ms (±{test_result.jitter:.1f}ms)"
        )

    print(f"\n{Colors.BOLD}Recommended Tunnel MTU Values:{Colors.RESET}\n")
    print(f"{'PROTOCOL':<30} │ {'OVERHEAD':>8} │ {'MTU':>6} │ {'MSS':>6}")
    print(f"{'─'*30}─┼─{'─'*8}─┼─{'─'*6}─┼─{'─'*6}")

    # Sort by MTU (descending) to show best options first
    sorted_tunnels = sorted(
        TUNNEL_OVERHEADS.items(), key=lambda x: phys_mtu - x[1], reverse=True
    )

    for proto, overhead in sorted_tunnels:
        tunnel_mtu = phys_mtu - overhead
        mss = tunnel_mtu - 40  # TCP overhead

        if tunnel_mtu >= 1280:  # Valid MTU
            color = Colors.GREEN
        else:
            color = Colors.YELLOW

        print(
            f"{proto:<30} │ {overhead:>8} │ {color}{tunnel_mtu:>6}{Colors.RESET} │ {mss:>6}"
        )

    print(f"{'─'*30}─┴─{'─'*8}─┴─{'─'*6}─┴─{'─'*6}")

    # Special notes
    print(f"\n{Colors.BOLD}Important Notes:{Colors.RESET}")
    print(f"• MTU = Maximum Transmission Unit (Layer 3)")
    print(f"• MSS = Maximum Segment Size (TCP Layer 4)")
    print(f"• For TCP-based tunnels, set MSS clamp = MTU - 40")
    print(f"• {Colors.YELLOW}Always test after applying changes!{Colors.RESET}")


def print_permanent_guide(mtu: int, interface: str = None):
    """Print guide for making MTU permanent"""
    if not interface:
        interface = "eth0"

    print(f"\n{Colors.BOLD}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  MAKING CHANGES PERMANENT{Colors.RESET}")
    print(f"{Colors.BOLD}{'═'*60}{Colors.RESET}\n")

    print(f"{Colors.BOLD}Option 1: Netplan (Ubuntu/Debian){Colors.RESET}")
    print(
        f"1. Edit: {Colors.CYAN}sudo nano /etc/netplan/00-installer-config.yaml{Colors.RESET}"
    )
    print(f"2. Add under 'ethernets: {interface}:'")
    print(f"   {Colors.GREEN}mtu: {mtu}{Colors.RESET}")
    print(f"3. Apply: {Colors.CYAN}sudo netplan apply{Colors.RESET}\n")

    print(f"{Colors.BOLD}Option 2: NetworkManager{Colors.RESET}")
    print(
        f"{Colors.CYAN}sudo nmcli connection modify {interface} 802-3-ethernet.mtu {mtu}{Colors.RESET}"
    )
    print(f"{Colors.CYAN}sudo nmcli connection up {interface}{Colors.RESET}\n")

    print(f"{Colors.BOLD}Option 3: Temporary (current session){Colors.RESET}")
    print(f"{Colors.CYAN}sudo ip link set dev {interface} mtu {mtu}{Colors.RESET}\n")

    print(f"{Colors.BOLD}Verification:{Colors.RESET}")
    print(f"{Colors.CYAN}ip link show {interface} | grep mtu{Colors.RESET}")


def run_mtu_discovery(
    target: str, interface: str = None, label: str = "Target", conservative: bool = True
) -> Tuple[Optional[int], Optional[int], Optional[TestResult]]:
    """Run complete MTU discovery process"""
    print(f"\n{Colors.BOLD}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  {label}{Colors.RESET}")
    print(f"{Colors.BOLD}{'═'*60}{Colors.RESET}")
    print(f"Target: {Colors.CYAN}{target}{Colors.RESET}")
    print(f"Mode: {'Conservative' if conservative else 'Standard'}\n")

    # Phase 1: Find theoretical maximum
    theoretical_max = find_theoretical_max(target, interface)

    if theoretical_max == 0:
        print_status(
            f"\n❌ No traffic passing - Target blocked or unreachable", Colors.RED
        )
        return None, None, None

    # Phase 2: Find stable MTU
    stable_mtu, result = find_stable_mtu(
        target, theoretical_max, interface, conservative
    )

    if stable_mtu == 0:
        print_status(f"\n❌ Could not find stable MTU", Colors.RED)
        return theoretical_max, None, None

    print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
    print(f"{Colors.GREEN}✓ Discovery Complete{Colors.RESET}")
    print(f"  Theoretical Max: {theoretical_max} bytes")
    print(f"  Stable MTU: {Colors.BOLD}{Colors.GREEN}{stable_mtu}{Colors.RESET} bytes")
    print(f"  Reliability: {result.success_rate:.2f}%")
    print(f"{Colors.BOLD}{'─'*60}{Colors.RESET}")

    return theoretical_max, stable_mtu, result


def main():
    parser = argparse.ArgumentParser(
        description="MTU Finder v5.0 - Production-Grade VPN Optimization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --iran              # Auto-detect best foreign & domestic targets
  %(prog)s 8.8.8.8             # Test specific target
  %(prog)s --iran --fast       # Faster testing (less conservative)
  %(prog)s 1.1.1.1 -i eth0     # Specify network interface
        """,
    )

    parser.add_argument("target", nargs="?", help="Manual target IP address")
    parser.add_argument(
        "--iran",
        action="store_true",
        help="Optimize for Iran: test both foreign and domestic routes",
    )
    parser.add_argument(
        "--interface", "-i", help="Network interface (e.g., eth0, wlan0)"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Faster testing with less conservative thresholds",
    )

    args = parser.parse_args()

    check_dependencies()

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(
        f"{Colors.BOLD}{Colors.CYAN}  MTU Finder v5.0 - Production Grade{Colors.RESET}"
    )
    print(f"{Colors.BOLD}{Colors.CYAN}  Optimized for VPN Tuning in Iran{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    conservative = not args.fast
    final_mtu = 0
    final_result = None

    if not args.iran:
        # Single target mode
        target = args.target if args.target else "8.8.8.8"
        _, final_mtu, final_result = run_mtu_discovery(
            target, args.interface, "Single Target Test", conservative
        )
    else:
        # Dual test mode for Iran
        print_status("🌍 Iran Optimization Mode: Dual Route Testing\n", Colors.YELLOW)

        # Test foreign route
        foreign_ip = find_best_target(FOREIGN_CANDIDATES, "FOREIGN (VPN Exit)")
        foreign_mtu = 0
        foreign_result = None

        if foreign_ip:
            _, foreign_mtu, foreign_result = run_mtu_discovery(
                foreign_ip,
                args.interface,
                "FOREIGN ROUTE (International VPN)",
                conservative,
            )

        # Test domestic route
        domestic_ip = find_best_target(IRAN_CANDIDATES, "DOMESTIC (Local Network)")
        domestic_mtu = 0
        domestic_result = None

        if domestic_ip:
            _, domestic_mtu, domestic_result = run_mtu_discovery(
                domestic_ip, args.interface, "DOMESTIC ROUTE (Iran Local)", conservative
            )

        # Determine bottleneck
        valid_results = []
        if foreign_mtu and foreign_mtu > 0:
            valid_results.append(("Foreign", foreign_mtu, foreign_result))
        if domestic_mtu and domestic_mtu > 0:
            valid_results.append(("Domestic", domestic_mtu, domestic_result))

        if valid_results:
            # Use minimum MTU (bottleneck)
            final_mtu = min(r[1] for r in valid_results)
            final_result = next(r[2] for r in valid_results if r[1] == final_mtu)

            print(f"\n{Colors.BOLD}{'═'*60}{Colors.RESET}")
            print(f"{Colors.BOLD}  BOTTLENECK ANALYSIS{Colors.RESET}")
            print(f"{Colors.BOLD}{'═'*60}{Colors.RESET}\n")

            for route, mtu, result in valid_results:
                indicator = "🔴" if mtu == final_mtu else "🟢"
                print(
                    f"{indicator} {route:12} MTU: {mtu:4} (Loss: {result.packet_loss:.2f}%)"
                )

            print(
                f"\n{Colors.CYAN}▸ Bottleneck MTU: {Colors.BOLD}{final_mtu}{Colors.RESET}"
            )
            print(f"  Using this value ensures stability on all routes.")

    # Final recommendations
    if final_mtu and final_mtu > 0:
        print_smart_calculations(final_mtu, final_result)
        print_permanent_guide(final_mtu, args.interface)

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.RESET}")
        print(
            f"{Colors.BOLD}{Colors.GREEN}  ✓ MTU Discovery Completed Successfully{Colors.RESET}"
        )
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.RESET}\n")
    else:
        print(f"\n{Colors.BOLD}{Colors.RED}{'='*60}{Colors.RESET}")
        print(
            f"{Colors.BOLD}{Colors.RED}  ❌ Could not determine stable MTU{Colors.RESET}"
        )
        print(f"{Colors.BOLD}{Colors.RED}{'='*60}{Colors.RESET}")
        print(f"\n{Colors.YELLOW}Troubleshooting:{Colors.RESET}")
        print(f"• Check network connectivity")
        print(f"• Verify firewall allows ICMP")
        print(f"• Try different target IP addresses")
        print(f"• Run with sudo if permission errors occur\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ Aborted by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error: {e}{Colors.RESET}")
        sys.exit(1)
