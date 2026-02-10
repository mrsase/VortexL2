"""
VortexL2 MTU & MSS Applier

Applies user-specified MTU and MSS values to the tunnel network interfaces
(L2TP, WireGuard) and sets up iptables MSS clamping.

Use the standalone mtu-finder.py script to discover optimal values first.
"""

import logging
import subprocess
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


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
# Apply MTU/MSS to running system
# ------------------------------------------------------------------

def apply_mtu_mss(
    l2tp_mtu: int,
    wg_mtu: int,
    tcp_mss: int,
    l2tp_interface: str = "l2tpeth0",
    wg_interface: str = "wg_vortex",
) -> List[Tuple[str, bool, str]]:
    """Apply MTU and MSS clamp to the system.

    Args:
        l2tp_mtu: MTU to set on the L2TP interface.
        wg_mtu: MTU to set on the WireGuard interface (0 to skip).
        tcp_mss: TCP MSS value for iptables clamping.
        l2tp_interface: L2TP interface name.
        wg_interface: WireGuard interface name.

    Returns list of (description, success, detail).
    """
    results: List[Tuple[str, bool, str]] = []

    # 1. Set L2TP interface MTU
    ok, _, err = _run(f"ip link set {l2tp_interface} mtu {l2tp_mtu}")
    results.append((
        f"Set {l2tp_interface} MTU → {l2tp_mtu}",
        ok,
        err if not ok else "applied",
    ))

    # 2. Set WireGuard interface MTU (if applicable)
    if wg_mtu > 0:
        ok, _, err = _run(f"ip link set {wg_interface} mtu {wg_mtu}")
        results.append((
            f"Set {wg_interface} MTU → {wg_mtu}",
            ok,
            err if not ok else "applied",
        ))

        # 3. MSS clamp on WireGuard interface
        for direction in ("-o", "-i"):
            # Remove existing rule first (ignore errors)
            _run(
                f"iptables -t mangle -D FORWARD {direction} {wg_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {tcp_mss}"
            )
            ok, _, err = _run(
                f"iptables -t mangle -A FORWARD {direction} {wg_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {tcp_mss}"
            )
            label = "outbound" if direction == "-o" else "inbound"
            results.append((
                f"MSS clamp {label} on {wg_interface} → {tcp_mss}",
                ok,
                err if not ok else "applied",
            ))
    else:
        # No WireGuard — clamp MSS on L2TP interface
        for direction in ("-o", "-i"):
            _run(
                f"iptables -t mangle -D FORWARD {direction} {l2tp_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {tcp_mss}"
            )
            ok, _, err = _run(
                f"iptables -t mangle -A FORWARD {direction} {l2tp_interface} "
                f"-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {tcp_mss}"
            )
            label = "outbound" if direction == "-o" else "inbound"
            results.append((
                f"MSS clamp {label} on {l2tp_interface} → {tcp_mss}",
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
