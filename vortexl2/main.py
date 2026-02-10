#!/usr/bin/env python3
"""
VortexL2 - L2TPv3 Tunnel Manager

Main entry point and CLI handler.
"""

import sys
import os
import argparse
import subprocess
import signal

# Ensure we can import the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vortexl2 import __version__
from vortexl2.config import TunnelConfig, ConfigManager, GlobalConfig
from vortexl2.tunnel import TunnelManager
from vortexl2.forward import get_forward_manager, get_forward_mode, set_forward_mode, ForwardManager
from vortexl2.wireguard_manager import WireGuardManager
from vortexl2 import bandwidth_monitor
from vortexl2 import ui


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n")
    ui.console.print("[yellow]Interrupted. Goodbye![/]")
    sys.exit(0)


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        ui.show_error("VortexL2 must be run as root (use sudo)")
        sys.exit(1)


def restart_forward_daemon():
    """Restart the forward daemon service to pick up config changes.
    
    Only starts HAProxy if forward mode is 'haproxy'.
    """
    mode = get_forward_mode()
    
    # Only start HAProxy if in haproxy mode
    if mode == "haproxy":
        subprocess.run(
            "systemctl start haproxy",
            shell=True,
            capture_output=True
        )
    
    # Restart the forward daemon
    subprocess.run(
        "systemctl restart vortexl2-forward-daemon",
        shell=True,
        capture_output=True
    )


def cmd_apply():
    """
    Apply all tunnel configurations (idempotent).
    Used by systemd service on boot.
    Note: Port forwarding is managed by the forward-daemon service
    """
    manager = ConfigManager()
    tunnels = manager.get_all_tunnels()
    
    if not tunnels:
        print("VortexL2: No tunnels configured, skipping")
        return 0
    
    errors = 0
    for config in tunnels:
        if not config.is_configured():
            print(f"VortexL2: Tunnel '{config.name}' not fully configured, skipping")
            continue
        
        tunnel = TunnelManager(config)
        
        # Setup tunnel
        success, msg = tunnel.full_setup()
        print(f"Tunnel '{config.name}': {msg}")
        
        if not success:
            errors += 1
            continue
    
    # Bring up WireGuard on tunnels that have it enabled
    for config in tunnels:
        if config.wireguard_enabled and config.wireguard_peer_public_key:
            wg = WireGuardManager(config)
            if not wg.is_interface_up():
                print(f"VortexL2: Bringing up WireGuard for tunnel '{config.name}'")
                wg_ok, wg_msg = wg.enable(
                    config, config.wireguard_side, config.wireguard_peer_public_key
                )
                print(f"  WireGuard: {wg_msg.splitlines()[-1] if wg_msg else 'unknown'}")

    print("VortexL2: Tunnel setup complete. Port forwarding managed by forward-daemon service")
    return 1 if errors > 0 else 0


def handle_prerequisites():
    """Handle prerequisites installation."""
    ui.show_banner()
    ui.show_info("Installing prerequisites...")
    
    # Use temp config for prerequisites (they're system-wide)
    tunnel = TunnelManager(TunnelConfig("temp"))
    
    success, msg = tunnel.install_prerequisites()
    ui.show_output(msg, "Prerequisites Installation")
    
    if success:
        ui.show_success("Prerequisites installed successfully")
    else:
        ui.show_error(msg)
    
    ui.wait_for_enter()


def handle_create_tunnel(manager: ConfigManager):
    """Handle tunnel creation (config + start)."""
    ui.show_banner()
    
    # Ask for side first
    side = ui.prompt_tunnel_side()
    if not side:
        return
    
    # Get tunnel name
    name = ui.prompt_tunnel_name()
    if not name:
        return
    
    if manager.tunnel_exists(name):
        ui.show_error(f"Tunnel '{name}' already exists")
        ui.wait_for_enter()
        return
    
    # Create tunnel config in memory (not saved yet)
    config = manager.create_tunnel(name)
    ui.show_info(f"Tunnel '{name}' will use interface {config.interface_name}")
    
    # Configure tunnel based on side
    if not ui.prompt_tunnel_config(config, side, manager):
        # User cancelled or error - no config file was created
        ui.show_error("Configuration cancelled.")
        ui.wait_for_enter()
        return
    
    # Start tunnel
    ui.show_info("Starting tunnel...")
    tunnel = TunnelManager(config)
    success, msg = tunnel.full_setup()
    ui.show_output(msg, "Tunnel Setup")
    
    if success:
        # Only save config after successful tunnel creation
        config.save()
        ui.show_success(f"Tunnel '{name}' created and started successfully!")
    else:
        ui.show_error("Tunnel creation failed. Config not saved.")
    
    ui.wait_for_enter()


def handle_delete_tunnel(manager: ConfigManager):
    """Handle tunnel deletion (stop + remove config)."""
    ui.show_banner()
    ui.show_tunnel_list(manager)
    
    tunnels = manager.list_tunnels()
    if not tunnels:
        ui.show_warning("No tunnels to delete")
        ui.wait_for_enter()
        return
    
    selected = ui.prompt_select_tunnel(manager)
    if not selected:
        return
    
    if not ui.confirm(f"Are you sure you want to delete tunnel '{selected}'?", default=False):
        return
    
    # Stop tunnel first
    config = manager.get_tunnel(selected)
    if config:
        tunnel = TunnelManager(config)
        forward = ForwardManager(config)
        
        # Remove all port forwards from config
        if config.forwarded_ports:
            ui.show_info("Clearing port forwards from config...")
            ports_to_remove = list(config.forwarded_ports)  # Copy list since we're modifying it
            for port in ports_to_remove:
                forward.remove_forward(port)
            ui.show_success(f"Removed {len(ports_to_remove)} port forward(s) from config")
        
        # Stop tunnel
        ui.show_info("Stopping tunnel...")
        success, msg = tunnel.full_teardown()
        ui.show_output(msg, "Tunnel Teardown")
    
    # Delete config
    manager.delete_tunnel(selected)
    ui.show_success(f"Tunnel '{selected}' deleted")
    ui.wait_for_enter()


def handle_list_tunnels(manager: ConfigManager):
    """Handle listing all tunnels."""
    ui.show_banner()
    ui.show_tunnel_list(manager)
    ui.wait_for_enter()


def handle_forwards_menu(manager: ConfigManager):
    """Handle port forwards submenu."""
    ui.show_banner()
    
    # Select tunnel for forwards
    config = ui.prompt_select_tunnel_for_forwards(manager)
    if not config:
        return
    
    while True:
        ui.show_banner()
        
        # Get current forward mode
        current_mode = get_forward_mode()
        
        # Get the appropriate manager based on mode
        forward = get_forward_manager(config)
        
        ui.console.print(f"[bold]Managing forwards for tunnel: [magenta]{config.name}[/][/]\n")
        
        if current_mode == "none":
            ui.console.print("[yellow]⚠ Port forwarding is DISABLED. Select option 6 to enable.[/]\n")
        else:
            ui.console.print(f"[green]Forward mode: {current_mode.upper()}[/]\n")
        
        # Show current forwards if manager is available
        if forward:
            forwards = forward.list_forwards()
            if forwards:
                ui.show_forwards_list(forwards)
        else:
            # Show config-only forwards when mode is none
            from vortexl2.haproxy_manager import HAProxyManager
            temp_manager = HAProxyManager(config)
            forwards = temp_manager.list_forwards()
            if forwards:
                ui.show_forwards_list(forwards)
        
        choice = ui.show_forwards_menu(current_mode)
        
        if choice == "0":
            break
        elif choice == "1":
            # Add forwards - require mode selection first
            if current_mode == "none":
                ui.show_error("Please select a port forward mode first! (Option 6)")
            else:
                ports = ui.prompt_ports()
                if ports:
                    # Always use HAProxyManager to add to config (it just updates YAML)
                    from vortexl2.haproxy_manager import HAProxyManager
                    config_manager = HAProxyManager(config)
                    success, msg = config_manager.add_multiple_forwards(ports)
                    ui.show_output(msg, "Add Forwards to Config")
                    restart_forward_daemon()
                    ui.show_success("Forwards added. Daemon restarted to apply changes.")
            ui.wait_for_enter()
        elif choice == "2":
            # Remove forwards (from config)
            ports = ui.prompt_ports()
            if ports:
                from vortexl2.haproxy_manager import HAProxyManager
                config_manager = HAProxyManager(config)
                success, msg = config_manager.remove_multiple_forwards(ports)
                ui.show_output(msg, "Remove Forwards from Config")
                if current_mode != "none":
                    restart_forward_daemon()
                    ui.show_success("Forwards removed. Daemon restarted to apply changes.")
            ui.wait_for_enter()
        elif choice == "3":
            # List forwards (already shown above)
            ui.wait_for_enter()
        elif choice == "4":
            # Restart daemon
            if current_mode == "none":
                ui.show_error("Port forwarding is disabled. Enable a mode first.")
            else:
                restart_forward_daemon()
                ui.show_success("Forward daemon restarted.")
            ui.wait_for_enter()
        elif choice == "5":
            # Validate and reload
            if current_mode == "none":
                ui.show_error("Port forwarding is disabled. Enable a mode first.")
            elif forward:
                ui.show_info("Validating configuration and reloading...")
                success, msg = forward.validate_and_reload()
                ui.show_output(msg, "Validate & Reload")
                if success:
                    ui.show_success("Reloaded successfully")
                else:
                    ui.show_error(msg)
            ui.wait_for_enter()
        elif choice == "6":
            # Change forward mode
            mode_choice = ui.show_forward_mode_menu(current_mode)
            new_mode = None
            if mode_choice == "1":
                new_mode = "none"
            elif mode_choice == "2":
                new_mode = "haproxy"
            elif mode_choice == "3":
                new_mode = "socat"
            
            if new_mode and new_mode != current_mode:
                # Stop and cleanup current mode before switching
                if current_mode == "haproxy":
                    ui.show_info("Stopping HAProxy forwards...")
                    if forward:
                        import asyncio
                        try:
                            asyncio.run(forward.stop_all_forwards())
                            ui.show_success("✓ HAProxy forwards stopped")
                        except Exception as e:
                            ui.show_warning(f"Could not stop HAProxy gracefully: {e}")
                    # Always stop HAProxy service when switching away from haproxy mode
                    subprocess.run("systemctl stop haproxy", shell=True, capture_output=True)
                    subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True, capture_output=True)
                
                elif current_mode == "socat":
                    ui.show_info("Stopping Socat forwards...")
                    try:
                        from vortexl2.socat_manager import stop_all_socat
                        success, msg = stop_all_socat()
                        if success:
                            ui.show_success(f"✓ {msg}")
                        else:
                            ui.show_warning(msg)
                    except Exception as e:
                        ui.show_warning(f"Could not stop Socat gracefully: {e}")
                    subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True, capture_output=True)
                
                # Set new mode
                set_forward_mode(new_mode)
                ui.show_success(f"Forward mode changed to: {new_mode.upper()}")
                
                # If enabling a mode, offer to start
                if new_mode != "none":
                    if ui.Confirm.ask("Start port forwarding now?", default=True):
                        restart_forward_daemon()
                        ui.show_success("Forward daemon started.")
                else:
                    # Make sure everything is stopped when going to none
                    subprocess.run("systemctl stop haproxy", shell=True, capture_output=True)
                    subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True, capture_output=True)
                    ui.show_info("All port forwarding stopped.")
            ui.wait_for_enter()
        elif choice == "7":
            # Setup auto-restart cron
            from vortexl2.cron_manager import (
                get_auto_restart_status,
                add_auto_restart_cron,
                remove_auto_restart_cron
            )
            
            enabled, status = get_auto_restart_status()
            ui.console.print(f"\n[bold]Current status:[/] {status}\n")
            
            ui.console.print("[bold white]Auto-Restart Setup:[/]")
            ui.console.print("  Configure automatic restart for HAProxy port forwarding daemon")
            ui.console.print("  (Note: This only restarts port forwarding, NOT tunnels)\n")
            ui.console.print("[bold cyan]Options:[/]")
            ui.console.print("  [bold cyan][1][/] Enable with custom interval")
            ui.console.print("  [bold cyan][2][/] Disable auto-restart")
            ui.console.print("  [bold cyan][0][/] Cancel\n")
            
            cron_choice = ui.Prompt.ask("[bold cyan]Select option[/]", default="0")
            
            if cron_choice == "1":
                ui.console.print("\n[dim]Enter restart interval in minutes (e.g., 30, 60, 120)[/]")
                ui.console.print("[dim]Recommended: 60 (every hour), 30 (every 30 min)[/]")
                interval_input = ui.Prompt.ask("[bold cyan]Interval (minutes)[/]", default="60")
                
                try:
                    interval = int(interval_input)
                    if interval < 1:
                        ui.show_error("Interval must be at least 1 minute")
                    elif interval > 1440:
                        ui.show_error("Interval cannot exceed 1440 minutes (24 hours)")
                    else:
                        success, msg = add_auto_restart_cron(interval)
                        if success:
                            ui.show_success(msg)
                        else:
                            ui.show_error(msg)
                except ValueError:
                    ui.show_error(f"Invalid interval: {interval_input}. Must be a number.")
            elif cron_choice == "2":
                success, msg = remove_auto_restart_cron()
                if success:
                    ui.show_success(msg)
                else:
                    ui.show_error(msg)
            
            ui.wait_for_enter()


def handle_wireguard_menu(manager: ConfigManager):
    """Handle WireGuard encryption submenu."""
    while True:
        ui.show_banner()

        # Show current WireGuard status summary
        wg = WireGuardManager()
        status = wg.get_status()
        if status["interface_up"]:
            ui.console.print("[bold green]WireGuard: ACTIVE[/]\n")
        elif status["installed"]:
            ui.console.print("[bold yellow]WireGuard: INSTALLED but INACTIVE[/]\n")
        else:
            ui.console.print("[bold red]WireGuard: NOT INSTALLED[/]\n")

        choice = ui.show_wireguard_menu()

        if choice == "0":
            break
        elif choice == "1":
            # Install/Enable Secure Layer
            _handle_wireguard_enable(manager)
        elif choice == "2":
            # Disable Secure Layer
            _handle_wireguard_disable(manager)
        elif choice == "3":
            # View Status/Keys
            ui.show_banner()
            status = WireGuardManager.get_status()
            ui.show_wireguard_status(status)
            ui.wait_for_enter()
        else:
            ui.show_warning("Invalid option")
            ui.wait_for_enter()


def _reload_haproxy_after_wg_change():
    """Regenerate and reload HAProxy config after WireGuard enable/disable.

    This ensures port forwards point to the correct backend IP
    (WireGuard peer IP when encrypted, L2TP IP when direct).
    """
    from vortexl2.forward import get_forward_mode
    if get_forward_mode() in ("haproxy", "socat"):
        from vortexl2.haproxy_manager import HAProxyManager
        mgr = HAProxyManager(None)
        ok, msg = mgr.validate_and_reload()
        if ok:
            ui.show_success("Port forwards updated to use new routing path")
        else:
            ui.show_warning(f"Could not reload port forwards: {msg}")


def _handle_wireguard_enable(manager: ConfigManager):
    """Handle enabling WireGuard encryption layer."""
    ui.show_banner()
    ui.console.print("[bold white]Enable Secure Encryption Layer (WireGuard)[/]\n")

    # Step 1: Check/install wireguard-tools
    wg = WireGuardManager()
    if not wg.check_wireguard_installed():
        ui.show_info("WireGuard is not installed. Installing...")
        ok, msg = wg.install_wireguard()
        ui.show_output(msg, "WireGuard Installation")
        if not ok:
            ui.show_error("WireGuard installation failed.")
            ui.wait_for_enter()
            return
        ui.show_success("WireGuard installed")
    else:
        ui.show_success("WireGuard is already installed")

    # Step 2: Generate keys (idempotent)
    ok, msg = wg.generate_keys()
    keys = wg.get_keys()
    if not keys["public_key"]:
        ui.show_error("Failed to generate WireGuard keys")
        ui.wait_for_enter()
        return

    ui.console.print(f"\n[bold white]Your Public Key:[/] [bold green]{keys['public_key']}[/]")
    ui.console.print("[dim]Share this key with the peer server.[/]\n")

    # Step 3: Select tunnel
    config = ui.prompt_select_tunnel_for_forwards(manager)
    if not config:
        ui.wait_for_enter()
        return

    # Step 4: Select side
    side = ui.prompt_wireguard_side()
    if not side:
        ui.wait_for_enter()
        return

    # Step 5: Get peer public key
    peer_key = ui.prompt_peer_public_key()
    if not peer_key:
        ui.wait_for_enter()
        return

    # Step 6: Enable WireGuard
    ui.show_info("Enabling WireGuard encryption layer...")
    ok, msg = wg.enable(config, side, peer_key)
    ui.show_output(msg, "WireGuard Setup")

    if ok:
        # Update L2TP MTU to 1450 for WireGuard compatibility
        ui.show_info(f"Updating L2TP MTU on {config.interface_name} to 1450...")
        mtu_ok, mtu_msg = WireGuardManager.update_l2tp_mtu(config.interface_name)
        if mtu_ok:
            ui.show_success(mtu_msg)
        else:
            ui.show_warning(mtu_msg)

        ui.show_success("WireGuard encryption layer is now ACTIVE!")

        # Regenerate HAProxy config so port forwards route through WireGuard IP
        _reload_haproxy_after_wg_change()

        ui.console.print("\n[dim]Port forwards will now route through the encrypted WireGuard tunnel.[/]")
    else:
        ui.show_error("Failed to enable WireGuard encryption layer")

    ui.wait_for_enter()


def _handle_wireguard_disable(manager: ConfigManager):
    """Handle disabling WireGuard encryption layer."""
    ui.show_banner()

    wg = WireGuardManager()
    if not wg.is_interface_up():
        ui.show_warning("WireGuard is not currently active")
        ui.wait_for_enter()
        return

    if not ui.confirm("Disable WireGuard encryption layer?", default=False):
        return

    # Find tunnels with WireGuard enabled and update them
    tunnels = manager.get_all_tunnels()
    for config in tunnels:
        if config.wireguard_enabled:
            wg.disable(config)
            ui.show_info(f"Disabled WireGuard for tunnel '{config.name}'")

    # If no tunnel had it enabled, still tear down the interface
    if not any(t.wireguard_enabled for t in tunnels):
        wg.disable()

    ui.show_success("WireGuard encryption layer disabled")

    # Regenerate HAProxy config so port forwards revert to L2TP IP
    _reload_haproxy_after_wg_change()

    ui.wait_for_enter()


def handle_bandwidth_menu(manager: ConfigManager):
    """Handle bandwidth & performance monitor submenu."""
    while True:
        ui.show_banner()
        choice = ui.show_bandwidth_menu()

        if choice == "0":
            break
        elif choice == "1":
            _handle_live_monitor(manager)
        elif choice == "2":
            _handle_snapshot(manager)
        elif choice == "3":
            _handle_performance_analysis(manager)
        elif choice == "4":
            _handle_auto_optimize(manager)
        elif choice == "5":
            _handle_dns_cache_setup(manager)
        elif choice == "6":
            _handle_mtu_finder(manager)
        else:
            ui.show_warning("Invalid option")
            ui.wait_for_enter()


def _handle_live_monitor(manager: ConfigManager):
    """Run the live bandwidth monitor with Rich Live display."""
    from rich.live import Live
    import time

    tunnels = manager.get_all_tunnels()
    if not tunnels:
        ui.show_warning("No tunnels configured. Create a tunnel first.")
        ui.wait_for_enter()
        return

    # Setup iptables accounting for per-port monitoring
    all_ports = []
    for t in tunnels:
        all_ports.extend(t.forwarded_ports)
    if all_ports:
        bandwidth_monitor.setup_port_accounting(all_ports)

    ui.console.print("\n[bold yellow]Starting live monitor... Press Ctrl+C to stop.[/]\n")
    time.sleep(0.5)

    prev_stats = None
    start_time = time.time()
    interval = 1.0

    try:
        with Live(console=ui.console, refresh_per_second=1) as live:
            while True:
                current, bw = bandwidth_monitor.live_monitor_tick(
                    tunnels, prev_stats, interval
                )
                elapsed = int(time.time() - start_time)
                table = ui.show_bandwidth_live(bw, elapsed)
                live.update(table)
                prev_stats = current
                time.sleep(interval)
    except KeyboardInterrupt:
        pass

    ui.console.print("\n[dim]Monitor stopped.[/]")
    ui.wait_for_enter()


def _handle_snapshot(manager: ConfigManager):
    """Show a one-time snapshot of all layer statistics."""
    ui.show_banner()

    tunnels = manager.get_all_tunnels()
    if not tunnels:
        ui.show_warning("No tunnels configured.")
        ui.wait_for_enter()
        return

    # Setup accounting
    all_ports = []
    for t in tunnels:
        all_ports.extend(t.forwarded_ports)
    if all_ports:
        bandwidth_monitor.setup_port_accounting(all_ports)

    stats = bandwidth_monitor.get_all_layer_stats(tunnels)
    ui.show_snapshot(stats)
    ui.wait_for_enter()


def _handle_performance_analysis(manager: ConfigManager):
    """Run bottleneck analysis and show recommendations."""
    ui.show_banner()
    ui.console.print("[bold white]Analyzing performance...[/]\n")

    tunnels = manager.get_all_tunnels()
    findings = bandwidth_monitor.analyze_bottleneck(tunnels)
    ui.show_performance_analysis(findings)
    ui.wait_for_enter()


def _handle_auto_optimize(manager: ConfigManager):
    """Preview and apply TCP/network optimizations."""
    from rich.prompt import Confirm

    ui.show_banner()
    ui.console.print("[bold white]TCP & Network Auto-Optimizer[/]\n")

    # Show preview
    changes = bandwidth_monitor.get_optimization_preview()
    ui.show_optimization_preview(changes)

    needs_change = sum(1 for _, _, v in changes if v != "(already set)")
    if needs_change == 0:
        ui.console.print("\n[bold green]All parameters are already optimal![/]")
        ui.wait_for_enter()
        return

    # Confirm
    ui.console.print("")
    if not Confirm.ask("[bold yellow]Apply these optimizations?[/]", default=True):
        ui.show_info("Cancelled.")
        ui.wait_for_enter()
        return

    # Apply
    ok, msg = bandwidth_monitor.apply_tcp_optimizations()
    if ok:
        ui.show_success(msg)
        ui.console.print("\n[bold white]Re-running analysis to verify...[/]\n")
        tunnels = manager.get_all_tunnels()
        findings = bandwidth_monitor.analyze_bottleneck(tunnels)
        ui.show_performance_analysis(findings)
    else:
        ui.show_error(msg)

    ui.wait_for_enter()


def _handle_mtu_finder(manager: ConfigManager):
    """Manual MTU/MSS configuration — user enters values, we apply them."""
    from rich.prompt import Confirm, Prompt
    from vortexl2 import mtu_finder

    ui.show_banner()
    ui.console.print("[bold white]MTU & MSS Configuration[/]\n")

    tunnels = manager.get_all_tunnels()
    if not tunnels:
        ui.show_warning("No tunnels configured. Create a tunnel first.")
        ui.wait_for_enter()
        return

    tunnel = tunnels[0]
    wg_enabled = getattr(tunnel, 'wireguard_enabled', False)
    l2tp_iface = tunnel.interface_name

    # Show current values
    ui.console.print("[bold white]Current settings:[/]")
    cur_l2tp = mtu_finder.get_current_mtu(l2tp_iface)
    if cur_l2tp:
        ui.console.print(f"  {l2tp_iface} MTU: [cyan]{cur_l2tp}[/]")
    else:
        ui.console.print(f"  {l2tp_iface} MTU: [dim]not available[/]")
    cur_wg = mtu_finder.get_current_mtu("wg_vortex")
    if wg_enabled and cur_wg:
        ui.console.print(f"  wg_vortex MTU: [cyan]{cur_wg}[/]")
    elif wg_enabled:
        ui.console.print(f"  wg_vortex MTU: [dim]not available[/]")
    ui.console.print(f"  WireGuard: [cyan]{'Enabled' if wg_enabled else 'Disabled'}[/]")
    ui.console.print("")

    ui.console.print("[dim]Run mtu-finder.py on your server to discover optimal values.[/]\n")

    # Prompt for L2TP MTU
    l2tp_mtu_str = Prompt.ask(
        f"[bold cyan]Enter L2TP MTU for {l2tp_iface}[/]",
        default=str(cur_l2tp) if cur_l2tp else "1450",
    )
    try:
        l2tp_mtu = int(l2tp_mtu_str)
        if not (1280 <= l2tp_mtu <= 9000):
            ui.show_error("MTU must be between 1280 and 9000.")
            ui.wait_for_enter()
            return
    except ValueError:
        ui.show_error("Invalid number.")
        ui.wait_for_enter()
        return

    # Prompt for WireGuard MTU (if enabled)
    wg_mtu = 0
    if wg_enabled:
        wg_mtu_str = Prompt.ask(
            "[bold cyan]Enter WireGuard MTU for wg_vortex[/]",
            default=str(cur_wg) if cur_wg else "1380",
        )
        try:
            wg_mtu = int(wg_mtu_str)
            if not (1280 <= wg_mtu <= 9000):
                ui.show_error("MTU must be between 1280 and 9000.")
                ui.wait_for_enter()
                return
        except ValueError:
            ui.show_error("Invalid number.")
            ui.wait_for_enter()
            return

    # Prompt for TCP MSS
    inner_mtu = wg_mtu if wg_enabled else l2tp_mtu
    default_mss = inner_mtu - 40  # subtract TCP/IP headers
    mss_str = Prompt.ask(
        "[bold cyan]Enter TCP MSS[/]",
        default=str(default_mss),
    )
    try:
        tcp_mss = int(mss_str)
        if not (500 <= tcp_mss <= 9000):
            ui.show_error("MSS must be between 500 and 9000.")
            ui.wait_for_enter()
            return
    except ValueError:
        ui.show_error("Invalid number.")
        ui.wait_for_enter()
        return

    # Confirm
    ui.console.print("")
    ui.console.print("[bold white]Will apply:[/]")
    ui.console.print(f"  {l2tp_iface} MTU → [green]{l2tp_mtu}[/]")
    if wg_enabled:
        ui.console.print(f"  wg_vortex MTU → [green]{wg_mtu}[/]")
    ui.console.print(f"  TCP MSS clamp → [green]{tcp_mss}[/]")
    ui.console.print("")

    if not Confirm.ask("[bold yellow]Apply these settings?[/]", default=True):
        ui.show_info("Cancelled.")
        ui.wait_for_enter()
        return

    # Apply
    ui.console.print("\n[bold white]Applying...[/]\n")
    results = mtu_finder.apply_mtu_mss(
        l2tp_mtu=l2tp_mtu,
        wg_mtu=wg_mtu,
        tcp_mss=tcp_mss,
        l2tp_interface=l2tp_iface,
        wg_interface="wg_vortex",
    )
    ui.show_mtu_apply_results(results)

    all_ok = all(ok for _, ok, _ in results)
    if all_ok:
        ui.show_success("All MTU/MSS settings applied successfully!")
    else:
        ui.show_warning("Some settings could not be applied — see details above.")

    ui.wait_for_enter()


def _handle_dns_cache_setup(manager: ConfigManager):
    """DNS cache submenu — view status or setup/reconfigure."""
    while True:
        ui.show_banner()
        ui.console.print("[bold white]DNS Cache[/]\n")

        # Always show current status at the top
        status = bandwidth_monitor.get_dns_cache_status()
        ui.show_dns_cache_status(status)
        ui.console.print("")

        choice = ui.show_dns_submenu()

        if choice == "0":
            break
        elif choice == "1":
            # Already shown above, just wait
            ui.wait_for_enter()
        elif choice == "2":
            _run_dns_setup(manager)
        else:
            ui.show_warning("Invalid option")
            ui.wait_for_enter()


def _run_dns_setup(manager: ConfigManager):
    """Run the actual DNS cache setup flow."""
    from rich.prompt import Confirm

    ui.show_banner()
    ui.console.print("[bold white]DNS Cache Setup[/]\n")

    # Detect side from tunnel configs
    tunnels = manager.get_all_tunnels()
    side = None
    wireguard_ip = None
    wireguard_peer_ip = None

    for t in tunnels:
        wg_side = getattr(t, 'wireguard_side', None)
        if wg_side:
            side = wg_side
            # Strip CIDR notation (e.g. 10.8.0.2/24 -> 10.8.0.2)
            raw_ip = getattr(t, 'wireguard_ip', None)
            wireguard_ip = raw_ip.split('/')[0] if raw_ip else None
            wireguard_peer_ip = getattr(t, 'wireguard_peer_ip', None)
            break

    if not side:
        # Ask the user
        ui.console.print("[yellow]Could not detect server role from tunnel config.[/]")
        ui.console.print("[bold white]Which server is this?[/]")
        ui.console.print("  [bold cyan][1][/] [green]IRAN[/]  (clients connect here, forwards to Kharej)")
        ui.console.print("  [bold cyan][2][/] [magenta]KHAREJ[/] (runs V2Ray/services, has internet access)")
        ui.console.print("  [bold cyan][0][/] Cancel")
        choice = ui.Prompt.ask("\n[bold cyan]Select[/]", default="0")
        if choice == "1":
            side = "IRAN"
            wireguard_peer_ip = "10.8.0.2"
        elif choice == "2":
            side = "KHAREJ"
            wireguard_ip = "10.8.0.2"
        else:
            return

    if side == "IRAN":
        peer_ip = wireguard_peer_ip or "10.8.0.2"
        ui.console.print(f"[bold green]IRAN server[/] — Setting up DNS cache")
        ui.console.print(f"  Cache misses will forward to [cyan]{peer_ip}:53[/] (through tunnel)")
        ui.console.print("")

        if not Confirm.ask("[bold yellow]Install and configure dnsmasq?[/]", default=True):
            ui.show_info("Cancelled.")
            ui.wait_for_enter()
            return

        ok, msg, instructions = bandwidth_monitor.setup_dns_cache_iran(peer_ip)

    elif side == "KHAREJ":
        wg_ip = wireguard_ip or "10.8.0.2"
        ui.console.print(f"[bold magenta]KHAREJ server[/] — Setting up DNS resolver")
        ui.console.print(f"  Will listen on [cyan]{wg_ip}:53[/] (tunnel-only, not public)")

        # Check for existing DNS server
        existing = bandwidth_monitor.detect_existing_dns()
        if existing and existing["name"] not in ("systemd-resolved", "dnsmasq"):
            ui.console.print(f"\n[bold yellow]Detected: {existing['name']} on port 53[/]")
            if Confirm.ask(f"[bold]Use {existing['name']} as the resolver? (just print config instructions)[/]",
                           default=True):
                ok, msg, instructions = bandwidth_monitor.setup_dns_cache_kharej(wg_ip)
            else:
                ui.show_info("Cancelled.")
                ui.wait_for_enter()
                return
        else:
            ui.console.print("")
            if not Confirm.ask("[bold yellow]Install and configure dnsmasq?[/]", default=True):
                ui.show_info("Cancelled.")
                ui.wait_for_enter()
                return
            ok, msg, instructions = bandwidth_monitor.setup_dns_cache_kharej(wg_ip)
    else:
        ui.show_error(f"Unknown side: {side}")
        ui.wait_for_enter()
        return

    if ok:
        ui.show_success(msg)
        ui.show_dns_instructions(instructions)
    else:
        ui.show_error(msg)

    ui.wait_for_enter()


def handle_logs(manager: ConfigManager):
    """Handle log viewing."""
    ui.show_banner()
    
    services = [
        "vortexl2-tunnel.service",
        "vortexl2-forward-daemon.service",
        "vortexl2-wireguard.service",
    ]
    
    for service in services:
        result = subprocess.run(
            f"journalctl -u {service} -n 20 --no-pager",
            shell=True,
            capture_output=True,
            text=True
        )
        output = result.stdout or result.stderr or "No logs available"
        ui.show_output(output, f"Logs: {service}")
    
    ui.wait_for_enter()


def main_menu():
    """Main interactive menu loop."""
    check_root()
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Clear screen before starting
    ui.clear_screen()
    
    # Initialize config manager
    manager = ConfigManager()
    
    while True:
        ui.show_banner()
        choice = ui.show_main_menu()
        
        try:
            if choice == "0":
                ui.console.print("\n[bold green]Goodbye![/]\n")
                break
            elif choice == "1":
                handle_prerequisites()
            elif choice == "2":
                handle_create_tunnel(manager)
            elif choice == "3":
                handle_delete_tunnel(manager)
            elif choice == "4":
                handle_list_tunnels(manager)
            elif choice == "5":
                handle_forwards_menu(manager)
            elif choice == "6":
                handle_wireguard_menu(manager)
            elif choice == "7":
                handle_bandwidth_menu(manager)
            elif choice == "8":
                handle_logs(manager)
            else:
                ui.show_warning("Invalid option")
                ui.wait_for_enter()
        except KeyboardInterrupt:
            ui.console.print("\n[yellow]Interrupted[/]")
            continue
        except Exception as e:
            ui.show_error(f"Error: {e}")
            ui.wait_for_enter()


def main():
    """CLI entry point."""
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="VortexL2 - L2TPv3 Tunnel Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  (none)     Open interactive management panel
  apply      Apply all tunnel configurations (used by systemd)

Examples:
  sudo vortexl2           # Open management panel
  sudo vortexl2 apply     # Apply all tunnels (for systemd)
        """
    )
    parser.add_argument(
        'command',
        nargs='?',
        choices=['apply'],
        help='Command to run'
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'VortexL2 {__version__}'
    )
    
    args = parser.parse_args()
    
    if args.command == 'apply':
        check_root()
        sys.exit(cmd_apply())
    else:
        main_menu()


if __name__ == "__main__":
    main()
