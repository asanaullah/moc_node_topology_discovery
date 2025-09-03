#!/usr/bin/env python3
import os
import sys
import socket
import psutil
from pathlib import Path

def _get_all_nic_details():
    """
    Gathers detailed information for all network interfaces by scanning /sys
    and using psutil. Avoids external commands.

    Returns:
        A list of dictionaries, where each dictionary represents a NIC
        and contains its name, inet address, hca, speed, and status.
    """
    # 1. Map interface names to HCA names by scanning /sys
    iface_to_hca = {}
    infiniband_path = Path("/sys/class/infiniband")
    if infiniband_path.exists():
        for hca_dir in infiniband_path.iterdir():
            hca_name = hca_dir.name
            net_path = hca_dir / "device/net"
            if net_path.exists():
                for iface_dir in net_path.iterdir():
                    iface_to_hca[iface_dir.name] = hca_name

    # 2. Get interface addresses, stats, and combine with HCA info
    all_nics = []
    if_addrs = psutil.net_if_addrs()
    if_stats = psutil.net_if_stats()

    for iface_name, addrs in if_addrs.items():
        inet_addr = None
        for addr in addrs:
            if addr.family == socket.AF_INET:
                inet_addr = addr.address
                break # Found the IPv4 address

        stats = if_stats.get(iface_name)
        if stats:
            all_nics.append({
                'iface_name': iface_name,
                'inet_address': inet_addr,
                'hca_name': iface_to_hca.get(iface_name), # Will be None if not an IB device
                'speed': stats.speed,
                'is_up': stats.isup,
            })
    return all_nics


def discover_control_interface():
    """
    Discovers the most likely control interface based on a defined priority.

    Discovery Logic:
    1. If an SSH session is active, use the interface associated with that session.
    2. Otherwise, find all active, non-loopback network interfaces and select the
       one with the slowest speed.

    Returns:
        A dictionary containing the 'iface_name', 'hca_name', and 'inet_address'
        of the discovered control interface.

    Raises:
        RuntimeError: If no suitable control interface can be determined.
    """
    print ("--- Starting Control NIC Discovery ---")

    all_nics = _get_all_nic_details()

    # Priority 1: Use the interface from the active SSH session
    ssh_connection = os.environ.get('SSH_CONNECTION')
    if ssh_connection:
        try:
            # Format is "client_ip client_port server_ip server_port"
            server_ip = ssh_connection.split()[2]
            for nic in all_nics:
                if nic['inet_address'] == server_ip:
                    print(
                        f"INFO: Found control interface via active SSH session on "
                        f"'{nic['iface_name']}' ({nic['inet_address']}).",
                        file=sys.stderr
                    )
                    return {
                        'iface_name': nic['iface_name'],
                        'hca_name': nic['hca_name'],
                        'inet_address': nic['inet_address'],
                    }
        except IndexError:
            # Handle malformed SSH_CONNECTION variable gracefully
            print("WARN: SSH_CONNECTION environment variable is malformed. Skipping.", file=sys.stderr)


    # Priority 2: Find the slowest, active, non-loopback NIC
    active_nics = []
    for nic in all_nics:
        # Filter for interfaces that are up, not loopback, and have an IPv4 address
        if nic['is_up'] and nic['iface_name'] != 'lo' and nic['inet_address']:
            active_nics.append(nic)

    if not active_nics:
        raise RuntimeError("Could not determine a control interface: No active network interfaces found.")

    # Sort by speed to find the slowest one
    slowest_nic = min(active_nics, key=lambda x: x['speed'])
    print(
        f"INFO: No SSH session found. Selected slowest active interface "
        f"'{slowest_nic['iface_name']}' ({slowest_nic['inet_address']}) "
        f"with speed {slowest_nic['speed']} Mbps.",
        file=sys.stderr
    )
    return {
        'iface_name': slowest_nic['iface_name'],
        'hca_name': slowest_nic['hca_name'],
        'inet_address': slowest_nic['inet_address'],
    }


if __name__ == "__main__":
    try:
        control_interface = discover_control_interface()
        # Using a simple print format for the dictionary output
        print(control_interface)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)