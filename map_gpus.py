#!/usr/bin/env python3
import subprocess
import sys
import os
import re
import yaml
import psutil
import ipaddress
import argparse
import socket
from collections import defaultdict
from pathlib import Path


# Define known vendor IDs. This list can be easily extended.
# NVIDIA: 10de, Mellanox: 15b3, Intel: 8086, Broadcom: 14e4
GPU_VENDOR_IDS = {'10de'}
NIC_VENDOR_IDS = {'15b3', '8086', '14e4'}

def get_pci_device_path(pci_addr):
    """Returns the absolute path to a PCI device in /sys."""
    return Path(f"/sys/bus/pci/devices/{pci_addr}").resolve()

def get_path_to_root(pci_path):
    """
    Traverses up the PCI device tree from a given device path
    and returns the list of parent device paths, ordered from device to root.
    """
    path_list = [pci_path]
    current_path = pci_path
    # The parent of the root complex is not in the pci/devices directory
    while "devices" in str(current_path.parent):
        current_path = current_path.parent.resolve()
        path_list.append(current_path)
    return path_list

def get_pci_distance(pci_addr1, pci_addr2):
    """
    Calculates the PCIe hop distance between two PCI devices.
    Distance is the sum of hops from each device to their Lowest Common Ancestor (LCA).
    A lower number means they are closer.
    """
    path1 = get_path_to_root(get_pci_device_path(pci_addr1))
    path2 = get_path_to_root(get_pci_device_path(pci_addr2))

    common_ancestor = None
    # Iterate from device1 upwards (path1[0]) to find the first parent that is also in path2.
    # This finds the Lowest Common Ancestor (LCA), not the highest one.
    for p in path1:
        if p in path2:
            common_ancestor = p
            break
            
    if not common_ancestor:
        # This should theoretically never happen in a single-root system
        return float('inf')

    # Hops = (steps from dev1 to ancestor) + (steps from dev2 to ancestor)
    dist1 = path1.index(common_ancestor)
    dist2 = path2.index(common_ancestor)
    
    return dist1 + dist2


def get_nic_info(hca_name, iface_name):
    """
    Retrieves NIC info such as RoCE GID list and the network interface MTU.

    Args:
        hca_name (str): The name of the Host Channel Adapter (e.g., 'mlx5_0').
        iface_name (str): The name of the network interface (e.g., 'ens3f0').

    Returns:
        dict: A dictionary containing 'gid_list' and 'mtu'.
    """
    details = {'gid_list': [], 'mtu': None}

    # --- Get GID List using ibv_devinfo ---
    if hca_name and hca_name != "N/A":
        try:
            # The '-v' flag is needed to display the GID table
            cmd = ["ibv_devinfo", "-d", hca_name, "-v"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Regex to find GIDs associated with RoCE
            # Pattern: Matches lines starting with GID[...], captures the GID value before the comma
            print("  - Warning: Assuming GID list is sorted in ibv_devinfo")
            gid_pattern = re.compile(r"^\s*GID\[\s*\d+\]:\s+(.+?),\s+RoCE\s+v\d", re.MULTILINE)
            gids = gid_pattern.findall(result.stdout)
            details['gid_list'] = [{i: gids[i]} for i in range(len(gids))]

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            # ibv_devinfo might not be installed or might fail
            print(f"  - Warning: Could not get GIDs for {hca_name}. Command failed: {e}", file=sys.stderr)

    # --- Get MTU using the 'ip' command ---
    if iface_name:
        try:
            cmd = ["ip", "addr", "show", iface_name]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Regex to find the MTU value in the output
            mtu_pattern = re.compile(r"mtu\s+(\d+)")
            match = mtu_pattern.search(result.stdout)
            if match:
                details['mtu'] = int(match.group(1))

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            print(f"  - Warning: Could not get MTU for {iface_name}. Command failed: {e}", file=sys.stderr)

    return details


def get_gpu_nic_mappings():
    """
    Determines the closest high-speed NIC to each GPU by analyzing the
    /sys filesystem, without using nvidia-smi.
    """
    print("--- Starting GPU-NIC Mapping  ---")
    pci_devices_path = Path("/sys/bus/pci/devices")
    if not pci_devices_path.is_dir():
        print(f"Error: PCI devices path not found at '{pci_devices_path}'", file=sys.stderr)
        sys.exit(1)

    # --- Step 1: Discover all relevant PCI devices (GPUs and NICs) ---
    gpus = []
    nics = []
    for device_path in pci_devices_path.iterdir():
        pci_addr = device_path.name
        try:
            vendor_id = (device_path / "vendor").read_text().strip().split('x')[-1]
            if vendor_id in GPU_VENDOR_IDS:
                gpus.append(pci_addr)
            elif vendor_id in NIC_VENDOR_IDS:
                nics.append(pci_addr)
        except FileNotFoundError:
            continue
    
    if not gpus:
        print("Error: No GPUs found. Check device drivers and hardware.", file=sys.stderr)
        sys.exit(1)
    if not nics:
        print("Error: No NICs found.", file=sys.stderr)
        sys.exit(1)
        
    print(f"\n[Step 1] Discovered {len(gpus)} GPU(s) and {len(nics)} NIC(s) from known vendors.")

    # --- Step 2: Get details for all found NICs ---
    print("\n[Step 2] Gathering details for all discovered NICs...")
    nic_details = []
    all_net_if_addrs = psutil.net_if_addrs()

    for pci_addr in nics:
        dev_path = pci_devices_path / pci_addr
        net_path = dev_path / "net"
        if not net_path.is_dir():
            continue

        for iface_path in net_path.iterdir():
            iface_name = iface_path.name
            
            try:
                operstate = (Path("/sys/class/net") / iface_name / "operstate").read_text().strip()
                if operstate != 'up':
                    # This check is useful but commented out for brevity in the final output example
                    # print(f"  - Skipping NIC {pci_addr} ({iface_name}): Interface is down ('{operstate}').")
                    continue
                
                speed_str = (Path("/sys/class/net") / iface_name / "speed").read_text().strip()
                speed = int(speed_str) if speed_str.isdigit() else 0

                hca_name = "N/A"
                ib_path = dev_path / "infiniband"
                if ib_path.is_dir():
                    hca_name = next(ib_path.iterdir(), Path("N/A")).name

                ipv4_addrs = []
                if iface_name in all_net_if_addrs:
                    for addr in all_net_if_addrs[iface_name]:
                        if addr.family == socket.AF_INET:
                            ipv4_addrs.append(addr.address)
                            
                nic_details.append({
                    "pci_addr": pci_addr,
                    "iface_name": iface_name,
                    "hca_name": hca_name,
                    "speed_mbps": speed,
                    "ipv4": ipv4_addrs,
                })
            
            except (IOError, ValueError) as e:
                print(f"  - Warning: Could not read details for {iface_name}: {e}", file=sys.stderr)

    if not nic_details:
        print("Error: No active (state 'up') NICs were found.", file=sys.stderr)
        sys.exit(1)
    
    print("  ... Found the following active NICs:")
    for nic in nic_details:
        print(f"  + {nic['pci_addr']} | Iface: {nic['iface_name']:<8} | HCA: {nic['hca_name']:<8} | Speed: {nic['speed_mbps']} Mbps | IPv4: {', '.join(nic['ipv4']) or 'None'}")


    # --- Step 3: Filter for the fastest NICs available ---
    max_speed = max(n['speed_mbps'] for n in nic_details)
    fastest_nics = [n for n in nic_details if n['speed_mbps'] == max_speed]
    
    print(f"\n[Step 3] Filtering for fastest NICs. Max speed found: {max_speed} Mbps.")
    print(f"         Found {len(fastest_nics)} NIC(s) operating at this speed.")


    # --- Step 4: Assign GPU IDs based on sorted PCI bus address ---
    gpus.sort()
    gpu_map = {i: pci for i, pci in enumerate(gpus)}
    
    print("\n[Step 4] Assigning GPU IDs based on sorted PCI Bus Address (standard enumeration):")
    for gpu_id, pci_addr in gpu_map.items():
        print(f"  - GPU {gpu_id} -> {pci_addr}")

    # --- Step 5: For each GPU, calculate distance to each fast NIC and find the closest ---
    print("\n[Step 5] Calculating PCIe distance from each GPU to each of the fastest NICs...")
    final_gpu_to_nic_map = {}
    for gpu_id, gpu_pci in gpu_map.items():
        distances = []
        for nic in fastest_nics:
            dist = get_pci_distance(gpu_pci, nic["pci_addr"])
            distances.append((dist, nic))
        
        distances.sort(key=lambda x: x[0])
        
        print(f"\n  Distances for GPU {gpu_id} ({gpu_pci}):")
        for dist, nic in distances:
            print(f"    - To NIC {nic['pci_addr']} ({nic['hca_name']}): {dist} hops")
            
        closest_nic = distances[0][1]

        nic_info = get_nic_info(closest_nic['hca_name'], closest_nic['iface_name'])

        final_gpu_to_nic_map[gpu_id] = {
            'hca_name': closest_nic['hca_name'],
            'iface_name': closest_nic['iface_name'],
            'inet_addr': closest_nic['ipv4'][-1] if closest_nic['ipv4'] else None,
            'gid_list': nic_info['gid_list'],
            'mtu': nic_info['mtu']
        }

        print(f"  ==> Closest NIC for GPU {gpu_id} is {closest_nic['hca_name']} ({closest_nic['pci_addr']})")

    print("\n--- Mapping Complete ---")
    return final_gpu_to_nic_map


if __name__ == "__main__":
    gpu_mappings = get_gpu_nic_mappings()
    
    print("\nFinal GPU -> Closest HCA Mapping:")
    print(yaml.dump(gpu_mappings, default_flow_style=False))
