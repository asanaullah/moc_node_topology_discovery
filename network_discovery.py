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
from map_gpus import get_gpu_nic_mappings
from map_control import discover_control_interface

def find_longest_common_prefix(strs):
    """
    Finds the longest common starting substring from a list of strings.
    For example: ['eno1p1', 'eno1p2', 'eno2'] -> 'eno'
                 ['mlx5_0', 'mlx5_1'] -> 'mlx5_'
    """
    if not strs:
        return ""
    if len(strs) == 1:
        return strs[0]

    # Sort the list to find the lexicographically smallest and largest strings.
    # The common prefix will be the common prefix of these two strings.
    s1 = min(strs)
    s2 = max(strs)
    
    for i, c in enumerate(s1):
        if i >= len(s2) or c != s2[i]:
            return s1[:i]
    return s1

def main():
    parser = argparse.ArgumentParser(
        description="Automatically discover GPU/network topology and generate a YAML configuration file.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-o', '--output', type=str, help='Path to the output YAML file. Prints to stdout if not specified.')
    args = parser.parse_args()

    control_iface_details = discover_control_interface()
    gpu_map = get_gpu_nic_mappings()

    data_section = {}
    sorted_gpu_ids = sorted(gpu_map.keys())
    for gpu_id in sorted_gpu_ids:
        hca_name = gpu_map[gpu_id]['hca_name']
        iface_name = gpu_map[gpu_id]['iface_name']
        inet_addr = gpu_map[gpu_id]['inet_addr']
        gid_list = gpu_map[gpu_id]['gid_list']
        mtu = gpu_map[gpu_id]['mtu']
        gpu_key = f"gpu_{gpu_id}"
        data_section[gpu_key] = {'id': gpu_id, 'inet': inet_addr, 'name': iface_name, 'hca': hca_name, 'mtu': mtu, 'GIDs': gid_list}

    all_ifnames = []
    all_hcas = []

    # 1. Get ifname from the control interface
    if control_iface_details and 'ifname' in control_iface_details:
        all_ifnames.append(control_iface_details['ifname'])
    
    # 2. Get all ifnames and hcas from the data section
    for entry in data_section.values():
        if 'name' in entry:
            all_ifnames.append(entry['name'])
        if 'hca' in entry:
            all_hcas.append(entry['hca'])
            
    # 3. Calculate the default value as the longest common prefix
    # Use set to remove duplicates before finding the prefix
    default_ifname = find_longest_common_prefix(list(set(all_ifnames)))
    default_hca = find_longest_common_prefix(list(set(all_hcas)))
    
    # Use a fallback if no common prefix is found
    if not default_ifname:
        default_ifname = "eth" # or some other sensible fallback
    if not default_hca:
        default_hca = "mlx" # or some other sensible fallback

    final_config = {
        'ip': {
            'defaults': {'name': default_ifname, 'hca': default_hca},
            'control': {'ssh': control_iface_details},
            'data': data_section
        }
    }

    yaml.add_representer(str, lambda dumper, data: dumper.represent_scalar('tag:yaml.org,2002:str', data))
    yaml_output = yaml.dump(final_config, default_flow_style=False, sort_keys=False, indent=2)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(yaml_output)
            print(f"INFO: Successfully wrote configuration to {args.output}", file=sys.stderr)
        except IOError as e:
            print(f"Error: Could not write to file {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(yaml_output)

if __name__ == "__main__":
    main()
