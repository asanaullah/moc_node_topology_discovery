#!/usr/bin/env python3

"""
system_discovery.py

A comprehensive script to discover system, BIOS, and kernel settings on 
RHEL-based systems, with a focus on performance and power management. 
Output is formatted as YAML to guide system tuning.

This script is designed for ostree-based RHEL systems but works on most
modern Linux distributions. It prioritizes native tools and standard Python
libraries where possible.

Requires:
  - Python 3.6+
  - PyYAML library (`pip install PyYAML`).
  - The following utilities in the system's PATH:
    - 'dmidecode'
    - 'lscpu'
    - 'sysctl'
    - 'numactl' (from numactl-libs package)
    - 'tuned-adm' (from tuned package)
  - Root privileges (run with 'sudo') for full access to DMI data and other
    system information.

Usage:
  1. Make the script executable:
     chmod +x system_discovery.py

  2. Run with sudo, using the python from your virtual environment:
     # To print to console
     sudo /path/to/your/venv/bin/python system_discovery.py

     # To save to a file
     sudo /path/to/your/venv/bin/python system_discovery.py -o output.yaml
"""

import subprocess
import os
import sys
import glob
import argparse
import re

# Gracefully handle the PyYAML dependency
try:
    import yaml
except ImportError:
    print("Error: PyYAML library not found.", file=sys.stderr)
    print("Please install it in your virtual environment: pip install PyYAML", file=sys.stderr)
    sys.exit(1)


def run_command(command, quiet=False):
    """Runs a shell command and returns its output, or None on failure."""
    try:
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        if not quiet:
            print(f"Warning: Command '{command}' failed or not found: {e}", file=sys.stderr)
        return None

def read_sys_file(path):
    """Reads a file from /sys or /proc, returning None on failure."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, FileNotFoundError):
        return None

def get_dmi_info():
    """Parses 'dmidecode' for System and BIOS information."""
    print("Gathering DMI (System and BIOS) information...")
    all_info = {}
    
    # System Information
    sys_info = {}
    output_sys = run_command("dmidecode -t system")
    if output_sys:
        for line in output_sys.splitlines():
            if ":" in line:
                key, value = [x.strip() for x in line.split(":", 1)]
                if key in ["Manufacturer", "Product Name", "Serial Number", "UUID"]:
                    sys_info[key.lower().replace(" ", "_")] = value
    if sys_info:
        all_info["system_information"] = sys_info

    # BIOS Information
    bios_info = {}
    output_bios = run_command("dmidecode -t bios")
    if output_bios:
        for line in output_bios.splitlines():
            if ":" in line:
                key, value = [x.strip() for x in line.split(":", 1)]
                if key in ["Vendor", "Version", "Release Date"]:
                    bios_info[key.lower().replace(" ", "_")] = value
    if bios_info:
        all_info["bios_information"] = bios_info
        
    return all_info

def get_cpu_info():
    """Gathers CPU architecture and feature information from 'lscpu'."""
    print("Gathering CPU information...")
    info = {}
    output = run_command("lscpu")
    if output:
        for line in output.splitlines():
            if ":" in line:
                key, value = [x.strip() for x in line.split(":", 1)]
                # Sanitize key for YAML
                clean_key = key.lower().replace(" ", "_").replace("(", "").replace(")", "")
                info[clean_key] = value
    return {"cpu_information": info} if info else {}

def get_bios_performance_settings():
    """Gathers performance-relevant settings typically configured in BIOS."""
    print("Gathering BIOS-level performance settings...")
    info = {
        "cpu_turbo_boost": "Unknown",
        "smt_hyper-threading": "Unknown",
        "virtualization": "Unknown",
        "iommu": "Not Detected"
    }
    
    # 1. Check for CPU Turbo Boost (Intel) or Core Performance Boost (AMD)
    # The 'boost' sysfs entry is the most reliable indicator.
    boost_path = "/sys/devices/system/cpu/cpufreq/boost"
    boost_status = read_sys_file(boost_path)
    if boost_status == "1":
        info["cpu_turbo_boost"] = "Enabled"
    elif boost_status == "0":
        info["cpu_turbo_boost"] = "Disabled"
    else:
        # Fallback for systems that might not have the generic boost file
        intel_pstate_no_turbo = read_sys_file("/sys/devices/system/cpu/intel_pstate/no_turbo")
        if intel_pstate_no_turbo == "0":
             info["cpu_turbo_boost"] = "Enabled"
        elif intel_pstate_no_turbo == "1":
             info["cpu_turbo_boost"] = "Disabled (via intel_pstate)"
    # SMT (Hyper-Threading)
    smt_control = read_sys_file("/sys/devices/system/cpu/smt/control")
    if smt_control:
        info["smt_hyper-threading"] = smt_control # e.g., 'on', 'off', 'notsupported'
    else: # Fallback for older kernels
        lscpu_threads = run_command("lscpu | grep 'Thread(s) per core'")
        if lscpu_threads:
            threads = int(lscpu_threads.split(":")[-1].strip())
            info["smt_hyper-threading"] = "enabled" if threads > 1 else "disabled"

    # Virtualization (VT-x / AMD-V)
    lscpu_virt = run_command("lscpu | grep 'Virtualization:'")
    if lscpu_virt:
        info["virtualization"] = lscpu_virt.split(":")[-1].strip()

    # IOMMU (VT-d / AMD-Vi)
    if os.path.isdir("/sys/class/iommu/"):
        # Check kernel command line for explicit enabling
        cmdline = read_sys_file("/proc/cmdline") or ""
        if "intel_iommu=on" in cmdline or "amd_iommu=on" in cmdline:
            info["iommu"] = "Enabled"
        else:
            info["iommu"] = "Detected (may be in passthrough mode)"
    else:
        info["iommu"] = "Not Enabled or Not Supported"
        
    return {"bios_performance_settings": info}

def get_power_and_sleep_states():
    """Discovers system/CPU sleep states and power management details."""
    print("Discovering power management and sleep states...")
    info = {
        "system_s_states": {
            "available_power_states": [],
            "current_suspend_mode": None,
            "available_suspend_modes": None
        },
        "cpu_c_states": {},
        "cpu_p_states": {}
    }

    # S-States (System Sleep)
    s_states = read_sys_file("/sys/power/state")
    if s_states:
        info["system_s_states"]["available_power_states"] = s_states.split()

    mem_sleep_modes = read_sys_file("/sys/power/mem_sleep")
    if mem_sleep_modes:
        all_modes = mem_sleep_modes.replace('[', '').replace(']', '').split()
        info["system_s_states"]["available_suspend_modes"] = all_modes
        current_mode = next((s.strip('[]') for s in mem_sleep_modes.split() if s.startswith('[')), None)
        if current_mode:
            info["system_s_states"]["current_suspend_mode"] = current_mode

    # C-States (CPU Idle)
    c_state_path = "/sys/devices/system/cpu/cpu0/cpuidle/"
    if os.path.exists(c_state_path):
        for state_dir in sorted(glob.glob(os.path.join(c_state_path, "state*"))):
            name = read_sys_file(os.path.join(state_dir, "name"))
            if name:
                info["cpu_c_states"][name] = {
                    "description": read_sys_file(os.path.join(state_dir, "desc")),
                    "latency_us": int(read_sys_file(os.path.join(state_dir, "latency")) or 0),
                    "is_disabled": read_sys_file(os.path.join(state_dir, "disable")) == "1"
                }
    
    # P-States (CPU Frequency Scaling)
    governor_path = "/sys/devices/system/cpu/cpufreq/policy0/"
    if os.path.exists(governor_path):
        driver = read_sys_file(os.path.join(governor_path, "scaling_driver"))
        info["cpu_p_states"]["driver"] = driver
        info["cpu_p_states"]["governor"] = read_sys_file(os.path.join(governor_path, "scaling_governor"))
        info["cpu_p_states"]["available_governors"] = read_sys_file(os.path.join(governor_path, "scaling_available_governors"))
        
        # Check for HWP and EPP (Intel/AMD-specific, but safe to check)
        if driver in ["intel_pstate", "amd-pstate"]:
            info["cpu_p_states"]["hwp_enabled"] = True
            epp = read_sys_file(os.path.join(governor_path, "energy_performance_preference"))
            if epp:
                info["cpu_p_states"]["energy_performance_preference"] = epp
        else:
            info["cpu_p_states"]["hwp_enabled"] = False

    return {"power_and_sleep_states": info}

def get_pcie_aspm_info():
    """Discovers the PCIe Active State Power Management (ASPM) policy."""
    print("Discovering PCIe ASPM settings...")
    info = {}
    aspm_policy_path = "/sys/module/pcie_aspm/parameters/policy"

    policy_data = read_sys_file(aspm_policy_path)
    if policy_data:
        # The format is typically "[current_policy] other policies"
        match = re.search(r'\[(\w+)\]', policy_data)
        if match:
            current_policy = match.group(1)
            info["policy"] = current_policy
            # Also capture the available policies for context
            available_policies = policy_data.replace('[', '').replace(']', '').split()
            info["available_policies"] = available_policies
        else:
            # Fallback if parsing fails but file was read
            info["policy"] = f"Unknown format: {policy_data}"
    else:
        info["policy"] = "Not available or pcie_aspm module not loaded"

    return {"pcie_aspm_settings": info}

def get_memory_info():
    """Gathers information about memory devices, NUMA, and THP."""
    print("Gathering memory subsystem information...")
    info = {
        "transparent_huge_pages": {}
    }

    # Transparent Huge Pages
    thp_enabled = read_sys_file("/sys/kernel/mm/transparent_hugepage/enabled")
    if thp_enabled:
        current_thp = next((s.strip('[]') for s in thp_enabled.split() if s.startswith('[')), "unknown")
        info["transparent_huge_pages"]["enabled"] = current_thp
        info["transparent_huge_pages"]["defrag"] = read_sys_file("/sys/kernel/mm/transparent_hugepage/defrag")

    return {"memory_information": info}

def get_kernel_tuning():
    """Checks for various performance-related kernel settings."""
    print("Checking kernel tuning parameters...")
    info = {
        "kernel_cmdline": read_sys_file("/proc/cmdline"),
        "cpu_vulnerabilities": {},
        "io_schedulers": {},
        "sysctl_tunables": {},
        "tuned_profile": "Not detected"
    }
    
    # CPU Vulnerabilities
    vuln_path = "/sys/devices/system/cpu/vulnerabilities/"
    if os.path.isdir(vuln_path):
        for vuln in os.listdir(vuln_path):
            info["cpu_vulnerabilities"][vuln] = read_sys_file(os.path.join(vuln_path, vuln))

    # I/O Schedulers
    for device_path in glob.glob("/sys/block/sd*") + glob.glob("/sys/block/nvme*n*"):
        dev_name = os.path.basename(device_path)
        scheduler_file = os.path.join(device_path, "queue/scheduler")
        scheduler = read_sys_file(scheduler_file)
        if scheduler:
            current_scheduler = next((s.strip('[]') for s in scheduler.split() if s.startswith('[')), scheduler)
            info["io_schedulers"][dev_name] = current_scheduler

    # Key Sysctl Tunables
    sysctl_keys = [
        "vm.swappiness", "vm.dirty_background_ratio", "vm.dirty_ratio",
        "net.core.somaxconn", "net.ipv4.tcp_max_syn_backlog",
        "kernel.sched_min_granularity_ns", "kernel.sched_latency_ns"
    ]
    for key in sysctl_keys:
        value = run_command(f"sysctl -n {key}", quiet=True)
        if value:
            info["sysctl_tunables"][key] = value
            
    # Tuned Profile
    tuned_output = run_command("tuned-adm active", quiet=True)
    if tuned_output and "Current active profile:" in tuned_output:
        info["tuned_profile"] = tuned_output.split(":")[-1].strip()
    elif run_command("systemctl is-active tuned", quiet=True) == "active":
        info["tuned_profile"] = "Active, but profile could not be determined"
        
    return {"kernel_tuning": info}


def main():
    """Main function to orchestrate the discovery and print the results."""
    if os.geteuid() != 0:
        print("Error: This script requires root privileges.", file=sys.stderr)
        sys.exit(1)
        
    parser = argparse.ArgumentParser(
        description="Discover system performance settings and output as YAML.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Optional: Path to the output file. Prints to console if not specified."
    )
    args = parser.parse_args()

    print("--- Starting System Discovery ---\n")
    
    # Combine results from all discovery functions
    discovery_results = {
        **get_dmi_info(),
        **get_bios_performance_settings(),
        **get_cpu_info(),
        **get_power_and_sleep_states(),
        **get_pcie_aspm_info(),
        **get_memory_info(),
        **get_kernel_tuning(),
    }

    # Generate clean, block-style YAML output
    yaml_output = yaml.dump(discovery_results, default_flow_style=False, sort_keys=False, indent=2)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(yaml_output)
            print(f"\n--- Results successfully written to {args.output} ---")
        except IOError as e:
            print(f"Error: Could not write to file {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("\n--- Discovery Complete ---")
        print("\nResults in YAML format:")
        print("---")
        print(yaml_output)

if __name__ == "__main__":
    main()