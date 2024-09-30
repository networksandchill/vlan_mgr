#!/usr/bin/env python3

import os
import subprocess
import time

# Path where the interfaces are stored
interfaces_path = '/etc/network/interfaces.d/'
user_confirmation = None  # Global variable to store user confirmation
original_ip = None
original_netmask = None

def interface_exists(interface):
    """Check if a network interface exists."""
    result = subprocess.run(['ip', 'link', 'show', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def get_interface_ip_and_netmask(interface):
    """Get the current IP address and netmask of the interface."""
    result = subprocess.run(['ip', 'addr', 'show', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    
    ip_address = None
    netmask = None

    # Look for the line containing the IP address and netmask
    for line in output.splitlines():
        if 'inet ' in line:
            # The line should look like: "inet 192.168.1.100/24 ..."
            ip_with_mask = line.split()[1]
            ip_address, prefix_length = ip_with_mask.split('/')
            netmask = prefix_to_netmask(int(prefix_length))
            break

    return ip_address, netmask

def prefix_to_netmask(prefix):
    """Convert a prefix length (e.g., 24) to a netmask (e.g., 255.255.255.0)."""
    mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
    return f"{(mask >> 24) & 255}.{(mask >> 16) & 255}.{(mask >> 8) & 255}.{mask & 255}"

def bring_vlan_up(vlan_id, ip_address, netmask):
    vlan_interface = f"eth0.{vlan_id}"
    config_file = os.path.join(interfaces_path, vlan_interface)

    # Create the VLAN configuration file
    with open(config_file, 'w') as f:
        f.write(f"auto {vlan_interface}\n")
        f.write(f"iface {vlan_interface} inet static\n")
        f.write(f"    address {ip_address}\n")
        f.write(f"    netmask {netmask}\n")
        f.write(f"    vlan-raw-device eth0\n")

    print(f"VLAN {vlan_interface} configuration written to {config_file}")

    # Bring up the interface
    subprocess.run(['sudo', 'ifup', vlan_interface], check=True)
    print(f"{vlan_interface} is up.")

def bring_vlan_down(vlan_id):
    vlan_interface = f"eth0.{vlan_id}"
    config_file = os.path.join(interfaces_path, vlan_interface)

    if not interface_exists(vlan_interface):
        print(f"Interface {vlan_interface} does not exist or is already down.")
        return

    # Bring down the interface
    subprocess.run(['sudo', 'ifdown', vlan_interface], check=True)
    print(f"{vlan_interface} is down.")

    # Remove the VLAN configuration file
    if os.path.exists(config_file):
        os.remove(config_file)
        print(f"Configuration for {vlan_interface} removed from {config_file}.")
    else:
        print(f"Configuration file {config_file} does not exist.")

def confirm_input_with_timer(vlan_id, action, timer=60):
    """Function to confirm the changes or rollback after the timer with input validation."""
    global user_confirmation, original_ip, original_netmask

    # Inform the user about the confirmation time
    print(f"You have {timer} seconds to CONFIRM or ROLLBACK before changes are reverted.")
    
    # Start countdown and input validation loop
    start_time = time.time()
    remaining_time = timer

    while remaining_time > 0:
        user_confirmation = input("> ").strip().lower()

        if user_confirmation not in ['confirm', 'rollback']:
            # Reject invalid input, show remaining time and prompt again
            elapsed_time = time.time() - start_time
            remaining_time = max(0, timer - int(elapsed_time))
            print(f"Invalid input. You have {remaining_time} seconds remaining to CONFIRM or ROLLBACK.")
        else:
            break

        elapsed_time = time.time() - start_time
        remaining_time = max(0, timer - int(elapsed_time))

    # Handle valid input or timer expiry
    if remaining_time > 0 and user_confirmation == 'confirm':
        print("Changes confirmed.")
    elif user_confirmation == 'rollback' or remaining_time <= 0:
        # Either no valid input in time or user chose to rollback
        if action == 'up':
            bring_vlan_down(vlan_id)
            if original_ip and original_netmask:
                print(f"Rolling back to original IP: {original_ip} and netmask: {original_netmask}")
                bring_vlan_up(vlan_id, original_ip, original_netmask)
            else:
                print(f"Changes reverted: VLAN {vlan_id} has been rolled back.")
        elif action == 'down':
            bring_vlan_up(vlan_id, original_ip or "192.168.1.1", original_netmask or "255.255.255.0")  # Use previous IP if available
            print(f"Changes reverted: VLAN {vlan_id} has been rolled back.")
    else:
        print(f"Confirmation failed: VLAN {vlan_id} has been automatically rolled back due to no valid input.")

def main():
    global user_confirmation, original_ip, original_netmask
    user_confirmation = None  # Reset the confirmation state for each run

    # Get user input for VLAN ID
    vlan_id = input("Enter VLAN ID (e.g., 314): ").strip()

    # Validate VLAN ID
    if not vlan_id.isdigit():
        print("Invalid VLAN ID. It must be a number.")
        return

    vlan_interface = f"eth0.{vlan_id}"

    # Get the current IP and netmask of the interface (if it exists)
    if interface_exists(vlan_interface):
        original_ip, original_netmask = get_interface_ip_and_netmask(vlan_interface)
        print(f"Current IP: {original_ip}, Netmask: {original_netmask}")

    # Get action input (up or down)
    action = input("Do you want to bring VLAN up or down? (up/down): ").strip().lower()

    if action == 'up':
        # Get IP address and netmask for 'up' action
        ip_address = input("Enter IP address (e.g., 192.168.1.100): ").strip()
        netmask = input("Enter netmask (e.g., 255.255.255.0): ").strip()

        # Bring the VLAN up
        bring_vlan_up(vlan_id, ip_address, netmask)

        # Start the confirm timer with input validation
        confirm_input_with_timer(vlan_id, 'up', 60)

    elif action == 'down':
        # Bring the VLAN down with a confirm timer
        bring_vlan_down(vlan_id)

        # Start the confirm timer for bringing down
        confirm_input_with_timer(vlan_id, 'down', 60)

    else:
        print("Invalid action. Use 'up' or 'down'.")

if __name__ == "__main__":
    main()
