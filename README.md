# VLAN Manager 🌐

A robust Python script for managing VLAN interfaces on Debian-style Linux systems with comprehensive error handling, gateway support, and dynamic route metrics.

## 📋 Overview

`vlan_mgr.py` is an enhanced VLAN management tool that simplifies the creation, configuration, and teardown of VLAN interfaces. It automatically handles network interface configurations, route management, and provides both static IP and DHCP support with intelligent error recovery.

## ✨ Features

- **🔧 Automatic VLAN Interface Management**: Creates and configures VLAN interfaces with proper validation
- **🌐 Gateway Support**: Configures default routes with dynamic metric assignment
- **📡 DHCP & Static IP Support**: Flexible IP configuration options
- **🛡️ Comprehensive Error Handling**: Automatic rollback on failures with detailed logging
- **⚡ Smart Route Metrics**: Automatically assigns route metrics above existing ones
- **🔒 Safety First**: Confirmation prompts and validation checks
- **📁 Config File Management**: Automatic creation/cleanup of `/etc/network/interfaces.d/` files
- **🔄 State Verification**: Ensures interfaces are properly configured after changes

## 🚀 Quick Start

### Prerequisites

- **Root privileges** (required for network configuration)
- **Python 3.6+**
- **Debian-based system** (Ubuntu, Debian, etc.) with `ifupdown` package

### Basic Usage

```bash
# Bring up VLAN 314 with static IP and gateway
sudo ./vlan_mgr.py 314 up --ip 192.168.1.100/24 --gateway 192.168.1.1

# Bring up VLAN 200 with DHCP (no confirmation prompt)
sudo ./vlan_mgr.py 200 up --dhcp --no-confirm

# Bring down VLAN 314
sudo ./vlan_mgr.py 314 down
```

## 📖 Detailed Examples

### Static IP Configuration

```bash
# Basic static IP setup
sudo ./vlan_mgr.py 100 up --ip 10.0.1.50/24

# Static IP with gateway and custom metric
sudo ./vlan_mgr.py 314 up \
    --ip 192.0.2.10/24 \
    --gateway 192.0.2.1 \
    --metric 200

# Custom base interface (default is eth0)
sudo ./vlan_mgr.py 500 up \
    --ip 172.16.0.10/16 \
    --base-interface enp0s3
```

### DHCP Configuration

```bash
# DHCP with confirmation
sudo ./vlan_mgr.py 314 up --dhcp

# DHCP without confirmation prompt
sudo ./vlan_mgr.py 314 up --dhcp --no-confirm

# DHCP on custom interface
sudo ./vlan_mgr.py 200 up --dhcp --base-interface eth1
```

### Interface Management

```bash
# Bring down a VLAN interface
sudo ./vlan_mgr.py 314 down

# Skip confirmation prompt when bringing down
sudo ./vlan_mgr.py 314 down --no-confirm

# Use custom config directory
sudo ./vlan_mgr.py 100 up --ip 10.0.0.1/24 --config-dir /custom/interfaces.d
```

## ⚙️ Command Line Options

### Required Arguments

| Argument | Description |
|----------|-------------|
| `vlan_id` | VLAN ID (1-4094) |
| `action` | Action to perform: `up` or `down` |

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ip` | IPv4 address in CIDR format (e.g., `192.168.1.10/24`) | Required for static mode |
| `--dhcp` | Use DHCP instead of static IP | `false` |
| `--gateway` | Gateway IP address for default route | None |
| `--metric` | Base route metric (script adds to existing max) | `1000` |
| `--base-interface` | Underlying physical interface | `eth0` |
| `--config-dir` | Directory for interface config files | `/etc/network/interfaces.d` |
| `--no-confirm` | Skip confirmation prompts | `false` |

### Examples by Use Case

#### 🏢 Corporate Network Setup
```bash
# Corporate VLAN with specific gateway
sudo ./vlan_mgr.py 100 up --ip 10.1.100.50/24 --gateway 10.1.100.1
```

#### 🏠 Home Lab Environment
```bash
# Home lab VLAN with DHCP
sudo ./vlan_mgr.py 200 up --dhcp --base-interface enp2s0
```

#### ☁️ Cloud Instance Configuration
```bash
# Cloud instance with custom metric
sudo ./vlan_mgr.py 314 up \
    --ip 172.31.0.100/16 \
    --gateway 172.31.0.1 \
    --metric 500 \
    --no-confirm
```

## 🔧 How It Works

### Interface Creation Process

1. **Validation**: Validates VLAN ID, interface names, and IP addresses
2. **Configuration Backup**: Stores existing interface configuration for rollback
3. **Config File Creation**: Generates `/etc/network/interfaces.d/[interface]` file
4. **Interface Activation**: Uses `ifup` to bring up the VLAN interface
5. **State Verification**: Confirms interface is properly configured
6. **Route Management**: Adds default routes with intelligent metric assignment

### Automatic Rollback

The script provides comprehensive error recovery:
- **Config File Cleanup**: Removes configuration files on failure
- **Interface Cleanup**: Removes newly created interfaces if setup fails
- **State Restoration**: Restores previous interface configuration when possible

### Route Metric Logic

The script intelligently handles route metrics:
1. Scans existing default routes to find maximum metric
2. Adds 1 to the maximum found metric (or uses specified `--metric` if higher)
3. Ensures new routes don't conflict with existing ones

## 📁 Generated Files

When bringing up a VLAN interface, the script creates a configuration file at:
```
/etc/network/interfaces.d/[base_interface].[vlan_id]
```

### Example Static Configuration
```bash
# Contents of /etc/network/interfaces.d/eth0.314
auto eth0.314
iface eth0.314 inet static
    address 192.0.2.10
    netmask 255.255.255.0
    vlan-raw-device eth0
```

### Example DHCP Configuration
```bash
# Contents of /etc/network/interfaces.d/eth0.314
auto eth0.314
iface eth0.314 inet dhcp
```

## ⚠️ Important Notes

- **Root Required**: Script must be run with root privileges for network configuration
- **Interface Dependencies**: Base interface must exist before creating VLANs
- **Config Persistence**: Configurations persist across reboots via `/etc/network/interfaces.d/`
- **Automatic Cleanup**: Failed operations are automatically rolled back
- **Validation**: All inputs are validated before making system changes

## 🐛 Troubleshooting

### Common Issues

**Interface doesn't exist**
```
ERROR: Base interface eth0 does not exist
```
*Solution*: Verify the base interface name with `ip link show`

**Permission denied**
```
ERROR: Must run as root
```
*Solution*: Run with `sudo` or as root user

**Invalid VLAN ID**
```
ERROR: VLAN ID must be between 1 and 4094
```
*Solution*: Use a valid VLAN ID within the 802.1Q standard range

**Configuration conflicts**
```
ERROR: Interface verification failed
```
*Solution*: Check for conflicting network configurations or try a different IP range

### Debug Mode

For troubleshooting, you can modify the logging level in the script or check system logs:
```bash
# Check system networking logs
sudo journalctl -u networking
sudo journalctl -u NetworkManager  # if using NetworkManager
```

## 🤝 Contributing

This script is designed for defensive network administration tasks. When contributing:
- Maintain comprehensive error handling
- Add validation for all user inputs
- Include rollback mechanisms for destructive operations
- Document all changes thoroughly

## 📝 License

This script is provided as-is for network administration purposes. Use at your own risk and always test in a development environment first.%
