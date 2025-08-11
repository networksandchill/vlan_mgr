#!/usr/bin/env python3
"""
Enhanced VLAN management script with gateway support, dynamic route metrics,
error handling, and configuration.
"""
import argparse
import os
import sys
import subprocess
import ipaddress
import logging
import json
import tempfile
import re
import shlex
import shutil

# Defaults
INTERFACES_DIR_DEFAULT = '/etc/network/interfaces.d'
DEFAULT_BASE_IFACE = 'eth0'
# Base metric if no existing default metric found
DEFAULT_ROUTE_METRIC = 1000


def setup_logger():
    logger = logging.getLogger('vlan_manager')
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

logger = setup_logger()


def require_root():
    if os.geteuid() != 0:
        logger.error("Must run as root.")
        sys.exit(1)


def sanitize_interface_name(name):
    """Sanitize interface name to prevent command injection."""
    if not re.match(r'^[a-zA-Z0-9.-]+$', name):
        raise ValueError(f"Invalid interface name: {name}")
    return name

def sanitize_ip_address(ip_str):
    """Sanitize IP address string."""
    try:
        ipaddress.IPv4Address(ip_str)
        return ip_str
    except ipaddress.AddressValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")

def sanitize_vlan_id(vlan_id):
    """Sanitize VLAN ID."""
    if not isinstance(vlan_id, int) or not (1 <= vlan_id <= 4094):
        raise ValueError(f"Invalid VLAN ID: {vlan_id}")
    return str(vlan_id)

def run_command(cmd, check=True):
    logger.debug(f"Cmd: {cmd}")
    try:
        return subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Cmd failed: {cmd}\n{e.stderr.strip()}")
        return None
    except (OSError, FileNotFoundError) as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(1)


def interface_exists(iface):
    try:
        iface = sanitize_interface_name(iface)
        res = run_command(f'ip link show {iface}', check=False)
        return bool(res and res.returncode == 0)
    except ValueError:
        return False


def get_interface_info(iface):
    """Return (ip, prefixlen) or (None, None)."""
    iface = sanitize_interface_name(iface)
    res = run_command(f'ip -j addr show {iface}', check=False)
    if res and res.returncode == 0:
        try:
            data = json.loads(res.stdout)
            if data and len(data) > 0:
                info = data[0].get('addr_info', [])
                if info and len(info) > 0 and 'local' in info[0] and 'prefixlen' in info[0]:
                    return info[0]['local'], info[0]['prefixlen']
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
    res = run_command(f'ip -br addr show {iface}', check=False)
    if res and res.returncode == 0:
        parts = res.stdout.split()
        if len(parts) >= 3:
            try:
                ip_str, prefix = parts[2].split('/')
                return ip_str, int(prefix)
            except (ValueError, IndexError):
                pass
    return None, None


def get_current_max_metric():
    res = run_command('ip -j route show default', check=False)
    max_metric = 0
    found_any_metric = False
    if res and res.stdout:
        try:
            routes = json.loads(res.stdout)
            for route in routes:
                if 'metric' in route:
                    max_metric = max(max_metric, route['metric'])
                    found_any_metric = True
        except json.JSONDecodeError:
            pass  # Fallback to text parsing if JSON fails
    if not found_any_metric:
        # Fallback for older systems or if JSON parsing fails
        res = run_command('ip route show default', check=False)
        if res and res.stdout:
            for line in res.stdout.splitlines():
                parts = line.split()
                if 'metric' in parts:
                    try:
                        idx = parts.index('metric') + 1
                        if idx < len(parts):
                            m = int(parts[idx])
                            max_metric = max(max_metric, m)
                            found_any_metric = True
                    except (ValueError, IndexError):
                        pass
    return max_metric if found_any_metric else DEFAULT_ROUTE_METRIC


def prefix_to_netmask(prefix):
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    except Exception:
        raise ValueError(f"Invalid prefix {prefix}")


def store_configuration(iface):
    ip_addr, pref = get_interface_info(iface)
    mask = None
    if pref is not None:
        try:
            mask = prefix_to_netmask(pref)
        except Exception as e:
            logger.warning(f"Failed to convert prefix {pref} to netmask: {e}")
    logger.info(f"Stored cfg {iface}: ip={ip_addr}, prefix={pref}, netmask={mask}")
    return {'ip': ip_addr, 'prefix': pref, 'netmask': mask}


def write_config_file(path, lines):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='vlan_', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write('\n'.join(lines) + '\n')
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
            logger.info(f"Wrote config to {path}")
        except Exception:
            os.unlink(tmp)
            raise
    except (OSError, IOError) as e:
        logger.error(f"Failed to write config file {path}: {e}")
        raise


def rollback_configuration(base, vlan, saved):
    try:
        base = sanitize_interface_name(base)
        vlan_str = sanitize_vlan_id(vlan)
        iface = f"{base}.{vlan_str}"
        
        if not isinstance(saved, dict):
            logger.error("Invalid saved configuration")
            return
            
        if not interface_exists(iface):
            run_command(f'ip link add link {base} name {iface} type vlan id {vlan_str}')
        run_command(f'ip link set {iface} down')
        run_command(f'ip addr flush dev {iface}')
        
        ip_addr = saved.get('ip')
        pref = saved.get('prefix')
        if ip_addr and pref:
            ip_addr = sanitize_ip_address(ip_addr)
            run_command(f'ip addr add {ip_addr}/{pref} dev {iface}')
        run_command(f'ip link set {iface} up')
        logger.info(f"Rolled back {iface}")
    except (ValueError, TypeError) as e:
        logger.error(f"Rollback failed: {e}")


def bring_vlan_up(args):
    base = sanitize_interface_name(args.base_interface)
    vlan = args.vlan_id
    vlan_str = sanitize_vlan_id(vlan)
    iface = f"{base}.{vlan_str}"
    saved = store_configuration(iface)

    # Determine mode and plan
    if args.dhcp:
        plan = 'DHCP'; ip_str = None; prefix = None
    else:
        iface_obj = ipaddress.IPv4Interface(args.ip)
        ip_str = str(iface_obj.ip)
        prefix = iface_obj.network.prefixlen
        plan = f"static {ip_str}/{prefix}"

    if not args.no_confirm:
        logger.info(f"Plan: {plan} on {iface}")
        if input("Apply? (yes/no): ").strip().lower() != 'yes':
            logger.info("Cancelled.")
            return

    # Build interfaces file (omit gateway)
    lines = [f"auto {iface}",
             f"iface {iface} inet {'dhcp' if args.dhcp else 'static'}"]
    if not args.dhcp:
        netmask = prefix_to_netmask(prefix)
        lines += [f"    address {ip_str}",
                  f"    netmask {netmask}",
                  f"    vlan-raw-device {base}"]

    try:
        write_config_file(os.path.join(args.config_dir, iface), lines)
        res = run_command(f'ifup {iface}')
        if not res or res.returncode != 0:
            raise RuntimeError(f"ifup failed for {iface}")

        # If a gateway was specified, delete auto routes then add ours
        if not args.dhcp and args.gateway:
            gateway = sanitize_ip_address(args.gateway)
            run_command(f'ip route del default dev {iface}', check=False)
            existing_max = get_current_max_metric()
            desired = max(existing_max + 1, args.metric)
            run_command(f'ip route add default via {gateway} dev {iface} metric {desired}')
            logger.info(f"Set default via {gateway} metric {desired}")

        logger.info(f"{iface} is up")
    except Exception as e:
        logger.error(f"Error: {e}, rolling back")
        rollback_configuration(base, vlan, saved)


def bring_vlan_down(args):
    base = sanitize_interface_name(args.base_interface)
    vlan = args.vlan_id
    vlan_str = sanitize_vlan_id(vlan)
    iface = f"{base}.{vlan_str}"
    config_path = os.path.join(args.config_dir, iface)

    if not interface_exists(iface):
        logger.warning(f"{iface} does not exist")
        return

    saved = store_configuration(iface)
    if not args.no_confirm:
        if input(f"Bring down {iface}? (yes/no): ").strip().lower() != 'yes':
            logger.info("Cancelled.")
            return

    try:
        run_command(f'ip addr flush dev {iface}')
        run_command(f'ifdown {iface}')
        if os.path.exists(config_path):
            os.remove(config_path)
            logger.info(f"Removed config file {config_path}")
    except Exception as e:
        logger.error(f"Error during bring down: {e}")


def parse_args():
    example_text = '''
Examples:
  # Static VLAN up with CIDR and gateway, safe metric above existing
  vlan_manager.py 314 up --ip 192.0.2.10/24 \
      --gateway 192.0.2.1 --metric 200

  # DHCP VLAN up without prompts
  vlan_manager.py 314 up --dhcp --no-confirm

  # VLAN down
  vlan_manager.py 314 down
'''
    parser = argparse.ArgumentParser(
        description="Manage VLAN interfaces on Debian-style systems.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=example_text
    )
    parser.add_argument('vlan_id', type=int,
                        help='VLAN ID (1–4094)')
    parser.add_argument('action', choices=['up', 'down'],
                        help='"up" to configure and bring up; "down" to bring down and remove config.')
    parser.add_argument('--ip',
                        help='IPv4 in CIDR (e.g. 192.0.2.10/24) for static mode; required unless --dhcp.')
    parser.add_argument('--dhcp', action='store_true',
                        help='Use DHCP; skips --ip requirement.')
    parser.add_argument('--gateway',
                        help='Gateway IP for default route (optional).')
    parser.add_argument('--metric', type=int, default=DEFAULT_ROUTE_METRIC,
                        help=f'Base route metric (default: {DEFAULT_ROUTE_METRIC}); script raises above existing.')
    parser.add_argument('--base-interface', default=DEFAULT_BASE_IFACE,
                        help='Underlying interface (default: eth0).')
    parser.add_argument('--config-dir', default=INTERFACES_DIR_DEFAULT,
                        help='Directory for interfaces.d files (default: /etc/network/interfaces.d).')
    parser.add_argument('--no-confirm', action='store_true',
                        help='Skip confirmation prompts.')
    return parser.parse_args()

def check_dependencies():
    """Check for required commands."""
    for cmd in ['ifup', 'ifdown']:
        if not shutil.which(cmd):
            logger.error(f"Required command not found: {cmd}. Please install the 'ifupdown' package.")
            sys.exit(1)

def main():
    args = parse_args()
    if os.geteuid() != 0 and not any(o in sys.argv for o in ('-h', '--help')):
        require_root()

    check_dependencies()

    if not (1 <= args.vlan_id <= 4094):
        logger.error("VLAN ID must be between 1 and 4094")
        sys.exit(1)

    if args.action == 'up' and not args.dhcp:
        if not args.ip:
            logger.error("Static mode requires --ip in CIDR.")
            sys.exit(1)
        try:
            ipaddress.IPv4Interface(args.ip)
        except ValueError:
            logger.error("Invalid CIDR for --ip.")
            sys.exit(1)
        if args.gateway:
            try:
                ipaddress.IPv4Address(args.gateway)
            except ValueError:
                logger.error("Invalid gateway IP.")
                sys.exit(1)

    if args.action == 'up':
        bring_vlan_up(args)
    else:
        bring_vlan_down(args)

if __name__ == '__main__':
    main()