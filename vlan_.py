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


def run_command(cmd, check=True):
    logger.debug(f"Cmd: {' '.join(cmd)}")
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Cmd failed: {' '.join(cmd)}\n{e.stderr.strip()}")
        return None
    except OSError as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(1)


def interface_exists(iface):
    res = run_command(['ip', 'link', 'show', iface], check=False)
    return bool(res and res.returncode == 0)


def get_interface_info(iface):
    """Return (ip, prefixlen) or (None, None)."""
    res = run_command(['ip', '-j', 'addr', 'show', iface], check=False)
    if res and res.returncode == 0:
        try:
            data = json.loads(res.stdout)
            info = data[0].get('addr_info', [])
            if info:
                return info[0]['local'], info[0]['prefixlen']
        except json.JSONDecodeError:
            pass
    res = run_command(['ip', '-br', 'addr', 'show', iface], check=False)
    if res and res.returncode == 0:
        parts = res.stdout.split()
        if len(parts) >= 3:
            try:
                ip_str, prefix = parts[2].split('/')
                return ip_str, int(prefix)
            except Exception:
                pass
    return None, None


def get_current_max_metric():
    res = run_command(['ip', 'route', 'show', 'default'], check=False)
    max_metric = 0
    if res and res.stdout:
        for line in res.stdout.splitlines():
            parts = line.split()
            if 'metric' in parts:
                try:
                    idx = parts.index('metric') + 1
                    m = int(parts[idx])
                    max_metric = max(max_metric, m)
                except Exception:
                    pass
            else:
                max_metric = max(max_metric, DEFAULT_ROUTE_METRIC)
    return max_metric


def prefix_to_netmask(prefix):
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    except Exception:
        logger.error(f"Invalid prefix {prefix}")
        sys.exit(1)


def store_configuration(iface):
    ip_addr, pref = get_interface_info(iface)
    mask = prefix_to_netmask(pref) if pref is not None else None
    logger.info(f"Stored cfg {iface}: ip={ip_addr}, prefix={pref}, netmask={mask}")
    return {'ip': ip_addr, 'prefix': pref, 'netmask': mask}


def write_config_file(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    os.replace(tmp, path)
    logger.info(f"Wrote config to {path}")


def rollback_configuration(base, vlan, saved):
    iface = f"{base}.{vlan}"
    if not interface_exists(iface):
        run_command(['ip', 'link', 'add', 'link', base, 'name', iface,
                     'type', 'vlan', 'id', str(vlan)])
    run_command(['ip', 'link', 'set', iface, 'down'])
    run_command(['ip', 'addr', 'flush', 'dev', iface])
    ip_addr = saved.get('ip'); pref = saved.get('prefix')
    if ip_addr and pref:
        run_command(['ip', 'addr', 'add', f"{ip_addr}/{pref}", 'dev', iface])
    run_command(['ip', 'link', 'set', iface, 'up'])
    logger.info(f"Rolled back {iface}")


def bring_vlan_up(args):
    base = args.base_interface
    vlan = args.vlan_id
    iface = f"{base}.{vlan}"
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
        res = run_command(['ifup', iface])
        if not res or res.returncode != 0:
            raise RuntimeError(f"ifup failed for {iface}")

        # If a gateway was specified, delete auto routes then add ours
        if not args.dhcp and args.gateway:
            run_command(['ip', 'route', 'del', 'default', 'dev', iface], check=False)
            existing_max = get_current_max_metric()
            desired = max(existing_max + 1, args.metric)
            run_command(['ip', 'route', 'add', 'default', 'via', args.gateway,
                         'dev', iface, 'metric', str(desired)])
            logger.info(f"Set default via {args.gateway} metric {desired}")

        logger.info(f"{iface} is up")
    except Exception as e:
        logger.error(f"Error: {e}, rolling back")
        rollback_configuration(base, vlan, saved)


def bring_vlan_down(args):
    base = args.base_interface
    vlan = args.vlan_id
    iface = f"{base}.{vlan}"
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
        run_command(['ifdown', iface])
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


def main():
    args = parse_args()
    if os.geteuid() != 0 and not any(o in sys.argv for o in ('-h', '--help')):
        require_root()

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
