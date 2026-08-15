#!/usr/bin/env python3
"""
send_dhcp.py - simple DHCP packet sender using Scapy
Usage:
  python send_dhcp.py --iface "Ethernet" --count 3 --type discover
Requires: Python 3, Scapy, Npcap (on Windows) and Administrator rights.
"""
import argparse
import sys

try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, get_if_hwaddr, conf
except Exception as e:
    print("Scapy import failed:", e)
    print("Install scapy: pip install scapy")
    sys.exit(1)

IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    try:
        import ctypes
        def is_admin():
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
    except Exception:
        def is_admin():
            return False
else:
    def is_admin():
        return False


def build_chaddr(mac_str):
    mac = mac_str.replace(':', '').replace('-', '')
    b = bytes.fromhex(mac)
    return b + b"\x00" * (16 - len(b))


def send_dhcp(iface, count, msg_type, client_mac=None, requested_ip=None):
    conf.iface = iface
    if client_mac is None:
        try:
            client_mac = get_if_hwaddr(iface)
        except Exception as e:
            print("Failed to get interface MAC:", e)
            return

    chaddr = build_chaddr(client_mac)

    ether = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=chaddr)

    options = []
    if msg_type == 'discover':
        options.append(("message-type", "discover"))
    elif msg_type == 'request':
        options.append(("message-type", "request"))
        if requested_ip:
            # use requested_addr option
            options.append(("requested_addr", requested_ip))
    else:
        print("Unknown msg_type", msg_type)
        return

    options.append(("end", b""))

    pkt = ether / ip / udp / bootp / DHCP(options=options)

    print(f"Sending {count} DHCP {msg_type.upper()} packet(s) on iface {iface} with MAC {client_mac}")
    sendp(pkt, iface=iface, count=count, verbose=True)


def main():
    parser = argparse.ArgumentParser(description='Send DHCP packets (Scapy)')
    parser.add_argument('--iface', required=True, help='Interface name (Windows: "Ethernet", "Wi-Fi")')
    parser.add_argument('--count', type=int, default=1, help='Number of packets to send')
    parser.add_argument('--type', choices=['discover', 'request'], default='discover', help='DHCP message type')
    parser.add_argument('--mac', help='Client MAC address to use (e.g. 00:11:22:33:44:55)')
    parser.add_argument('--requested-ip', help='Requested IP address (for DHCPREQUEST)')

    args = parser.parse_args()

    if IS_WINDOWS and not is_admin():
        print("Warning: On Windows you must run this script as Administrator and have Npcap installed.")

    send_dhcp(args.iface, args.count, args.type, client_mac=args.mac, requested_ip=args.requested_ip)


if __name__ == '__main__':
    main()
