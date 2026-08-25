#!/usr/bin/env python3
"""
send_dhcp.py - DHCP/BOOTP packet sender using Scapy

Usage examples:

  DHCPDISCOVER:
    python send_dhcp.py --iface "Беспроводная сеть" --count 3 --type discover

  DHCPREQUEST без Option 81:
    python send_dhcp.py --iface "Ethernet" --count 1 --type request --mac 9C:6B:00:57:10:A1 --requested-ip 10.91.0.191

  DHCPREQUEST з Option 81 (Client FQDN):
    python send_dhcp.py --iface "Ethernet" --count 1 --type request --mac 9C:6B:00:57:10:A1 --requested-ip 10.91.0.191 --fqdn C50-100-6165.fbp.bank.gov.ua

  BOOTP REQUEST:
    python send_dhcp.py --iface "Беспроводная сеть" --count 3 --type bootp --mac 44:6D:57:2E:F3:6A
"""

import argparse
import sys

try:
    from scapy.all import (
        Ether,
        IP,
        UDP,
        BOOTP,
        DHCP,
        sendp,
        get_if_hwaddr,
        conf,
        RandInt,
    )
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
    """
    BOOTP chaddr is 16 bytes.
    Ethernet MAC occupies the first 6 bytes.
    """
    mac = mac_str.replace(":", "").replace("-", "")
    b = bytes.fromhex(mac)

    if len(b) != 6:
        raise ValueError("MAC address must contain exactly 6 bytes")

    return b + b"\x00" * 10


def send_dhcp(iface, count, msg_type, client_mac=None, requested_ip=None, fqdn=None):

    conf.iface = iface

    if client_mac is None:
        try:
            client_mac = get_if_hwaddr(iface)
        except Exception as e:
            print("Failed to get interface MAC:", e)
            return

    try:
        chaddr = build_chaddr(client_mac)
    except ValueError as e:
        print(f"Invalid MAC address: {e}")
        return

    #
    # Common Ethernet/IP/UDP headers
    #
    ether = Ether(
        src=client_mac,
        dst="ff:ff:ff:ff:ff:ff"
    )

    ip = IP(
        src="0.0.0.0",
        dst="255.255.255.255"
    )

    udp = UDP(
        sport=68,
        dport=67
    )

    #
    # ---------------------------------------------------------
    # BOOTP REQUEST
    # ---------------------------------------------------------
    #
    if msg_type == "bootp":

        bootp = BOOTP(
            op=1,                  # BOOTREQUEST
            htype=1,               # Ethernet
            hlen=6,                # MAC address length
            hops=0,
            xid=int(RandInt()),
            secs=0,
            flags=0x8000,          # Broadcast
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr=chaddr
        )

        pkt = ether / ip / udp / bootp

        print(
            f"Sending {count} BOOTP REQUEST packet(s) "
            f"on iface {iface} with MAC {client_mac}"
        )

        print("Packet structure:")
        print("  Ethernet / IPv4 / UDP 68->67 / BOOTP")
        print("  DHCP options: NONE")

        sendp(
            pkt,
            iface=iface,
            count=count,
            verbose=True
        )

        return

    #
    # ---------------------------------------------------------
    # DHCP
    # ---------------------------------------------------------
    #

    bootp = BOOTP(
        op=1,
        htype=1,
        hlen=6,
        chaddr=chaddr
    )

    options = []

    if msg_type == "discover":

        options.append(
            ("message-type", "discover")
        )

    elif msg_type == "request":

        options.append(
            ("message-type", "request")
        )

        if requested_ip:
            options.append(
                ("requested_addr", requested_ip)
            )

    else:

        print("Unknown msg_type:", msg_type)
        return

    if fqdn:
        # Option 81 (Client FQDN): Flags=0x01 (S-bit=1), RCODE1=0, RCODE2=0
        opt81_bytes = b"\x01\x00\x00" + fqdn.encode("ascii")
        options.append((81, opt81_bytes))

    options.append(
        ("end", b"")
    )

    pkt = (
        ether
        / ip
        / udp
        / bootp
        / DHCP(options=options)
    )

    print(
        f"Sending {count} DHCP {msg_type.upper()} packet(s) "
        f"on iface {iface} with MAC {client_mac}"
    )

    sendp(
        pkt,
        iface=iface,
        count=count,
        verbose=True
    )


def main():

    parser = argparse.ArgumentParser(
        description="Send DHCP or BOOTP packets using Scapy"
    )

    parser.add_argument(
        "--iface",
        required=True,
        help='Interface name, e.g. "Ethernet" or "Беспроводная сеть"'
    )

    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of packets to send"
    )

    parser.add_argument(
        "--type",
        choices=[
            "discover",
            "request",
            "bootp"
        ],
        default="discover",
        help="Packet type: discover, request or bootp"
    )

    parser.add_argument(
        "--mac",
        help="Client MAC address, e.g. 00:11:22:33:44:55"
    )

    parser.add_argument(
        "--requested-ip",
        help="Requested IP address for DHCPREQUEST"
    )

    parser.add_argument(
        "--fqdn",
        help="Client FQDN for Option 81, e.g. C50-100-6165.fbp.bank.gov.ua"
    )

    args = parser.parse_args()

    if IS_WINDOWS and not is_admin():

        print(
            "WARNING: On Windows this script should be run "
            "as Administrator with Npcap installed."
        )

    send_dhcp(
        args.iface,
        args.count,
        args.type,
        client_mac=args.mac,
        requested_ip=args.requested_ip,
        fqdn=args.fqdn
    )


if __name__ == "__main__":
    main()
    