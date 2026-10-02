import argparse
import random

from scapy.all import (
    Ether,
    IP,
    UDP,
    BOOTP,
    DHCP,
    sendp,
    AsyncSniffer,
    get_if_hwaddr,
    conf,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--mac")
    args = parser.parse_args()

    iface = args.iface
    conf.iface = iface

    mac = args.mac or get_if_hwaddr(iface)
    chaddr = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    xid = random.randint(0, 0xFFFFFFFF)

    print(f"Interface : {iface}")
    print(f"MAC       : {mac}")
    print(f"XID       : 0x{xid:08x}")
    print()
    print("Listening for DHCP/PXE responses...")

    pkt = (
        Ether(
            src=mac,
            dst="ff:ff:ff:ff:ff:ff"
        )
        / IP(
            src="0.0.0.0",
            dst="255.255.255.255"
        )
        / UDP(
            sport=68,
            dport=67
        )
        / BOOTP(
            op=1,
            htype=1,
            hlen=6,
            xid=xid,
            flags=0x8000,
            chaddr=chaddr + b"\x00" * 10
        )
        / DHCP(
            options=[
                ("message-type", "discover"),
                ("end", b"")
            ]
        )
    )

    sniffer = AsyncSniffer(
        iface=iface,
        filter="udp and (port 67 or port 68 or port 4011)"
    )

    sniffer.start()

    print("Sending DHCPDISCOVER...")

    sendp(
        pkt,
        iface=iface,
        verbose=False
    )

    sniffer.join(timeout=8)
    packets = sniffer.stop()

    print()
    print(f"Captured packets: {len(packets)}")

    for i, p in enumerate(packets, 1):
        if not p.haslayer(BOOTP):
            continue

        bootp = p[BOOTP]

        print()
        print(f"--- Packet {i} ---")
        print(p.summary())

        print(f"Source IP : {p[IP].src}")
        print(f"UDP       : {p[UDP].sport} -> {p[UDP].dport}")
        print(f"XID       : 0x{bootp.xid:08x}")

        if bootp.xid != xid:
            print("XID       : different")
        
        file_name = bytes(bootp.file).split(b"\x00", 1)[0]

        if file_name:
            print(f"BOOTP file: {file_name!r}")

        if p.haslayer(DHCP):
            for option in p[DHCP].options:
                if option == "end" or option == "pad":
                    continue
    
                print(f"DHCP      : {option}")

                if (
                    isinstance(option, tuple)
                    and (
                        option[0] == "boot-file-name"
                        or option[0] == 67
                    )
                ):
                    print(f"OPTION 67 : {option[1]!r}")


if __name__ == "__main__":
    main()
    