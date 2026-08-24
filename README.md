# dhcplog — simple DHCP/BOOTP logger

## Overview

dhcplog is a small Windows C++ application that can capture and log DHCP/BOOTP messages from a network interface. The repository also includes a helper script `send_dhcp.py` to send test DHCP packets using Scapy.

## Key files

* `dhcplog.sln` / `dhcplog.vcxproj` — Visual Studio solution and project
* `dhcplog/sniffer.cpp`, `dhcplog/sniffer.h` — packet capture logic
* `dhcplog/logger.*` — logging implementation
* `send_dhcp.py` — Python script to send test DHCP packets (Scapy)
* `send_dhcp.v2.py` — extended version with BOOTP request support

## Requirements

* Windows 10/11, x64
* Microsoft Visual Studio (MSVC) to build the project
* Npcap runtime driver installed with "WinPcap API-compatible mode" — optional at runtime; the app falls back to a native Winsock raw-socket (SIO_RCVALL) capture backend if Npcap is not installed
* Python 3 and Scapy for sending test packets (`pip install scapy`)

## Build (Visual Studio)

1. Open `dhcplog.sln` in Visual Studio.
2. The Npcap SDK (headers + import libs) is vendored in the repository at `dhcplog/sdk` — no separate download or global install path is required to build. Project Properties (Configuration = x64) are already set to:

   * C/C++ → Additional Include Directories → `$(SolutionDir)sdk`
   * Linker → Additional Library Directories → `$(SolutionDir)sdk\lib`
   * Linker → Input → Additional Dependencies → `wpcap.lib;Packet.lib;Ws2_32.lib`
3. Build the solution for the **x64** platform (Build → Build Solution). Win32/x86 is not configured — only x64 libs are vendored in `dhcplog/sdk`.

At runtime, the app checks whether the Npcap driver is installed (via the `npcap` service in the Service Control Manager). If present, it captures through Npcap; otherwise it automatically falls back to the raw-socket (SIO_RCVALL) backend. No build-time toggle is needed — both backends are always compiled in.

## Run and test

1. Run the built `dhcplog.exe` as Administrator (admin rights are required for packet capture).
2. To send test DHCP packets:

   * Install Python 3 and Npcap (WinPcap-compatible).
   * Open an elevated terminal in the project folder and install Scapy:
     `pip install scapy`
   * Find the interface name:
     `netsh interface show interface`
     Copy the exact value from the "Interface Name" column, e.g. `Wi-Fi` or `Беспроводная сеть`.
   * Run TShark in parallel to monitor DHCP traffic:
     `tshark -i 5 -f "udp port 67 or udp port 68"`
   * Run the test example (v1 supports DHCP only):<br>
     `python .\send_dhcp.py --iface "Беспроводная сеть" --count 3 --type discover --mac 44:6D:57:2E:F3:6A`<br>
     `python .\send_dhcp.py --iface "Ethernet" --count 3 --type discover --mac 44:6D:57:2E:F3:6A`
   * BOOTP request example using version 2 (support both DHCP or BOOTP request type):<br>
     `python .\send_dhcp.v2.py --iface "Беспроводная сеть" --count 3 --type bootp --mac 44:6D:57:2E:F3:6A`<br>
	 `python .\send_dhcp.v2.py --iface "Ethernet" --count 3 --type discover --mac 44:6D:57:2E:F3:6A`
	 
## Security and permissions

* Sending DHCP packets on a network can affect local DHCP servers. Use this only on test or isolated networks.
* Capturing raw packets (SIO_RCVALL) or using pcap requires Administrator privileges.

## Troubleshooting

* The application log states which capture backend is active on startup: `Npcap detected, using pcap backend` or `Npcap not installed, using raw-socket (WinAPI) backend`.
* If Npcap is detected but `pcap_open_live failed` appears in the log, the app automatically falls back to the raw-socket backend (`falling back to raw-socket backend`) — capture continues, but check the Npcap installation (WinPcap API-compatible mode) and the reported error text if pcap capture specifically is required.
* If the application does not log packets on either backend, confirm it is running as Administrator — both `SIO_RCVALL` and Npcap capture require elevated privileges.
* If `send_dhcp.py` does not send packets, ensure Npcap is installed and the terminal is running as Administrator.

## Contact

This is a local project in your repository. For further changes or issues, open issues in your remote repository.
