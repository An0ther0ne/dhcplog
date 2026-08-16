dhcplog — simple DHCP/BOOTP logger
=================================

Overview
--------
dhcplog is a small Windows C++ application that can capture and log DHCP/BOOTP messages from a network interface. The repository also includes a helper script send_dhcp.py to send test DHCP packets (Scapy).

Key files
---------
- dhcplog.sln / dhcplog.vcxproj — Visual Studio solution and project
- dhcplog/sniffer.cpp, dhcplog/sniffer.h — packet capture logic
- dhcplog/logger.* — logging implementation
- send_dhcp.py — Python script to send test DHCP packets (Scapy)

Requirements
------------
- Windows 10/11
- Microsoft Visual Studio (MSVC) to build the project
- For live packet capture: Npcap (install with "WinPcap API‑compatible mode")
- For sending test packets: Python 3 and scapy (pip install scapy)

Build (Visual Studio)
----------------------
1. Open dhcplog.sln in Visual Studio.
2. (Optional) To enable pcap support using WinPcap/Npcap:
   - Install Npcap and optionally the Npcap SDK.
   - Project Properties -> C/C++ -> Preprocessor -> add HAVE_PCAP
   - Project Properties -> C/C++ -> Additional Include Directories: add Npcap\\Include (e.g. C:\\Program Files\\Npcap\\Include)
   - Project Properties -> Linker -> Additional Library Directories: add Npcap\\Lib\\<x86|x64>
   - Project Properties -> Linker -> Input -> Additional Dependencies: add wpcap.lib;Packet.lib;Ws2_32.lib
   - Rebuild the project.
3. Build the solution (Build -> Build Solution).

Run and test
------------
1. Run the built dhcplog.exe as Administrator (admin rights are required for packet capture).
2. To send test DHCP packets (to verify logging):
   - Install Python 3 and Npcap (WinPcap-compatible).
   - Open an elevated terminal in the project folder and install scapy:
	 pip install scapy
   - Find the interface name (use netsh or Scapy):
	 netsh interface show interface
	 (copy the exact value from the "Interface Name" column, e.g. "Wi‑Fi" or "Беспроводная сеть")
   - Run the example (using the interface name you found):
	 python .\\send_dhcp.py --iface "Беспроводная сеть" --count 3 --type discover --mac 44:6D:57:2E:F3:6A

Security and permissions
------------------------
- Sending DHCP packets on a network can affect local DHCP servers. Use this only on test or isolated networks.
- Capturing raw packets (SIO_RCVALL) or using pcap requires Administrator privileges.

Troubleshooting
---------------
- If the application does not log packets, check whether the project was built with HAVE_PCAP (if you expect to use pcap) or whether SIO_RCVALL (raw sockets) is permitted on your Windows version.
- If send_dhcp.py does not send packets, ensure Npcap is installed and you run the terminal as Administrator.

Contact
-------
This is a local project in your repository. For further changes or issues, open issues in your remote repository.

---
This README was generated automatically. If you need a more detailed README or additional examples, tell me which sections to add.
