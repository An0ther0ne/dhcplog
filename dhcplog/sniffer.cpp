#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include "sniffer.h"

#include <sstream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")

static std::string nowTimestamp()
{
    using namespace std::chrono;

    auto t = system_clock::to_time_t(system_clock::now());

    std::tm tm;
    localtime_s(&tm, &t);

    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

static std::string ipToString(uint32_t netOrderIp)
{
    in_addr addr{};
    addr.s_addr = netOrderIp;

    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

// DHCP/BOOTP fixed header is 236 bytes, followed by a 4-byte magic
// cookie (63 82 53 63) and options for DHCP. Plain BOOTP has neither.
static std::string DhcpMessageType(const unsigned char* payload, int len)
{
    if (len < 1)
        return "?";

    const char* opName =
        (payload[0] == 1) ? "BOOTREQUEST" :
        (payload[0] == 2) ? "BOOTREPLY" : "BOOTP?";

    if (len < 240)
        return opName;

    static const unsigned char cookie[4] = { 0x63, 0x82, 0x53, 0x63 };

    if (memcmp(payload + 236, cookie, 4) != 0)
        return opName;

    // Walk options for tag 53 (DHCP Message Type).
    int i = 240;

    while (i < len) {

        unsigned char tag = payload[i];

        if (tag == 0xFF)
            break;

        if (tag == 0x00) {
            ++i;
            continue;
        }

        if (i + 1 >= len)
            break;

        unsigned char optLen = payload[i + 1];

        if (tag == 53 && optLen >= 1 && i + 2 < len) {

            switch (payload[i + 2]) {
            case 1: return "DHCPDISCOVER";
            case 2: return "DHCPOFFER";
            case 3: return "DHCPREQUEST";
            case 4: return "DHCPDECLINE";
            case 5: return "DHCPACK";
            case 6: return "DHCPNAK";
            case 7: return "DHCPRELEASE";
            case 8: return "DHCPINFORM";
            default: return "DHCP(type=" + std::to_string(payload[i + 2]) + ")";
            }
        }

        i += 2 + optLen;
    }

    // Magic cookie present, but no option 53 -- still DHCP framing.
    return std::string("DHCP/") + opName;
}

// Appends one 16-byte hex dump line: 8 bytes, 2-space gap, 8 bytes,
// 4-space gap, ASCII column. lineLen is 1..16 (bytes actually
// present); missing slots on the last line are left blank so the
// ASCII column still lines up.
static void AppendHexDumpLine(
    std::ostringstream& out,
    const unsigned char* data,
    int lineLen)
{
    out << std::hex << std::uppercase << std::setfill('0');

    for (int col = 0; col < 16; ++col) {

        if (col < lineLen)
            out << std::setw(2) << static_cast<int>(data[col]);
        else
            out << "  ";

        if (col == 7)
            out << "  ";
        else if (col != 15)
            out << " ";
    }

    out << std::dec << std::nouppercase << "    ";

    for (int col = 0; col < lineLen; ++col) {
        unsigned char b = data[col];
        out << (b >= 0x20 && b < 0x7F ? static_cast<char>(b) : '.');
    }
}

DhcpSniffer::DhcpSniffer(
    HWND mainWnd,
    LogManager* logger,
    const std::string& interfaceName)
    : mainWnd_(mainWnd),
    logger_(logger),
    interfaceName_(interfaceName),
    running_(false)
{
}

DhcpSniffer::~DhcpSniffer()
{
    Stop();
}

void DhcpSniffer::Start()
{
    if (running_) return;

    running_ = true;
    thread_ = std::thread(&DhcpSniffer::run, this);
}

void DhcpSniffer::Stop()
{
    if (!running_) return;

    running_ = false;

    if (thread_.joinable())
        thread_.join();
}

// interfaceName_ holds the dotted IPv4 address of the selected
// adapter (see NetworkAdapter::ipv4 in dhcplog.cpp) -- raw sockets
// bind to an IP, not to a device name.
void DhcpSniffer::run()
{
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if (sock == INVALID_SOCKET) {
        logger_->Log(
            nowTimestamp() +
            " ERROR: socket() failed: " +
            std::to_string(WSAGetLastError()));

        return;
    }

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;

    if (inet_pton(AF_INET, interfaceName_.c_str(), &bindAddr.sin_addr) != 1) {

        logger_->Log(
            nowTimestamp() +
            " ERROR: invalid interface IPv4 address: " +
            interfaceName_);

        closesocket(sock);
        return;
    }

    if (bind(
        sock,
        reinterpret_cast<sockaddr*>(&bindAddr),
        sizeof(bindAddr)) == SOCKET_ERROR) {

        logger_->Log(
            nowTimestamp() +
            " ERROR: bind() failed: " +
            std::to_string(WSAGetLastError()));

        closesocket(sock);
        return;
    }

    DWORD hdrIncl = TRUE;

    setsockopt(
        sock,
        IPPROTO_IP,
        IP_HDRINCL,
        reinterpret_cast<char*>(&hdrIncl),
        sizeof(hdrIncl));

    // RCVALL_IPLEVEL: deliver every IP packet the NIC already
    // receives (unicast to us, broadcast, multicast) without
    // switching the adapter into true NIC promiscuous mode.
    // DHCP/BOOTP traffic is broadcast or addressed to us, so this
    // is sufficient and works on adapters (Wi-Fi, virtual) that
    // don't support real promiscuous mode. If it doesn't capture
    // anything on a given adapter, switch this to RCVALL_ON.
    DWORD rcvAll = RCVALL_IPLEVEL;
    DWORD bytesReturned = 0;

    if (WSAIoctl(
        sock,
        SIO_RCVALL,
        &rcvAll,
        sizeof(rcvAll),
        nullptr,
        0,
        &bytesReturned,
        nullptr,
        nullptr) == SOCKET_ERROR) {

        logger_->Log(
            nowTimestamp() +
            " ERROR: SIO_RCVALL failed (потрібні права адміністратора): " +
            std::to_string(WSAGetLastError()));

        closesocket(sock);
        return;
    }

    logger_->Log(
        nowTimestamp() +
        " INFO: raw capture started on " +
        interfaceName_);

    // Recv timeout so the loop notices Stop() promptly instead of
    // blocking indefinitely on recv().
    DWORD timeout = 500;

    setsockopt(
        sock,
        SOL_SOCKET,
        SO_RCVTIMEO,
        reinterpret_cast<char*>(&timeout),
        sizeof(timeout));

    std::vector<unsigned char> buffer(65536);

    while (running_) {

        int received = recv(
            sock,
            reinterpret_cast<char*>(buffer.data()),
            static_cast<int>(buffer.size()),
            0);

        if (received == SOCKET_ERROR) {

            int err = WSAGetLastError();

            if (err == WSAETIMEDOUT)
                continue;

            logger_->Log(
                nowTimestamp() +
                " ERROR: recv() failed: " +
                std::to_string(err));

            break;
        }

        if (received < 20)
            continue;

        const unsigned char* ip = buffer.data();

        int ipHeaderLen = (ip[0] & 0x0F) * 4;

        if (ip[9] != IPPROTO_UDP)
            continue;

        if (received < ipHeaderLen + 8)
            continue;

        const unsigned char* udp = ip + ipHeaderLen;

        uint16_t srcPort = (udp[0] << 8) | udp[1];
        uint16_t dstPort = (udp[2] << 8) | udp[3];

        if (srcPort != 67 && srcPort != 68 &&
            dstPort != 67 && dstPort != 68)
            continue;

        uint32_t srcIpRaw;
        uint32_t dstIpRaw;

        memcpy(&srcIpRaw, ip + 12, 4);
        memcpy(&dstIpRaw, ip + 16, 4);

        const unsigned char* payload = udp + 8;
        int payloadLen = received - ipHeaderLen - 8;

        std::ostringstream entry;

        entry << nowTimestamp()
            << " CAPTURE len=" << received
            << " SRC=" << ipToString(srcIpRaw) << ":" << srcPort
            << " DST=" << ipToString(dstIpRaw) << ":" << dstPort
            << " TYPE=" << DhcpMessageType(payload, payloadLen);

        int toDump = (std::min)(128, payloadLen);

        for (int offset = 0; offset < toDump; offset += 16) {

            int lineLen = (std::min)(16, toDump - offset);

            entry << "\r\n";

            AppendHexDumpLine(entry, payload + offset, lineLen);
        }

        logger_->Log(entry.str());
    }

    DWORD rcvOff = RCVALL_OFF;

    WSAIoctl(
        sock,
        SIO_RCVALL,
        &rcvOff,
        sizeof(rcvOff),
        nullptr,
        0,
        &bytesReturned,
        nullptr,
        nullptr);

    closesocket(sock);
}

