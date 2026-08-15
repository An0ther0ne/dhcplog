#include "sniffer.h"
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <atomic>
#include <chrono>
#include <cstring>
#include <algorithm>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif

static std::string nowTimestamp()
{
    using namespace std::chrono;

    auto t = system_clock::to_time_t(system_clock::now());

    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    tm = *std::localtime(&t);
#endif

    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

static std::string macToString(const unsigned char* mac)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');

    for (int i = 0; i < 6; ++i) {
        if (i) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }

    ss << std::dec;
    return ss.str();
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

void DhcpSniffer::run()
{
#ifdef HAVE_PCAP

    char errbuf[PCAP_ERRBUF_SIZE]{};

    pcap_t* handle = pcap_open_live(
        interfaceName_.c_str(),
        65536,
        1,
        1000,
        errbuf);

    if (!handle) {
        logger_->Log(
            nowTimestamp() +
            " ERROR: pcap_open_live failed: " +
            std::string(errbuf));

        return;
    }

    // DHCP / BOOTP: UDP ports 67 and 68.
    struct bpf_program fp;

    if (pcap_compile(
        handle,
        &fp,
        "udp and (port 67 or port 68)",
        1,
        PCAP_NETMASK_UNKNOWN) == 0) {

        if (pcap_setfilter(handle, &fp) != 0) {
            logger_->Log(
                nowTimestamp() +
                " ERROR: pcap_setfilter failed: " +
                std::string(pcap_geterr(handle)));

            pcap_freecode(&fp);
            pcap_close(handle);
            return;
        }

        pcap_freecode(&fp);
    }
    else {
        logger_->Log(
            nowTimestamp() +
            " ERROR: pcap_compile failed: " +
            std::string(pcap_geterr(handle)));

        pcap_close(handle);
        return;
    }

    logger_->Log(
        nowTimestamp() +
        " INFO: pcap capture started on device: " +
        interfaceName_);

    while (running_) {

        struct pcap_pkthdr* header = nullptr;
        const u_char* pkt = nullptr;

        int res = pcap_next_ex(
            handle,
            &header,
            &pkt);

        if (res == 0)
            continue;

        if (res < 0) {
            logger_->Log(
                nowTimestamp() +
                " ERROR: pcap_next_ex failed: " +
                std::string(pcap_geterr(handle)));

            break;
        }

        std::ostringstream entry;

        entry << nowTimestamp()
            << " CAPTURE len=" << header->len
            << " caplen=" << header->caplen;

        if (header->caplen >= 14) {
            const unsigned char* eth = pkt;

            entry << " SRC_MAC="
                << macToString(eth + 6)
                << " DST_MAC="
                << macToString(eth + 0);
        }

        int toDump = static_cast<int>(
            std::min<size_t>(128, header->caplen));

        entry << " DATA=";

        for (int i = 0; i < toDump; ++i) {
            entry << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<int>(pkt[i]);
        }

        entry << std::dec;

        logger_->Log(entry.str());
    }

    pcap_close(handle);

#else

    logger_->Log(
        nowTimestamp() +
        " ERROR: DHCP/BOOTP capture is unavailable: "
        "program was built without HAVE_PCAP");

#endif
}
