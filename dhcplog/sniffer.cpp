#include "sniffer.h"
#include <Windows.h>
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <atomic>
#include <chrono>
#include <cstring>

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

DhcpSniffer::DhcpSniffer(HWND mainWnd, LogManager* logger)
	: mainWnd_(mainWnd), logger_(logger), running_(false)
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
	if (thread_.joinable()) thread_.join();
}

void DhcpSniffer::run()
{
#ifdef HAVE_PCAP
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldevs;
	if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
		logger_->Log(nowTimestamp() + " ERROR: no pcap devices found: " + std::string(errbuf));
		return;
	}
	// pick the first device
	pcap_if_t* dev = alldevs;
	pcap_t* handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	if (!handle) {
		logger_->Log(nowTimestamp() + " ERROR: pcap_open_live failed: " + std::string(errbuf));
		pcap_freealldevs(alldevs);
		return;
	}

	// apply filter for dhcp/bootp (UDP port 67 or 68)
	struct bpf_program fp;
	if (pcap_compile(handle, &fp, "udp and (port 67 or port 68)", 1, PCAP_NETMASK_UNKNOWN) == 0) {
		pcap_setfilter(handle, &fp);
		pcap_freecode(&fp);
	}

	logger_->Log(nowTimestamp() + " INFO: pcap capture started on device: " + std::string(dev->name));

	pcap_freealldevs(alldevs);

	while (running_) {
		struct pcap_pkthdr* header;
		const u_char* pkt;
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res <= 0) continue;
		std::ostringstream entry;
		entry << nowTimestamp() << " CAPTURE len=" << header->len << " caplen=" << header->caplen;
		if (header->caplen >= 14) {
			const unsigned char* eth = pkt;
			entry << " SRC_MAC=" << macToString(eth + 6) << " DST_MAC=" << macToString(eth + 0);
		}
		// dump first 128 bytes of payload hex
		int toDump = std::min((size_t)128, (size_t)header->caplen);
		entry << " DATA=";
		for (int i = 0; i < toDump; ++i) {
			entry << std::hex << std::setw(2) << std::setfill('0') << (int)pkt[i];
		}
		entry << std::dec;
		logger_->Log(entry.str());
	}

	pcap_close(handle);
#else
	// pcap not available in this build: do not spam the log with an INFO line
	// keep the thread alive without logging
	while (running_) {
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}
#endif
}
