#pragma once

#include <string>
#include <Windows.h>
#include <pcap.h>
#include <thread>
#include <atomic>
#include "logger.h"

class DhcpSniffer {
public:
    DhcpSniffer(
        HWND mainWnd,
        LogManager* logger,
        const std::string& interfaceName,
        const std::string& npcapDevice);

    ~DhcpSniffer();

    void Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    void run();
    void runRawSocket();
    bool runNpcap();

    HWND mainWnd_;
    LogManager* logger_;
    std::string interfaceName_;
    std::string npcapDevice_;
    std::thread thread_;
    std::atomic<bool> running_;
    pcap_t* pcap_ = nullptr;
};
