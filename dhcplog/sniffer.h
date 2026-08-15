#pragma once

#include <string>
#include <Windows.h>
#include <thread>
#include <atomic>
#include "logger.h"

class DhcpSniffer {
public:
    DhcpSniffer(
        HWND mainWnd,
        LogManager* logger,
        const std::string& interfaceName);

    ~DhcpSniffer();

    void Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    void run();

    HWND mainWnd_;
    LogManager* logger_;
    std::string interfaceName_;
    std::thread thread_;
    std::atomic<bool> running_;
};
