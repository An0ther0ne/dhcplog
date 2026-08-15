#include "logger.h"
#include <Windows.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>

using namespace std::chrono;

static std::string timeSuffixDaily()
{
	auto t = system_clock::to_time_t(system_clock::now());
	std::tm tm;
#ifdef _WIN32
	localtime_s(&tm, &t);
#else
	tm = *std::localtime(&t);
#endif
	std::ostringstream ss;
	ss << std::put_time(&tm, "%Y-%m-%d");
	return ss.str();
}

static std::string timeSuffixWeekly()
{
	auto now = system_clock::now();
	auto t = system_clock::to_time_t(now);
	std::tm tm;
#ifdef _WIN32
	localtime_s(&tm, &t);
#else
	tm = *std::localtime(&t);
#endif
	// ISO week-based year-week number would need more work; use year-weekofyear
	int wday = (tm.tm_yday + 7 - tm.tm_wday) / 7 + 1;
	std::ostringstream ss;
	ss << (1900 + tm.tm_year) << "-W" << wday;
	return ss.str();
}

LogManager::LogManager(const std::wstring& dir, Rotation r, HWND mainWnd)
	: directory_(dir), rotation_(r), running_(false)
{
	std::filesystem::create_directories(directory_);
	mainWnd_ = mainWnd;
}

LogManager::~LogManager()
{
	Stop();
}

void LogManager::Start()
{
	std::lock_guard<std::mutex> lk(mutex_);
	if (running_) return;
	running_ = true;
	openNewFile();
}

void LogManager::Stop()
{
	std::lock_guard<std::mutex> lk(mutex_);
	running_ = false;
	if (out_.is_open()) out_.close();
}

void LogManager::SetRotation(Rotation r)
{
	std::lock_guard<std::mutex> lk(mutex_);
	rotation_ = r;
	// force new file next write
	currentSuffix_.clear();
}

void LogManager::rotateIfNeeded()
{
	std::string suffix = (rotation_ == Rotation::Daily) ? timeSuffixDaily() : timeSuffixWeekly();
	if (suffix != currentSuffix_)
	{
		if (out_.is_open()) out_.close();
		currentSuffix_ = suffix;
		openNewFile();
	}
}

void LogManager::openNewFile()
{
	std::string suffix = (rotation_ == Rotation::Daily) ? timeSuffixDaily() : timeSuffixWeekly();
	currentSuffix_ = suffix;
	std::ostringstream file;
	// convert dir to narrow string
	std::wstring wname = directory_ + L"/dhcp_log_" + std::wstring(currentSuffix_.begin(), currentSuffix_.end()) + L".log";
	std::string name;
	name.assign(wname.begin(), wname.end());
	out_.open(name, std::ios::out | std::ios::app);
}

void LogManager::Log(const std::string& line)
{
	std::lock_guard<std::mutex> lk(mutex_);
	if (!running_) Start();
	rotateIfNeeded();
	if (out_.is_open())
	{
		out_ << line << "\n";
		out_.flush();
	}
	// post to UI if available
	if (mainWnd_) {
		// allocate a copy for the UI thread
		std::string* p = new std::string(line);
		PostMessageA(mainWnd_, WM_APP+1, 0, (LPARAM)p);
	}
}
