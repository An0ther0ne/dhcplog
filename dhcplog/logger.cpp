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

bool LogManager::rotateIfNeeded()
{
	std::string suffix = (rotation_ == Rotation::Daily) ? timeSuffixDaily() : timeSuffixWeekly();
	if (suffix != currentSuffix_)
	{
		if (out_.is_open()) out_.close();
		currentSuffix_ = suffix;
		openNewFile();
		return true;
	}

	return false;
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

void LogManager::ForceRotate()
{
	try {
		std::function<void()> cb;

		{
			std::lock_guard<std::mutex> lk(mutex_);

			// If no file open, just open new file
			if (!out_.is_open()) {
				openNewFile();
				cb = rotationCallback_;
				// call callback outside lock
			}
			else {
				// Close current file and attempt to rename it with a timestamp
				out_.close();

				// currentSuffix_ holds the logical suffix used for filenames
				std::wstring wold = directory_ + L"/dhcp_log_" + std::wstring(currentSuffix_.begin(), currentSuffix_.end()) + L".log";
				std::ostringstream ts;
				auto t = system_clock::to_time_t(system_clock::now());
				std::tm tm;
#ifdef _WIN32
				localtime_s(&tm, &t);
#else
				tm = *std::localtime(&t);
#endif
				ts << std::put_time(&tm, "%Y%m%d_%H%M%S");

				std::wstring wnew = wold + L"." + std::wstring(ts.str().begin(), ts.str().end());

				try {
					std::filesystem::rename(wold, wnew);
				}
				catch (...) {
					// ignore rename errors; file may be locked. Proceed to open new file anyway.
				}

				// open a fresh file (will recreate base filename)
				openNewFile();
				cb = rotationCallback_;
			}
		}

		if (cb) {
			try { cb(); } catch (...) { /* swallow callback exceptions */ }
		}
	}
	catch (const std::exception& ex) {
		// Ensure no exception escapes; write to debug output instead of calling Log()
		std::string msg = "LogManager::ForceRotate exception: ";
		msg += ex.what();
		OutputDebugStringA(msg.c_str());
	}
	catch (...) {
		OutputDebugStringA("LogManager::ForceRotate unknown exception\n");
	}
}

void LogManager::SetRotationCallback(std::function<void()> cb)
{
	std::lock_guard<std::mutex> lk(mutex_);
	rotationCallback_ = std::move(cb);
}

void LogManager::Log(const std::string& line)
{
	// Ensure logger is started outside the mutex to avoid deadlock with Start()
	if (!running_) Start();

	std::function<void()> cb;
	bool rotated = false;

	{
		std::lock_guard<std::mutex> lk(mutex_);
		rotated = rotateIfNeeded();
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
		cb = rotationCallback_;
	}

	if (rotated && cb) {
		try { cb(); } catch (...) { /* swallow to avoid throwing from logger */ }
	}
}
