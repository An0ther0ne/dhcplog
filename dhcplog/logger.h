#pragma once

#include <string>
#include <Windows.h>
#include <mutex>
#include <fstream>
#include <atomic>

class LogManager {
public:
	enum class Rotation { Daily, Weekly };
	LogManager(const std::wstring& dir = L".", Rotation r = Rotation::Daily, HWND mainWnd = nullptr);
	~LogManager();
	void Start();
	void Stop();
	void Log(const std::string& line);
	void SetRotation(Rotation r);
private:
	void rotateIfNeeded();
	void openNewFile();

	std::wstring directory_;
	Rotation rotation_;
	std::mutex mutex_;
	std::ofstream out_;    
	std::string currentSuffix_;
	std::atomic<bool> running_;
	HWND mainWnd_ = nullptr;
};
