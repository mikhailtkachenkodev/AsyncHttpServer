#pragma once

#include <string>
#include <mutex>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace http_server {
namespace utils {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

class Logger {
public:
    static void SetLevel(LogLevel level);
    static LogLevel GetLevel();

    static void Debug(const std::string& message);
    static void Info(const std::string& message);
    static void Warning(const std::string& message);
    static void Error(const std::string& message);

    static void Log(LogLevel level, const std::string& message);

private:
    static std::string GetTimestamp();
    static std::string LevelToString(LogLevel level);

    static LogLevel s_level;
    static std::mutex s_mutex;
};

} // namespace utils
} // namespace http_server
