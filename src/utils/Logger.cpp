#include "utils/Logger.hpp"

namespace http_server {
namespace utils {

LogLevel Logger::s_level = LogLevel::Info;
std::mutex Logger::s_mutex;

void Logger::SetLevel(LogLevel level) {
    s_level = level;
}

LogLevel Logger::GetLevel() {
    return s_level;
}

void Logger::Debug(const std::string& message) {
    Log(LogLevel::Debug, message);
}

void Logger::Info(const std::string& message) {
    Log(LogLevel::Info, message);
}

void Logger::Warning(const std::string& message) {
    Log(LogLevel::Warning, message);
}

void Logger::Error(const std::string& message) {
    Log(LogLevel::Error, message);
}

void Logger::Log(LogLevel level, const std::string& message) {
    if (level < s_level) {
        return;
    }

    std::lock_guard<std::mutex> lock(s_mutex);

    std::ostream& out = (level >= LogLevel::Warning) ? std::cerr : std::cout;
    out << "[" << GetTimestamp() << "] [" << LevelToString(level) << "] " << message << std::endl;
}

std::string Logger::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_buf;
    localtime_s(&tm_buf, &time);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::string Logger::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Info:    return "INFO ";
        case LogLevel::Warning: return "WARN ";
        case LogLevel::Error:   return "ERROR";
        default:                return "?????";
    }
}

} // namespace utils
} // namespace http_server
