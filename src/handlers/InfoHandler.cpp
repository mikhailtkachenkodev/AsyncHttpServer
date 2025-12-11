#include "handlers/InfoHandler.hpp"
#include "utils/SystemInfo.hpp"
#include <nlohmann/json.hpp>
#include <iomanip>
#include <sstream>

namespace http_server {
namespace handlers {

InfoHandler::InfoHandler()
    : m_version("1.0")
    , m_startTime(std::chrono::system_clock::now())
    , m_connectionCounter([]() { return 0; }) {
}

http::HttpResponse InfoHandler::Handle(http::HttpRequest& /*request*/) {
    auto sysInfo = utils::SystemInfo::GetSystemInfo();

    nlohmann::json response = {
        {"version", m_version},
        {"started", FormatStartTime()},
        {"platform", utils::SystemInfo::GetPlatformName()},
        {"connections", m_connectionCounter()},
        {"system", utils::SystemInfo::ToJson(sysInfo)}
    };

    return http::HttpResponse::Json(response);
}

std::string InfoHandler::FormatStartTime() const {
    auto time = std::chrono::system_clock::to_time_t(m_startTime);
    std::tm tm_buf;
    gmtime_s(&tm_buf, &time);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace handlers
} // namespace http_server
