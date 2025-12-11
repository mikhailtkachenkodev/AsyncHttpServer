#pragma once

#include "handlers/IRequestHandler.hpp"
#include <string>
#include <chrono>
#include <atomic>
#include <functional>

namespace http_server {
namespace handlers {

class InfoHandler : public IRequestHandler {
public:
    InfoHandler();

    http::HttpResponse Handle(http::HttpRequest& request) override;

    void SetVersion(const std::string& version) { m_version = version; }
    void SetConnectionCounter(std::function<int()> counter) { m_connectionCounter = std::move(counter); }

private:
    std::string m_version;
    std::chrono::system_clock::time_point m_startTime;
    std::function<int()> m_connectionCounter;

    std::string FormatStartTime() const;
};

} // namespace handlers
} // namespace http_server
