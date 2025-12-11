#pragma once

#include "http/HttpRequest.hpp"
#include "http/HttpResponse.hpp"
#include <functional>
#include <vector>
#include <string>
#include <memory>
#include <regex>

namespace http_server {
namespace http {

using RequestHandler = std::function<HttpResponse(HttpRequest&)>;

struct RouteEntry {
    HttpMethod method;
    std::string pattern;
    std::regex regex;
    std::vector<std::string> paramNames;
    RequestHandler handler;
};

class HttpRouter {
public:
    HttpRouter();

    void Get(const std::string& pattern, RequestHandler handler);
    void Post(const std::string& pattern, RequestHandler handler);
    void Put(const std::string& pattern, RequestHandler handler);
    void Delete(const std::string& pattern, RequestHandler handler);
    void AddRoute(HttpMethod method, const std::string& pattern, RequestHandler handler);

    HttpResponse Route(HttpRequest& request);

    void SetNotFoundHandler(RequestHandler handler);
    void SetMethodNotAllowedHandler(RequestHandler handler);

private:
    struct ParsedPattern {
        std::regex regex;
        std::vector<std::string> paramNames;
    };

    ParsedPattern ParsePattern(const std::string& pattern);
    bool MatchRoute(const RouteEntry& route, const std::string& path, HttpRequest& request);

    std::vector<RouteEntry> m_routes;
    RequestHandler m_notFoundHandler;
    RequestHandler m_methodNotAllowedHandler;
};

} // namespace http
} // namespace http_server
