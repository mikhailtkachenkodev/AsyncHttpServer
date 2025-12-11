#include "http/HttpRouter.hpp"
#include <sstream>

namespace http_server {
namespace http {

HttpRouter::HttpRouter() {
    m_notFoundHandler = [](HttpRequest&) {
        return HttpResponse::NotFound();
    };

    m_methodNotAllowedHandler = [](HttpRequest&) {
        return HttpResponse::MethodNotAllowed();
    };
}

void HttpRouter::Get(const std::string& pattern, RequestHandler handler) {
    AddRoute(HttpMethod::GET, pattern, std::move(handler));
}

void HttpRouter::Post(const std::string& pattern, RequestHandler handler) {
    AddRoute(HttpMethod::POST, pattern, std::move(handler));
}

void HttpRouter::Put(const std::string& pattern, RequestHandler handler) {
    AddRoute(HttpMethod::PUT, pattern, std::move(handler));
}

void HttpRouter::Delete(const std::string& pattern, RequestHandler handler) {
    AddRoute(HttpMethod::DELETE_, pattern, std::move(handler));
}

void HttpRouter::AddRoute(HttpMethod method, const std::string& pattern, RequestHandler handler) {
    RouteEntry route;
    route.method = method;
    route.pattern = pattern;
    route.handler = std::move(handler);

    auto parsed = ParsePattern(pattern);
    route.regex = std::move(parsed.regex);
    route.paramNames = std::move(parsed.paramNames);

    m_routes.push_back(std::move(route));
}

HttpResponse HttpRouter::Route(HttpRequest& request) {
    const std::string& path = request.GetPath();
    bool pathMatched = false;

    for (auto& route : m_routes) {
        if (MatchRoute(route, path, request)) {
            pathMatched = true;
            if (route.method == request.GetMethod()) {
                try {
                    return route.handler(request);
                } catch (const std::exception& e) {
                    return HttpResponse::InternalServerError(e.what());
                } catch (...) {
                    return HttpResponse::InternalServerError();
                }
            }
        }
    }

    if (pathMatched) {
        return m_methodNotAllowedHandler(request);
    }

    return m_notFoundHandler(request);
}

void HttpRouter::SetNotFoundHandler(RequestHandler handler) {
    m_notFoundHandler = std::move(handler);
}

void HttpRouter::SetMethodNotAllowedHandler(RequestHandler handler) {
    m_methodNotAllowedHandler = std::move(handler);
}

HttpRouter::ParsedPattern HttpRouter::ParsePattern(const std::string& pattern) {
    ParsedPattern result;
    std::string regexStr = "^";
    std::string current;

    for (size_t i = 0; i < pattern.size(); ++i) {
        char c = pattern[i];

        if (c == ':') {
            regexStr += current;
            current.clear();

            std::string paramName;
            ++i;
            while (i < pattern.size() && pattern[i] != '/') {
                paramName += pattern[i];
                ++i;
            }
            --i;

            result.paramNames.push_back(paramName);
            regexStr += "([^/]+)";
        } else if (c == '*') {
            regexStr += current;
            current.clear();
            regexStr += ".*";
        } else if (c == '.' || c == '[' || c == ']' || c == '(' || c == ')' ||
                   c == '{' || c == '}' || c == '\\' || c == '^' || c == '$' ||
                   c == '|' || c == '?' || c == '+') {
            current += '\\';
            current += c;
        } else {
            current += c;
        }
    }

    regexStr += current;
    regexStr += "$";

    result.regex = std::regex(regexStr);
    return result;
}

bool HttpRouter::MatchRoute(const RouteEntry& route, const std::string& path, HttpRequest& request) {
    std::smatch match;
    if (!std::regex_match(path, match, route.regex)) {
        return false;
    }

    for (size_t i = 0; i < route.paramNames.size() && i + 1 < match.size(); ++i) {
        request.SetPathParam(route.paramNames[i], match[i + 1].str());
    }

    return true;
}

} // namespace http
} // namespace http_server
