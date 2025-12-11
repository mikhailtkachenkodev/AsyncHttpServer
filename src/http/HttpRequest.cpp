#include "http/HttpRequest.hpp"
#include <algorithm>
#include <cctype>

namespace http_server {
namespace http {

namespace {
    std::string ToLowerCase(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    std::string UrlDecode(const std::string& str) {
        std::string result;
        result.reserve(str.size());

        for (size_t i = 0; i < str.size(); ++i) {
            if (str[i] == '%' && i + 2 < str.size()) {
                int value;
                if (sscanf_s(str.substr(i + 1, 2).c_str(), "%x", &value) == 1) {
                    result += static_cast<char>(value);
                    i += 2;
                } else {
                    result += str[i];
                }
            } else if (str[i] == '+') {
                result += ' ';
            } else {
                result += str[i];
            }
        }

        return result;
    }
}

std::optional<std::string> HttpRequest::GetHeader(const std::string& name) const {
    auto it = m_headers.find(ToLowerCase(name));
    if (it != m_headers.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool HttpRequest::HasHeader(const std::string& name) const {
    return m_headers.find(ToLowerCase(name)) != m_headers.end();
}

std::optional<std::string> HttpRequest::GetPathParam(const std::string& name) const {
    auto it = m_pathParams.find(name);
    if (it != m_pathParams.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<std::string> HttpRequest::GetQueryParam(const std::string& name) const {
    auto it = m_queryParams.find(name);
    if (it != m_queryParams.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t HttpRequest::GetContentLength() const {
    auto header = GetHeader("content-length");
    if (header) {
        try {
            return std::stoull(*header);
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

std::string HttpRequest::GetContentType() const {
    auto header = GetHeader("content-type");
    return header.value_or("");
}

bool HttpRequest::IsKeepAlive() const {
    auto connection = GetHeader("connection");
    if (connection) {
        std::string value = ToLowerCase(*connection);
        if (value == "close") {
            return false;
        }
        if (value == "keep-alive") {
            return true;
        }
    }

    return m_httpVersion == "HTTP/1.1";
}

void HttpRequest::SetPath(const std::string& path) {
    auto queryPos = path.find('?');
    if (queryPos != std::string::npos) {
        m_path = path.substr(0, queryPos);
        m_queryString = path.substr(queryPos + 1);
        ParseQueryString();
    } else {
        m_path = path;
        m_queryString.clear();
        m_queryParams.clear();
    }
}

void HttpRequest::AddHeader(const std::string& name, const std::string& value) {
    m_headers[ToLowerCase(name)] = value;
}

void HttpRequest::SetPathParam(const std::string& name, const std::string& value) {
    m_pathParams[name] = value;
}

void HttpRequest::SetQueryParam(const std::string& name, const std::string& value) {
    m_queryParams[name] = value;
}

void HttpRequest::Clear() {
    m_method = HttpMethod::UNKNOWN;
    m_path.clear();
    m_queryString.clear();
    m_httpVersion.clear();
    m_body.clear();
    m_headers.clear();
    m_pathParams.clear();
    m_queryParams.clear();
}

void HttpRequest::ParseQueryString() {
    m_queryParams.clear();

    if (m_queryString.empty()) {
        return;
    }

    size_t pos = 0;
    while (pos < m_queryString.size()) {
        size_t ampPos = m_queryString.find('&', pos);
        if (ampPos == std::string::npos) {
            ampPos = m_queryString.size();
        }

        std::string pair = m_queryString.substr(pos, ampPos - pos);
        size_t eqPos = pair.find('=');
        if (eqPos != std::string::npos) {
            std::string name = UrlDecode(pair.substr(0, eqPos));
            std::string value = UrlDecode(pair.substr(eqPos + 1));
            m_queryParams[name] = value;
        } else {
            m_queryParams[UrlDecode(pair)] = "";
        }

        pos = ampPos + 1;
    }
}

} // namespace http
} // namespace http_server
