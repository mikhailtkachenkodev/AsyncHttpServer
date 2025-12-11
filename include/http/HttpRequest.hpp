#pragma once

#include "http/HttpStatus.hpp"
#include <string>
#include <unordered_map>
#include <optional>

namespace http_server {
namespace http {

class HttpRequest {
public:
    HttpRequest() = default;

    HttpMethod GetMethod() const { return m_method; }
    const std::string& GetPath() const { return m_path; }
    const std::string& GetHttpVersion() const { return m_httpVersion; }
    const std::string& GetBody() const { return m_body; }
    const std::string& GetQueryString() const { return m_queryString; }

    std::optional<std::string> GetHeader(const std::string& name) const;
    const std::unordered_map<std::string, std::string>& GetHeaders() const { return m_headers; }
    bool HasHeader(const std::string& name) const;

    std::optional<std::string> GetPathParam(const std::string& name) const;
    const std::unordered_map<std::string, std::string>& GetPathParams() const { return m_pathParams; }

    std::optional<std::string> GetQueryParam(const std::string& name) const;
    const std::unordered_map<std::string, std::string>& GetQueryParams() const { return m_queryParams; }

    size_t GetContentLength() const;
    std::string GetContentType() const;
    bool IsKeepAlive() const;

    void SetMethod(HttpMethod method) { m_method = method; }
    void SetPath(const std::string& path);
    void SetHttpVersion(const std::string& version) { m_httpVersion = version; }
    void SetBody(const std::string& body) { m_body = body; }
    void SetBody(std::string&& body) { m_body = std::move(body); }
    void AddHeader(const std::string& name, const std::string& value);
    void SetPathParam(const std::string& name, const std::string& value);
    void SetQueryParam(const std::string& name, const std::string& value);

    void Clear();

private:
    void ParseQueryString();

    HttpMethod m_method = HttpMethod::UNKNOWN;
    std::string m_path;
    std::string m_queryString;
    std::string m_httpVersion;
    std::string m_body;
    std::unordered_map<std::string, std::string> m_headers;
    std::unordered_map<std::string, std::string> m_pathParams;
    std::unordered_map<std::string, std::string> m_queryParams;
};

} // namespace http
} // namespace http_server
