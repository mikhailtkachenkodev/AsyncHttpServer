#pragma once

#include "http/HttpStatus.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>

namespace http_server {
namespace http {

class HttpResponse {
public:
    HttpResponse();
    explicit HttpResponse(HttpStatus status);

    void SetStatus(HttpStatus status);
    HttpStatus GetStatus() const { return m_status; }

    void SetHeader(const std::string& name, const std::string& value);
    void RemoveHeader(const std::string& name);
    std::string GetHeader(const std::string& name) const;
    const std::unordered_map<std::string, std::string>& GetHeaders() const { return m_headers; }

    void SetBody(const std::string& body);
    void SetBody(std::string&& body);
    void SetJsonBody(const nlohmann::json& json);
    void SetTextBody(const std::string& text);
    void SetHtmlBody(const std::string& html);
    const std::string& GetBody() const { return m_body; }

    void SetContentType(const std::string& contentType);

    void SetKeepAlive(bool keepAlive);

    std::string Serialize() const;

    static HttpResponse Ok();
    static HttpResponse Created();
    static HttpResponse NoContent();
    static HttpResponse BadRequest(const std::string& message = "");
    static HttpResponse NotFound(const std::string& message = "");
    static HttpResponse MethodNotAllowed();
    static HttpResponse InternalServerError(const std::string& message = "");
    static HttpResponse Json(const nlohmann::json& json, HttpStatus status = HttpStatus::OK);

private:
    HttpStatus m_status;
    std::unordered_map<std::string, std::string> m_headers;
    std::string m_body;
    bool m_keepAlive;
};

} // namespace http
} // namespace http_server
