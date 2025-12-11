#include "http/HttpResponse.hpp"
#include <sstream>

namespace http_server {
namespace http {

HttpResponse::HttpResponse()
    : m_status(HttpStatus::OK)
    , m_keepAlive(true) {
    SetHeader("Server", "AsyncHttpServer/1.0");
}

HttpResponse::HttpResponse(HttpStatus status)
    : m_status(status)
    , m_keepAlive(true) {
    SetHeader("Server", "AsyncHttpServer/1.0");
}

void HttpResponse::SetStatus(HttpStatus status) {
    m_status = status;
}

void HttpResponse::SetHeader(const std::string& name, const std::string& value) {
    m_headers[name] = value;
}

void HttpResponse::RemoveHeader(const std::string& name) {
    m_headers.erase(name);
}

std::string HttpResponse::GetHeader(const std::string& name) const {
    auto it = m_headers.find(name);
    if (it != m_headers.end()) {
        return it->second;
    }
    return "";
}

void HttpResponse::SetBody(const std::string& body) {
    m_body = body;
    SetHeader("Content-Length", std::to_string(m_body.size()));
}

void HttpResponse::SetBody(std::string&& body) {
    m_body = std::move(body);
    SetHeader("Content-Length", std::to_string(m_body.size()));
}

void HttpResponse::SetJsonBody(const nlohmann::json& json) {
    SetContentType("application/json");
    SetBody(json.dump());
}

void HttpResponse::SetTextBody(const std::string& text) {
    SetContentType("text/plain; charset=utf-8");
    SetBody(text);
}

void HttpResponse::SetHtmlBody(const std::string& html) {
    SetContentType("text/html; charset=utf-8");
    SetBody(html);
}

void HttpResponse::SetContentType(const std::string& contentType) {
    SetHeader("Content-Type", contentType);
}

void HttpResponse::SetKeepAlive(bool keepAlive) {
    m_keepAlive = keepAlive;
    if (keepAlive) {
        SetHeader("Connection", "keep-alive");
    } else {
        SetHeader("Connection", "close");
    }
}

std::string HttpResponse::Serialize() const {
    std::ostringstream oss;

    oss << "HTTP/1.1 " << static_cast<int>(m_status) << " " << StatusToString(m_status) << "\r\n";

    for (const auto& [name, value] : m_headers) {
        oss << name << ": " << value << "\r\n";
    }

    if (m_headers.find("Content-Length") == m_headers.end()) {
        oss << "Content-Length: " << m_body.size() << "\r\n";
    }

    oss << "\r\n";
    oss << m_body;

    return oss.str();
}

HttpResponse HttpResponse::Ok() {
    return HttpResponse(HttpStatus::OK);
}

HttpResponse HttpResponse::Created() {
    return HttpResponse(HttpStatus::Created);
}

HttpResponse HttpResponse::NoContent() {
    HttpResponse response(HttpStatus::NoContent);
    response.SetBody("");
    return response;
}

HttpResponse HttpResponse::BadRequest(const std::string& message) {
    HttpResponse response(HttpStatus::BadRequest);
    if (!message.empty()) {
        response.SetJsonBody(nlohmann::json{{"error", message}});
    }
    return response;
}

HttpResponse HttpResponse::NotFound(const std::string& message) {
    HttpResponse response(HttpStatus::NotFound);
    std::string msg = message.empty() ? "Resource not found" : message;
    response.SetJsonBody(nlohmann::json{{"error", msg}});
    return response;
}

HttpResponse HttpResponse::MethodNotAllowed() {
    HttpResponse response(HttpStatus::MethodNotAllowed);
    response.SetJsonBody(nlohmann::json{{"error", "Method not allowed"}});
    return response;
}

HttpResponse HttpResponse::InternalServerError(const std::string& message) {
    HttpResponse response(HttpStatus::InternalServerError);
    std::string msg = message.empty() ? "Internal server error" : message;
    response.SetJsonBody(nlohmann::json{{"error", msg}});
    return response;
}

HttpResponse HttpResponse::Json(const nlohmann::json& json, HttpStatus status) {
    HttpResponse response(status);
    response.SetJsonBody(json);
    return response;
}

} // namespace http
} // namespace http_server
