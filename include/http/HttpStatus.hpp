#pragma once

#include <string>

namespace http_server {
namespace http {

enum class HttpStatus {
    OK = 200,
    Created = 201,
    NoContent = 204,

    MovedPermanently = 301,
    Found = 302,
    NotModified = 304,

    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    RequestTimeout = 408,
    Conflict = 409,
    LengthRequired = 411,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    UnsupportedMediaType = 415,

    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504
};

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE_,
    PATCH,
    HEAD,
    OPTIONS,
    UNKNOWN
};

inline std::string StatusToString(HttpStatus status) {
    switch (status) {
        case HttpStatus::OK: return "OK";
        case HttpStatus::Created: return "Created";
        case HttpStatus::NoContent: return "No Content";
        case HttpStatus::MovedPermanently: return "Moved Permanently";
        case HttpStatus::Found: return "Found";
        case HttpStatus::NotModified: return "Not Modified";
        case HttpStatus::BadRequest: return "Bad Request";
        case HttpStatus::Unauthorized: return "Unauthorized";
        case HttpStatus::Forbidden: return "Forbidden";
        case HttpStatus::NotFound: return "Not Found";
        case HttpStatus::MethodNotAllowed: return "Method Not Allowed";
        case HttpStatus::RequestTimeout: return "Request Timeout";
        case HttpStatus::Conflict: return "Conflict";
        case HttpStatus::LengthRequired: return "Length Required";
        case HttpStatus::PayloadTooLarge: return "Payload Too Large";
        case HttpStatus::UriTooLong: return "URI Too Long";
        case HttpStatus::UnsupportedMediaType: return "Unsupported Media Type";
        case HttpStatus::InternalServerError: return "Internal Server Error";
        case HttpStatus::NotImplemented: return "Not Implemented";
        case HttpStatus::BadGateway: return "Bad Gateway";
        case HttpStatus::ServiceUnavailable: return "Service Unavailable";
        case HttpStatus::GatewayTimeout: return "Gateway Timeout";
        default: return "Unknown";
    }
}

inline std::string MethodToString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE_: return "DELETE";
        case HttpMethod::PATCH: return "PATCH";
        case HttpMethod::HEAD: return "HEAD";
        case HttpMethod::OPTIONS: return "OPTIONS";
        default: return "UNKNOWN";
    }
}

inline HttpMethod StringToMethod(const std::string& method) {
    if (method == "GET") return HttpMethod::GET;
    if (method == "POST") return HttpMethod::POST;
    if (method == "PUT") return HttpMethod::PUT;
    if (method == "DELETE") return HttpMethod::DELETE_;
    if (method == "PATCH") return HttpMethod::PATCH;
    if (method == "HEAD") return HttpMethod::HEAD;
    if (method == "OPTIONS") return HttpMethod::OPTIONS;
    return HttpMethod::UNKNOWN;
}

} // namespace http
} // namespace http_server
