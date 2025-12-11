#pragma once

#include "http/HttpRequest.hpp"
#include "http/HttpResponse.hpp"

namespace http_server {
namespace handlers {

class IRequestHandler {
public:
    virtual ~IRequestHandler() = default;
    virtual http::HttpResponse Handle(http::HttpRequest& request) = 0;
};

} // namespace handlers
} // namespace http_server
