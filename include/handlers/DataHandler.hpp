#pragma once

#include "handlers/IRequestHandler.hpp"
#include "storage/ThreadSafeStore.hpp"
#include <memory>

namespace http_server {
namespace handlers {

class DataHandler : public IRequestHandler {
public:
    explicit DataHandler(std::shared_ptr<storage::ThreadSafeStore> store);

    http::HttpResponse Handle(http::HttpRequest& request) override;

    http::HttpResponse HandlePost(http::HttpRequest& request);
    http::HttpResponse HandleGet(http::HttpRequest& request);

private:
    std::shared_ptr<storage::ThreadSafeStore> m_store;

    static constexpr size_t MAX_JSON_SIZE = 1024 * 1024;
};

} // namespace handlers
} // namespace http_server
