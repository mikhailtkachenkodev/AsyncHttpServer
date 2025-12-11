#include "handlers/DataHandler.hpp"
#include "utils/Logger.hpp"
#include <nlohmann/json.hpp>

namespace http_server {
namespace handlers {

DataHandler::DataHandler(std::shared_ptr<storage::ThreadSafeStore> store)
    : m_store(std::move(store)) {
}

http::HttpResponse DataHandler::Handle(http::HttpRequest& request) {
    switch (request.GetMethod()) {
        case http::HttpMethod::POST:
            return HandlePost(request);
        case http::HttpMethod::GET:
            return HandleGet(request);
        default:
            return http::HttpResponse::MethodNotAllowed();
    }
}

http::HttpResponse DataHandler::HandlePost(http::HttpRequest& request) {
    const std::string& body = request.GetBody();

    if (body.size() > MAX_JSON_SIZE) {
        return http::HttpResponse::BadRequest("Request body too large");
    }

    nlohmann::json json;
    try {
        json = nlohmann::json::parse(body);
    } catch (const nlohmann::json::parse_error& e) {
        utils::Logger::Warning("JSON parse error: " + std::string(e.what()));
        return http::HttpResponse::BadRequest("Invalid JSON");
    }

    if (!json.is_object()) {
        return http::HttpResponse::BadRequest("JSON must be an object");
    }

    if (!m_store->SetFromJson(json)) {
        return http::HttpResponse::InternalServerError("Failed to store data");
    }

    return http::HttpResponse::Created();
}

http::HttpResponse DataHandler::HandleGet(http::HttpRequest& request) {
    auto keyOpt = request.GetPathParam("key");
    if (!keyOpt) {
        return http::HttpResponse::Json(m_store->ToJson());
    }

    const std::string& key = *keyOpt;

    if (!storage::ThreadSafeStore::ValidateKey(key)) {
        return http::HttpResponse::BadRequest("Invalid key format");
    }

    auto value = m_store->Get(key);
    if (!value) {
        return http::HttpResponse::NotFound("Key not found: " + key);
    }

    nlohmann::json response;
    response[key] = *value;
    return http::HttpResponse::Json(response);
}

} // namespace handlers
} // namespace http_server
