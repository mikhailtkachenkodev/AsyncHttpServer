#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <optional>
#include <vector>

namespace http_server {
namespace storage {

class ThreadSafeStore {
public:
    ThreadSafeStore() = default;

    bool Set(const std::string& key, const nlohmann::json& value);
    bool SetFromJson(const nlohmann::json& json);
    std::optional<nlohmann::json> Get(const std::string& key) const;
    bool Exists(const std::string& key) const;
    bool Delete(const std::string& key);
    std::vector<std::string> GetKeys() const;
    size_t Size() const;
    void Clear();
    nlohmann::json ToJson() const;

    static bool ValidateKey(const std::string& key);

    static constexpr size_t MAX_KEY_LENGTH = 256;
    static constexpr size_t MAX_VALUE_SIZE = 1024 * 1024;
    static constexpr size_t MAX_ENTRIES = 100000;

private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, nlohmann::json> m_data;
};

} // namespace storage
} // namespace http_server
