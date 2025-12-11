#include "storage/ThreadSafeStore.hpp"
#include <algorithm>
#include <cctype>

namespace http_server {
namespace storage {

bool ThreadSafeStore::Set(const std::string& key, const nlohmann::json& value) {
    if (!ValidateKey(key)) {
        return false;
    }

    std::string serialized = value.dump();
    if (serialized.size() > MAX_VALUE_SIZE) {
        return false;
    }

    std::unique_lock lock(m_mutex);

    if (m_data.find(key) == m_data.end() && m_data.size() >= MAX_ENTRIES) {
        return false;
    }

    m_data[key] = value;
    return true;
}

bool ThreadSafeStore::SetFromJson(const nlohmann::json& json) {
    if (!json.is_object()) {
        return false;
    }

    std::unique_lock lock(m_mutex);

    for (auto& [key, value] : json.items()) {
        if (!ValidateKey(key)) {
            continue;
        }

        std::string serialized = value.dump();
        if (serialized.size() > MAX_VALUE_SIZE) {
            continue;
        }

        if (m_data.find(key) == m_data.end() && m_data.size() >= MAX_ENTRIES) {
            break;
        }

        m_data[key] = value;
    }

    return true;
}

std::optional<nlohmann::json> ThreadSafeStore::Get(const std::string& key) const {
    std::shared_lock lock(m_mutex);

    auto it = m_data.find(key);
    if (it != m_data.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool ThreadSafeStore::Exists(const std::string& key) const {
    std::shared_lock lock(m_mutex);
    return m_data.find(key) != m_data.end();
}

bool ThreadSafeStore::Delete(const std::string& key) {
    std::unique_lock lock(m_mutex);
    return m_data.erase(key) > 0;
}

std::vector<std::string> ThreadSafeStore::GetKeys() const {
    std::shared_lock lock(m_mutex);

    std::vector<std::string> keys;
    keys.reserve(m_data.size());
    for (const auto& [key, _] : m_data) {
        keys.push_back(key);
    }
    return keys;
}

size_t ThreadSafeStore::Size() const {
    std::shared_lock lock(m_mutex);
    return m_data.size();
}

void ThreadSafeStore::Clear() {
    std::unique_lock lock(m_mutex);
    m_data.clear();
}

nlohmann::json ThreadSafeStore::ToJson() const {
    std::shared_lock lock(m_mutex);
    return nlohmann::json(m_data);
}

bool ThreadSafeStore::ValidateKey(const std::string& key) {
    if (key.empty() || key.size() > MAX_KEY_LENGTH) {
        return false;
    }

    return std::all_of(key.begin(), key.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_' || c == '-' || c == '.';
    });
}

} // namespace storage
} // namespace http_server
