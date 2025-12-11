#include "storage/ThreadSafeStore.hpp"

#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <atomic>

using namespace http_server::storage;

TEST(ThreadSafeStoreTest, SetAndGet) {
    ThreadSafeStore store;

    nlohmann::json value = {{"data", 42}};
    ASSERT_TRUE(store.Set("key1", value));

    auto result = store.Get("key1");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)["data"], 42);
}

TEST(ThreadSafeStoreTest, GetNonExistent) {
    ThreadSafeStore store;

    auto result = store.Get("nonexistent");
    EXPECT_FALSE(result.has_value());
}

TEST(ThreadSafeStoreTest, Exists) {
    ThreadSafeStore store;

    EXPECT_FALSE(store.Exists("key1"));

    store.Set("key1", nlohmann::json{{"value", true}});
    EXPECT_TRUE(store.Exists("key1"));
}

TEST(ThreadSafeStoreTest, Delete) {
    ThreadSafeStore store;

    store.Set("key1", nlohmann::json{{"value", 1}});
    EXPECT_TRUE(store.Exists("key1"));

    EXPECT_TRUE(store.Delete("key1"));
    EXPECT_FALSE(store.Exists("key1"));

    // Delete non-existent
    EXPECT_FALSE(store.Delete("key1"));
}

TEST(ThreadSafeStoreTest, SetFromJson) {
    ThreadSafeStore store;

    nlohmann::json data = {
        {"key1", "value1"},
        {"key2", 42},
        {"key3", {{"nested", true}}}
    };

    ASSERT_TRUE(store.SetFromJson(data));
    EXPECT_EQ(store.Size(), 3u);

    auto key1 = store.Get("key1");
    ASSERT_TRUE(key1.has_value());
    EXPECT_EQ(*key1, "value1");

    auto key2 = store.Get("key2");
    ASSERT_TRUE(key2.has_value());
    EXPECT_EQ(*key2, 42);
}

TEST(ThreadSafeStoreTest, GetKeys) {
    ThreadSafeStore store;

    store.Set("a", nlohmann::json(1));
    store.Set("b", nlohmann::json(2));
    store.Set("c", nlohmann::json(3));

    auto keys = store.GetKeys();
    EXPECT_EQ(keys.size(), 3u);
}

TEST(ThreadSafeStoreTest, Clear) {
    ThreadSafeStore store;

    store.Set("key1", nlohmann::json(1));
    store.Set("key2", nlohmann::json(2));
    EXPECT_EQ(store.Size(), 2u);

    store.Clear();
    EXPECT_EQ(store.Size(), 0u);
}

TEST(ThreadSafeStoreTest, ToJson) {
    ThreadSafeStore store;

    store.Set("key1", nlohmann::json("value1"));
    store.Set("key2", nlohmann::json(42));

    auto json = store.ToJson();
    EXPECT_EQ(json["key1"], "value1");
    EXPECT_EQ(json["key2"], 42);
}

TEST(ThreadSafeStoreTest, ValidateKey) {
    // Valid keys
    EXPECT_TRUE(ThreadSafeStore::ValidateKey("validkey"));
    EXPECT_TRUE(ThreadSafeStore::ValidateKey("valid_key"));
    EXPECT_TRUE(ThreadSafeStore::ValidateKey("valid-key"));
    EXPECT_TRUE(ThreadSafeStore::ValidateKey("valid.key"));
    EXPECT_TRUE(ThreadSafeStore::ValidateKey("Key123"));

    // Invalid keys
    EXPECT_FALSE(ThreadSafeStore::ValidateKey(""));
    EXPECT_FALSE(ThreadSafeStore::ValidateKey("key with space"));
    EXPECT_FALSE(ThreadSafeStore::ValidateKey("key@symbol"));
    EXPECT_FALSE(ThreadSafeStore::ValidateKey("key/slash"));

    // Too long key
    std::string longKey(300, 'a');
    EXPECT_FALSE(ThreadSafeStore::ValidateKey(longKey));
}

TEST(ThreadSafeStoreTest, RejectInvalidKey) {
    ThreadSafeStore store;

    EXPECT_FALSE(store.Set("", nlohmann::json(1)));
    EXPECT_FALSE(store.Set("invalid key", nlohmann::json(1)));
    EXPECT_FALSE(store.Set("key/path", nlohmann::json(1)));
}

TEST(ThreadSafeStoreTest, ConcurrentReads) {
    ThreadSafeStore store;

    // Populate store
    for (int i = 0; i < 100; ++i) {
        store.Set("key" + std::to_string(i), nlohmann::json(i));
    }

    std::atomic<int> successCount{0};
    std::vector<std::thread> threads;

    // Multiple threads reading concurrently
    for (int t = 0; t < 10; ++t) {
        threads.emplace_back([&store, &successCount]() {
            for (int i = 0; i < 100; ++i) {
                auto value = store.Get("key" + std::to_string(i));
                if (value.has_value() && *value == i) {
                    ++successCount;
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(successCount.load(), 1000);
}

TEST(ThreadSafeStoreTest, ConcurrentWrites) {
    ThreadSafeStore store;
    std::atomic<int> writeCount{0};
    std::vector<std::thread> threads;

    // Multiple threads writing concurrently
    for (int t = 0; t < 10; ++t) {
        threads.emplace_back([&store, &writeCount, t]() {
            for (int i = 0; i < 100; ++i) {
                std::string key = "thread" + std::to_string(t) + "_key" + std::to_string(i);
                if (store.Set(key, nlohmann::json(i))) {
                    ++writeCount;
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(writeCount.load(), 1000);
    EXPECT_EQ(store.Size(), 1000u);
}

TEST(ThreadSafeStoreTest, ConcurrentReadWrite) {
    ThreadSafeStore store;

    // Pre-populate
    for (int i = 0; i < 50; ++i) {
        store.Set("key" + std::to_string(i), nlohmann::json(i));
    }

    std::atomic<bool> running{true};
    std::atomic<int> reads{0};
    std::atomic<int> writes{0};

    // Reader threads
    std::vector<std::thread> readers;
    for (int t = 0; t < 5; ++t) {
        readers.emplace_back([&]() {
            while (running.load()) {
                for (int i = 0; i < 50; ++i) {
                    store.Get("key" + std::to_string(i));
                    ++reads;
                }
            }
        });
    }

    // Writer threads
    std::vector<std::thread> writers;
    for (int t = 0; t < 2; ++t) {
        writers.emplace_back([&]() {
            while (running.load()) {
                for (int i = 0; i < 50; ++i) {
                    store.Set("key" + std::to_string(i), nlohmann::json(i * 2));
                    ++writes;
                }
            }
        });
    }

    // Let it run for a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    running.store(false);

    for (auto& t : readers) t.join();
    for (auto& t : writers) t.join();

    // Just verify we did a lot of concurrent operations without crashing
    EXPECT_TRUE(reads.load() > 0);
    EXPECT_TRUE(writes.load() > 0);
}
