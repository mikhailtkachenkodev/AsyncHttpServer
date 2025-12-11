#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <memory>

namespace http_server {
namespace core {

class IoCompletionPort;
struct CompletionResult;

using CompletionHandler = std::function<void(const CompletionResult&)>;

class ThreadPool {
public:
    explicit ThreadPool(IoCompletionPort& iocp);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    void Start();
    void Start(size_t threadCount);
    void Stop();

    bool IsRunning() const { return m_running.load(std::memory_order_acquire); }
    size_t GetThreadCount() const { return m_threads.size(); }

    void SetCompletionHandler(CompletionHandler handler);

    static size_t GetOptimalThreadCount();

private:
    void WorkerThread();

    IoCompletionPort& m_iocp;
    std::vector<std::thread> m_threads;
    std::atomic<bool> m_running;
    CompletionHandler m_handler;
};

} // namespace core
} // namespace http_server
