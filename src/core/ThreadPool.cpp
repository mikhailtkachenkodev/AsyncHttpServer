#include "core/ThreadPool.hpp"
#include "core/IoCompletionPort.hpp"
#include "utils/Logger.hpp"

namespace http_server {
namespace core {

ThreadPool::ThreadPool(IoCompletionPort& iocp)
    : m_iocp(iocp)
    , m_running(false) {
}

ThreadPool::~ThreadPool() {
    Stop();
}

void ThreadPool::Start() {
    Start(GetOptimalThreadCount());
}

void ThreadPool::Start(size_t threadCount) {
    if (m_running.load(std::memory_order_acquire)) {
        return;
    }

    m_running.store(true, std::memory_order_release);

    for (size_t i = 0; i < threadCount; ++i) {
        m_threads.emplace_back(&ThreadPool::WorkerThread, this);
    }

    utils::Logger::Info("Thread pool started with " + std::to_string(threadCount) + " threads");
}

void ThreadPool::Stop() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }

    m_running.store(false, std::memory_order_release);

    for (size_t i = 0; i < m_threads.size(); ++i) {
        m_iocp.PostCompletion(0, 0, nullptr);
    }

    for (auto& thread : m_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    m_threads.clear();
    utils::Logger::Info("Thread pool stopped");
}

void ThreadPool::SetCompletionHandler(CompletionHandler handler) {
    m_handler = std::move(handler);
}

size_t ThreadPool::GetOptimalThreadCount() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return static_cast<size_t>(sysInfo.dwNumberOfProcessors) * 2;
}

void ThreadPool::WorkerThread() {
    utils::Logger::Debug("Worker thread started: " + std::to_string(GetCurrentThreadId()));

    while (m_running.load(std::memory_order_acquire)) {
        CompletionResult result = m_iocp.GetCompletion(INFINITE);

        if (!m_running.load(std::memory_order_acquire)) {
            break;
        }

        if (result.overlapped == nullptr && result.bytesTransferred == 0 && result.completionKey == 0) {
            continue;
        }

        if (m_handler) {
            try {
                m_handler(result);
            } catch (const std::exception& e) {
                utils::Logger::Error("Exception in completion handler: " + std::string(e.what()));
            } catch (...) {
                utils::Logger::Error("Unknown exception in completion handler");
            }
        }
    }

    utils::Logger::Debug("Worker thread exiting: " + std::to_string(GetCurrentThreadId()));
}

} // namespace core
} // namespace http_server
