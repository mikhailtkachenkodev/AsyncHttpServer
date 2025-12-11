#include "core/IoCompletionPort.hpp"
#include "utils/ErrorHandler.hpp"
#include "utils/Logger.hpp"

namespace http_server {
namespace core {

IoCompletionPort::IoCompletionPort()
    : IoCompletionPort(0) {
}

IoCompletionPort::IoCompletionPort(DWORD concurrentThreads)
    : m_handle(nullptr) {
    m_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, concurrentThreads);
    if (m_handle == nullptr) {
        throw IocpException("Failed to create IOCP", GetLastError());
    }
    utils::Logger::Debug("IOCP created with " + std::to_string(concurrentThreads) + " concurrent threads");
}

IoCompletionPort::~IoCompletionPort() {
    if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_handle);
        utils::Logger::Debug("IOCP handle closed");
    }
}

IoCompletionPort::IoCompletionPort(IoCompletionPort&& other) noexcept
    : m_handle(other.m_handle) {
    other.m_handle = nullptr;
}

IoCompletionPort& IoCompletionPort::operator=(IoCompletionPort&& other) noexcept {
    if (this != &other) {
        if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
        m_handle = other.m_handle;
        other.m_handle = nullptr;
    }
    return *this;
}

void IoCompletionPort::Associate(SOCKET socket, ULONG_PTR completionKey) {
    Associate(reinterpret_cast<HANDLE>(socket), completionKey);
}

void IoCompletionPort::Associate(HANDLE handle, ULONG_PTR completionKey) {
    HANDLE result = CreateIoCompletionPort(handle, m_handle, completionKey, 0);
    if (result == nullptr) {
        throw IocpException("Failed to associate handle with IOCP", GetLastError());
    }
}

CompletionResult IoCompletionPort::GetCompletion(DWORD timeout) {
    CompletionResult result{};
    result.success = GetQueuedCompletionStatus(
        m_handle,
        &result.bytesTransferred,
        &result.completionKey,
        &result.overlapped,
        timeout
    ) != FALSE;

    if (!result.success) {
        result.error = GetLastError();
    }

    return result;
}

bool IoCompletionPort::PostCompletion(DWORD bytesTransferred, ULONG_PTR completionKey, LPOVERLAPPED overlapped) {
    return PostQueuedCompletionStatus(m_handle, bytesTransferred, completionKey, overlapped) != FALSE;
}

IocpException::IocpException(const std::string& message, DWORD errorCode)
    : std::runtime_error(message + ": " + utils::ErrorHandler::GetErrorMessage(errorCode))
    , m_errorCode(errorCode) {
}

} // namespace core
} // namespace http_server
