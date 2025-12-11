#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <memory>
#include <stdexcept>

namespace http_server {
namespace core {

struct CompletionResult {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;
    bool success;
    DWORD error;
};

class IoCompletionPort {
public:
    IoCompletionPort();
    explicit IoCompletionPort(DWORD concurrentThreads);
    ~IoCompletionPort();

    IoCompletionPort(const IoCompletionPort&) = delete;
    IoCompletionPort& operator=(const IoCompletionPort&) = delete;
    IoCompletionPort(IoCompletionPort&&) noexcept;
    IoCompletionPort& operator=(IoCompletionPort&&) noexcept;

    HANDLE GetHandle() const { return m_handle; }

    void Associate(SOCKET socket, ULONG_PTR completionKey);
    void Associate(HANDLE handle, ULONG_PTR completionKey);

    CompletionResult GetCompletion(DWORD timeout = INFINITE);
    bool PostCompletion(DWORD bytesTransferred, ULONG_PTR completionKey, LPOVERLAPPED overlapped = nullptr);

    bool IsValid() const { return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; }

private:
    HANDLE m_handle;
};

class IocpException : public std::runtime_error {
public:
    IocpException(const std::string& message, DWORD errorCode);
    DWORD GetErrorCode() const { return m_errorCode; }
private:
    DWORD m_errorCode;
};

} // namespace core
} // namespace http_server
