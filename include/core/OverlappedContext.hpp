#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <array>
#include <memory>

namespace http_server {
namespace core {

constexpr size_t BUFFER_SIZE = 8192;

enum class IoOperation {
    Accept,
    Receive,
    Send,
    Disconnect
};

class ConnectionContext;

struct OverlappedContext : public OVERLAPPED {
    IoOperation operation;
    WSABUF wsaBuf;
    std::array<char, BUFFER_SIZE> buffer;
    ConnectionContext* connection;
    SOCKET acceptSocket;

    OverlappedContext();
    void Reset();
    void PrepareForReceive();
    void PrepareForSend(const char* data, size_t length);
    void PrepareForAccept(SOCKET socket);
};

using OverlappedContextPtr = std::unique_ptr<OverlappedContext>;

OverlappedContextPtr CreateOverlappedContext();

} // namespace core
} // namespace http_server
