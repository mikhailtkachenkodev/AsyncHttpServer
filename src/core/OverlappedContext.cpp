#include "core/OverlappedContext.hpp"
#include <cstring>

namespace http_server {
namespace core {

OverlappedContext::OverlappedContext()
    : operation(IoOperation::Receive)
    , connection(nullptr)
    , acceptSocket(INVALID_SOCKET) {
    Reset();
}

void OverlappedContext::Reset() {
    Internal = 0;
    InternalHigh = 0;
    Offset = 0;
    OffsetHigh = 0;
    hEvent = nullptr;

    wsaBuf.buf = buffer.data();
    wsaBuf.len = static_cast<ULONG>(buffer.size());
    buffer.fill(0);
}

void OverlappedContext::PrepareForReceive() {
    Reset();
    operation = IoOperation::Receive;
    wsaBuf.buf = buffer.data();
    wsaBuf.len = static_cast<ULONG>(buffer.size());
}

void OverlappedContext::PrepareForSend(const char* data, size_t length) {
    Reset();
    operation = IoOperation::Send;

    size_t copyLen = (std::min)(length, buffer.size());
    std::memcpy(buffer.data(), data, copyLen);

    wsaBuf.buf = buffer.data();
    wsaBuf.len = static_cast<ULONG>(copyLen);
}

void OverlappedContext::PrepareForAccept(SOCKET socket) {
    Reset();
    operation = IoOperation::Accept;
    acceptSocket = socket;
    wsaBuf.buf = buffer.data();
    wsaBuf.len = static_cast<ULONG>(buffer.size());
}

OverlappedContextPtr CreateOverlappedContext() {
    return std::make_unique<OverlappedContext>();
}

} // namespace core
} // namespace http_server
