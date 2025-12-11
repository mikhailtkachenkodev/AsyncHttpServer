#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <stdexcept>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

namespace http_server {
namespace core {

class WinsockInit {
public:
    WinsockInit();
    ~WinsockInit();

    WinsockInit(const WinsockInit&) = delete;
    WinsockInit& operator=(const WinsockInit&) = delete;
    WinsockInit(WinsockInit&&) = delete;
    WinsockInit& operator=(WinsockInit&&) = delete;

    static LPFN_ACCEPTEX GetAcceptEx();
    static LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockaddrs();

private:
    static void LoadExtensionFunctions();

    static LPFN_ACCEPTEX s_acceptEx;
    static LPFN_GETACCEPTEXSOCKADDRS s_getAcceptExSockaddrs;
    static bool s_extensionsLoaded;
};

class WinsockException : public std::runtime_error {
public:
    WinsockException(const std::string& message, int errorCode);
    int GetErrorCode() const { return m_errorCode; }
private:
    int m_errorCode;
};

} // namespace core
} // namespace http_server
