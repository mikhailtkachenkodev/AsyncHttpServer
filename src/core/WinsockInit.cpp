#include "core/WinsockInit.hpp"
#include "utils/ErrorHandler.hpp"
#include "utils/Logger.hpp"

namespace http_server {
namespace core {

LPFN_ACCEPTEX WinsockInit::s_acceptEx = nullptr;
LPFN_GETACCEPTEXSOCKADDRS WinsockInit::s_getAcceptExSockaddrs = nullptr;
bool WinsockInit::s_extensionsLoaded = false;

WinsockInit::WinsockInit() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        throw WinsockException("WSAStartup failed", result);
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        WSACleanup();
        throw WinsockException("Winsock 2.2 not available", 0);
    }

    utils::Logger::Info("Winsock 2.2 initialized");
    LoadExtensionFunctions();
}

WinsockInit::~WinsockInit() {
    WSACleanup();
    utils::Logger::Info("Winsock cleaned up");
}

void WinsockInit::LoadExtensionFunctions() {
    if (s_extensionsLoaded) {
        return;
    }

    SOCKET tempSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tempSocket == INVALID_SOCKET) {
        throw WinsockException("Failed to create temp socket for extension functions",
                               WSAGetLastError());
    }

    DWORD bytesReturned = 0;

    GUID guidAcceptEx = WSAID_ACCEPTEX;
    int result = WSAIoctl(
        tempSocket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidAcceptEx,
        sizeof(guidAcceptEx),
        &s_acceptEx,
        sizeof(s_acceptEx),
        &bytesReturned,
        nullptr,
        nullptr
    );

    if (result == SOCKET_ERROR) {
        closesocket(tempSocket);
        throw WinsockException("Failed to load AcceptEx", WSAGetLastError());
    }

    GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
    result = WSAIoctl(
        tempSocket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidGetAcceptExSockaddrs,
        sizeof(guidGetAcceptExSockaddrs),
        &s_getAcceptExSockaddrs,
        sizeof(s_getAcceptExSockaddrs),
        &bytesReturned,
        nullptr,
        nullptr
    );

    if (result == SOCKET_ERROR) {
        closesocket(tempSocket);
        throw WinsockException("Failed to load GetAcceptExSockaddrs", WSAGetLastError());
    }

    closesocket(tempSocket);
    s_extensionsLoaded = true;
    utils::Logger::Debug("Winsock extension functions loaded");
}

LPFN_ACCEPTEX WinsockInit::GetAcceptEx() {
    return s_acceptEx;
}

LPFN_GETACCEPTEXSOCKADDRS WinsockInit::GetAcceptExSockaddrs() {
    return s_getAcceptExSockaddrs;
}

WinsockException::WinsockException(const std::string& message, int errorCode)
    : std::runtime_error(message + ": " + utils::ErrorHandler::GetWsaErrorMessage(errorCode))
    , m_errorCode(errorCode) {
}

} // namespace core
} // namespace http_server
