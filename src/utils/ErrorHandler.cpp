#include "utils/ErrorHandler.hpp"
#include <WinSock2.h>

namespace http_server {
namespace utils {

std::string ErrorHandler::GetLastErrorMessage() {
    return GetErrorMessage(::GetLastError());
}

std::string ErrorHandler::GetErrorMessage(DWORD errorCode) {
    if (errorCode == 0) {
        return "No error";
    }

    LPWSTR buffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr
    );

    if (size == 0) {
        return "Unknown error (code: " + std::to_string(errorCode) + ")";
    }

    // Convert wide string to UTF-8
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, buffer, static_cast<int>(size), nullptr, 0, nullptr, nullptr);
    std::string result(utf8Size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buffer, static_cast<int>(size), result.data(), utf8Size, nullptr, nullptr);

    LocalFree(buffer);

    // Remove trailing newlines
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }

    return result;
}

std::string ErrorHandler::GetWsaErrorMessage() {
    return GetWsaErrorMessage(WSAGetLastError());
}

std::string ErrorHandler::GetWsaErrorMessage(int wsaError) {
    return GetErrorMessage(static_cast<DWORD>(wsaError));
}

std::string ErrorHandler::GetSchannelErrorMessage(LONG status) {
    return GetErrorMessage(static_cast<DWORD>(status));
}

std::string ErrorHandler::FormatError(const std::string& context, DWORD errorCode) {
    return context + ": " + GetErrorMessage(errorCode) + " (error code: " + std::to_string(errorCode) + ")";
}

std::string ErrorHandler::FormatWsaError(const std::string& context, int wsaError) {
    return context + ": " + GetWsaErrorMessage(wsaError) + " (WSA error: " + std::to_string(wsaError) + ")";
}

} // namespace utils
} // namespace http_server
