#include "utils/ErrorHandler.hpp"

#include <gtest/gtest.h>
#include <WinSock2.h>

using namespace http_server::utils;

class ErrorHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    void TearDown() override {
        WSACleanup();
    }
};

TEST_F(ErrorHandlerTest, GetErrorMessageForZero) {
    std::string message = ErrorHandler::GetErrorMessage(0);
    EXPECT_EQ(message, "No error");
}

TEST_F(ErrorHandlerTest, GetErrorMessageForKnownError) {
    std::string message = ErrorHandler::GetErrorMessage(ERROR_FILE_NOT_FOUND);
    EXPECT_FALSE(message.empty());
    EXPECT_NE(message.find("file"), std::string::npos);
}

TEST_F(ErrorHandlerTest, GetErrorMessageForAccessDenied) {
    std::string message = ErrorHandler::GetErrorMessage(ERROR_ACCESS_DENIED);
    EXPECT_FALSE(message.empty());
    EXPECT_NE(message.find("denied"), std::string::npos);
}

TEST_F(ErrorHandlerTest, GetErrorMessageRemovesTrailingNewlines) {
    std::string message = ErrorHandler::GetErrorMessage(ERROR_FILE_NOT_FOUND);
    if (!message.empty()) {
        EXPECT_NE(message.back(), '\n');
        EXPECT_NE(message.back(), '\r');
    }
}

TEST_F(ErrorHandlerTest, GetErrorMessageForUnknownError) {
    std::string message = ErrorHandler::GetErrorMessage(0xFFFFFFFF);
    EXPECT_NE(message.find("Unknown error"), std::string::npos);
    EXPECT_NE(message.find("4294967295"), std::string::npos);
}

TEST_F(ErrorHandlerTest, GetWsaErrorMessageForKnownError) {
    std::string message = ErrorHandler::GetWsaErrorMessage(WSAECONNREFUSED);
    EXPECT_FALSE(message.empty());
}

TEST_F(ErrorHandlerTest, GetWsaErrorMessageForConnectionReset) {
    std::string message = ErrorHandler::GetWsaErrorMessage(WSAECONNRESET);
    EXPECT_FALSE(message.empty());
}

TEST_F(ErrorHandlerTest, GetWsaErrorMessageForTimedOut) {
    std::string message = ErrorHandler::GetWsaErrorMessage(WSAETIMEDOUT);
    EXPECT_FALSE(message.empty());
}

TEST_F(ErrorHandlerTest, GetSchannelErrorMessage) {
    std::string message = ErrorHandler::GetSchannelErrorMessage(0);
    EXPECT_EQ(message, "No error");
}

TEST_F(ErrorHandlerTest, FormatErrorIncludesContext) {
    std::string formatted = ErrorHandler::FormatError("Failed to open file", ERROR_FILE_NOT_FOUND);
    EXPECT_NE(formatted.find("Failed to open file"), std::string::npos);
}

TEST_F(ErrorHandlerTest, FormatErrorIncludesErrorCode) {
    std::string formatted = ErrorHandler::FormatError("Test", ERROR_FILE_NOT_FOUND);
    EXPECT_NE(formatted.find("error code:"), std::string::npos);
    EXPECT_NE(formatted.find(std::to_string(ERROR_FILE_NOT_FOUND)), std::string::npos);
}

TEST_F(ErrorHandlerTest, FormatErrorIncludesMessage) {
    std::string formatted = ErrorHandler::FormatError("Context", ERROR_ACCESS_DENIED);
    std::string plainMessage = ErrorHandler::GetErrorMessage(ERROR_ACCESS_DENIED);
    EXPECT_NE(formatted.find(plainMessage), std::string::npos);
}

TEST_F(ErrorHandlerTest, FormatWsaErrorIncludesContext) {
    std::string formatted = ErrorHandler::FormatWsaError("Connection failed", WSAECONNREFUSED);
    EXPECT_NE(formatted.find("Connection failed"), std::string::npos);
}

TEST_F(ErrorHandlerTest, FormatWsaErrorIncludesErrorCode) {
    std::string formatted = ErrorHandler::FormatWsaError("Test", WSAECONNREFUSED);
    EXPECT_NE(formatted.find("WSA error:"), std::string::npos);
    EXPECT_NE(formatted.find(std::to_string(WSAECONNREFUSED)), std::string::npos);
}

TEST_F(ErrorHandlerTest, FormatWsaErrorIncludesMessage) {
    std::string formatted = ErrorHandler::FormatWsaError("Context", WSAECONNRESET);
    std::string plainMessage = ErrorHandler::GetWsaErrorMessage(WSAECONNRESET);
    EXPECT_NE(formatted.find(plainMessage), std::string::npos);
}

TEST_F(ErrorHandlerTest, GetLastErrorMessageReturnsString) {
    SetLastError(ERROR_SUCCESS);
    std::string message = ErrorHandler::GetLastErrorMessage();
    EXPECT_FALSE(message.empty());
}

TEST_F(ErrorHandlerTest, GetLastErrorMessageAfterSettingError) {
    SetLastError(ERROR_INVALID_PARAMETER);
    std::string message = ErrorHandler::GetLastErrorMessage();
    EXPECT_FALSE(message.empty());
    EXPECT_NE(message, "No error");
}

TEST_F(ErrorHandlerTest, MultipleErrorsReturnDifferentMessages) {
    std::string msg1 = ErrorHandler::GetErrorMessage(ERROR_FILE_NOT_FOUND);
    std::string msg2 = ErrorHandler::GetErrorMessage(ERROR_ACCESS_DENIED);
    std::string msg3 = ErrorHandler::GetErrorMessage(ERROR_INVALID_PARAMETER);

    EXPECT_NE(msg1, msg2);
    EXPECT_NE(msg2, msg3);
    EXPECT_NE(msg1, msg3);
}

TEST_F(ErrorHandlerTest, WsaErrorsReturnDifferentMessages) {
    std::string msg1 = ErrorHandler::GetWsaErrorMessage(WSAECONNREFUSED);
    std::string msg2 = ErrorHandler::GetWsaErrorMessage(WSAECONNRESET);
    std::string msg3 = ErrorHandler::GetWsaErrorMessage(WSAETIMEDOUT);

    EXPECT_NE(msg1, msg2);
    EXPECT_NE(msg2, msg3);
}
