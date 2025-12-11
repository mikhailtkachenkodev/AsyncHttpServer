#include "utils/Logger.hpp"

#include <gtest/gtest.h>
#include <sstream>
#include <iostream>

using namespace http_server::utils;

class LoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        originalLevel = Logger::GetLevel();
        originalCoutBuf = std::cout.rdbuf();
        originalCerrBuf = std::cerr.rdbuf();
    }

    void TearDown() override {
        Logger::SetLevel(originalLevel);
        std::cout.rdbuf(originalCoutBuf);
        std::cerr.rdbuf(originalCerrBuf);
    }

    void CaptureOutput() {
        std::cout.rdbuf(coutCapture.rdbuf());
        std::cerr.rdbuf(cerrCapture.rdbuf());
    }

    void RestoreOutput() {
        std::cout.rdbuf(originalCoutBuf);
        std::cerr.rdbuf(originalCerrBuf);
    }

    LogLevel originalLevel;
    std::streambuf* originalCoutBuf;
    std::streambuf* originalCerrBuf;
    std::stringstream coutCapture;
    std::stringstream cerrCapture;
};

TEST_F(LoggerTest, SetAndGetLevel) {
    Logger::SetLevel(LogLevel::Debug);
    EXPECT_EQ(Logger::GetLevel(), LogLevel::Debug);

    Logger::SetLevel(LogLevel::Error);
    EXPECT_EQ(Logger::GetLevel(), LogLevel::Error);
}

TEST_F(LoggerTest, InfoLoggedAtInfoLevel) {
    Logger::SetLevel(LogLevel::Info);
    CaptureOutput();

    Logger::Info("Test info message");

    RestoreOutput();
    std::string output = coutCapture.str();
    EXPECT_NE(output.find("[INFO ]"), std::string::npos);
    EXPECT_NE(output.find("Test info message"), std::string::npos);
}

TEST_F(LoggerTest, DebugNotLoggedAtInfoLevel) {
    Logger::SetLevel(LogLevel::Info);
    CaptureOutput();

    Logger::Debug("Debug message");

    RestoreOutput();
    std::string output = coutCapture.str();
    EXPECT_TRUE(output.empty());
}

TEST_F(LoggerTest, DebugLoggedAtDebugLevel) {
    Logger::SetLevel(LogLevel::Debug);
    CaptureOutput();

    Logger::Debug("Debug message");

    RestoreOutput();
    std::string output = coutCapture.str();
    EXPECT_NE(output.find("[DEBUG]"), std::string::npos);
    EXPECT_NE(output.find("Debug message"), std::string::npos);
}

TEST_F(LoggerTest, WarningLoggedToStderr) {
    Logger::SetLevel(LogLevel::Debug);
    CaptureOutput();

    Logger::Warning("Warning message");

    RestoreOutput();
    std::string errOutput = cerrCapture.str();
    EXPECT_NE(errOutput.find("[WARN ]"), std::string::npos);
    EXPECT_NE(errOutput.find("Warning message"), std::string::npos);
}

TEST_F(LoggerTest, ErrorLoggedToStderr) {
    Logger::SetLevel(LogLevel::Debug);
    CaptureOutput();

    Logger::Error("Error message");

    RestoreOutput();
    std::string errOutput = cerrCapture.str();
    EXPECT_NE(errOutput.find("[ERROR]"), std::string::npos);
    EXPECT_NE(errOutput.find("Error message"), std::string::npos);
}

TEST_F(LoggerTest, ErrorLevelFiltersLowerLevels) {
    Logger::SetLevel(LogLevel::Error);
    CaptureOutput();

    Logger::Debug("Debug");
    Logger::Info("Info");
    Logger::Warning("Warning");

    RestoreOutput();
    EXPECT_TRUE(coutCapture.str().empty());
    EXPECT_TRUE(cerrCapture.str().empty());
}

TEST_F(LoggerTest, ErrorLevelAllowsError) {
    Logger::SetLevel(LogLevel::Error);
    CaptureOutput();

    Logger::Error("Error message");

    RestoreOutput();
    EXPECT_FALSE(cerrCapture.str().empty());
}

TEST_F(LoggerTest, WarningLevelFiltersDebugAndInfo) {
    Logger::SetLevel(LogLevel::Warning);
    CaptureOutput();

    Logger::Debug("Debug");
    Logger::Info("Info");

    RestoreOutput();
    EXPECT_TRUE(coutCapture.str().empty());
}

TEST_F(LoggerTest, WarningLevelAllowsWarningAndError) {
    Logger::SetLevel(LogLevel::Warning);
    CaptureOutput();

    Logger::Warning("Warning");
    Logger::Error("Error");

    RestoreOutput();
    std::string output = cerrCapture.str();
    EXPECT_NE(output.find("Warning"), std::string::npos);
    EXPECT_NE(output.find("Error"), std::string::npos);
}

TEST_F(LoggerTest, LogIncludesTimestamp) {
    Logger::SetLevel(LogLevel::Info);
    CaptureOutput();

    Logger::Info("Test");

    RestoreOutput();
    std::string output = coutCapture.str();
    EXPECT_NE(output.find("[20"), std::string::npos);
    EXPECT_NE(output.find(":"), std::string::npos);
}

TEST_F(LoggerTest, LogWithLevelFunction) {
    Logger::SetLevel(LogLevel::Debug);
    CaptureOutput();

    Logger::Log(LogLevel::Info, "Via Log function");

    RestoreOutput();
    std::string output = coutCapture.str();
    EXPECT_NE(output.find("Via Log function"), std::string::npos);
}

TEST_F(LoggerTest, LogFiltersByLevelParameter) {
    Logger::SetLevel(LogLevel::Warning);
    CaptureOutput();

    Logger::Log(LogLevel::Info, "Should not appear");
    Logger::Log(LogLevel::Error, "Should appear");

    RestoreOutput();
    EXPECT_TRUE(coutCapture.str().empty());
    EXPECT_NE(cerrCapture.str().find("Should appear"), std::string::npos);
}
