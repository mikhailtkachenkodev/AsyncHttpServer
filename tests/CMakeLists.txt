# tests/CMakeLists.txt

include(GoogleTest)

# Unit test executables - using Google Test
add_executable(HttpParserTests unit/HttpParserTests.cpp)
target_link_libraries(HttpParserTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(HttpParserTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(HttpParserTests)

add_executable(HttpRouterTests unit/HttpRouterTests.cpp)
target_link_libraries(HttpRouterTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(HttpRouterTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(HttpRouterTests)

add_executable(ThreadSafeStoreTests unit/ThreadSafeStoreTests.cpp)
target_link_libraries(ThreadSafeStoreTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(ThreadSafeStoreTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(ThreadSafeStoreTests)

add_executable(InputValidationTests unit/InputValidationTests.cpp)
target_link_libraries(InputValidationTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(InputValidationTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(InputValidationTests)

add_executable(HttpRequestTests unit/HttpRequestTests.cpp)
target_link_libraries(HttpRequestTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(HttpRequestTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(HttpRequestTests)

add_executable(HttpResponseTests unit/HttpResponseTests.cpp)
target_link_libraries(HttpResponseTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(HttpResponseTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(HttpResponseTests)

add_executable(HttpStatusTests unit/HttpStatusTests.cpp)
target_link_libraries(HttpStatusTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(HttpStatusTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(HttpStatusTests)

add_executable(LoggerTests unit/LoggerTests.cpp)
target_link_libraries(LoggerTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(LoggerTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(LoggerTests)

add_executable(SystemInfoTests unit/SystemInfoTests.cpp)
target_link_libraries(SystemInfoTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(SystemInfoTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(SystemInfoTests)

add_executable(ErrorHandlerTests unit/ErrorHandlerTests.cpp)
target_link_libraries(ErrorHandlerTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(ErrorHandlerTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(ErrorHandlerTests)

# Security/TLS unit tests
add_executable(SchannelContextTests unit/SchannelContextTests.cpp)
target_link_libraries(SchannelContextTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(SchannelContextTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(SchannelContextTests)

add_executable(TlsConnectionTests unit/TlsConnectionTests.cpp)
target_link_libraries(TlsConnectionTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(TlsConnectionTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(TlsConnectionTests)

add_executable(HttpsServerConfigTests unit/HttpsServerConfigTests.cpp)
target_link_libraries(HttpsServerConfigTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(HttpsServerConfigTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(HttpsServerConfigTests)

# Integration test executable - uses Google Test
add_executable(IntegrationTests integration/ServerIntegrationTests.cpp)
target_link_libraries(IntegrationTests PRIVATE AsyncHttpServerLib GTest::gtest GTest::gtest_main)
target_include_directories(IntegrationTests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)
gtest_discover_tests(IntegrationTests)
