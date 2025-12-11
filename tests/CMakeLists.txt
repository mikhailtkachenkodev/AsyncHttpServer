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
