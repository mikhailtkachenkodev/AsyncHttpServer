#include "http/HttpStatus.hpp"

#include <gtest/gtest.h>

using namespace http_server::http;

class HttpStatusTest : public ::testing::Test {};

// StatusToString tests

TEST_F(HttpStatusTest, StatusToStringOK) {
    EXPECT_EQ(StatusToString(HttpStatus::OK), "OK");
}

TEST_F(HttpStatusTest, StatusToStringCreated) {
    EXPECT_EQ(StatusToString(HttpStatus::Created), "Created");
}

TEST_F(HttpStatusTest, StatusToStringNoContent) {
    EXPECT_EQ(StatusToString(HttpStatus::NoContent), "No Content");
}

TEST_F(HttpStatusTest, StatusToStringMovedPermanently) {
    EXPECT_EQ(StatusToString(HttpStatus::MovedPermanently), "Moved Permanently");
}

TEST_F(HttpStatusTest, StatusToStringFound) {
    EXPECT_EQ(StatusToString(HttpStatus::Found), "Found");
}

TEST_F(HttpStatusTest, StatusToStringNotModified) {
    EXPECT_EQ(StatusToString(HttpStatus::NotModified), "Not Modified");
}

TEST_F(HttpStatusTest, StatusToStringBadRequest) {
    EXPECT_EQ(StatusToString(HttpStatus::BadRequest), "Bad Request");
}

TEST_F(HttpStatusTest, StatusToStringUnauthorized) {
    EXPECT_EQ(StatusToString(HttpStatus::Unauthorized), "Unauthorized");
}

TEST_F(HttpStatusTest, StatusToStringForbidden) {
    EXPECT_EQ(StatusToString(HttpStatus::Forbidden), "Forbidden");
}

TEST_F(HttpStatusTest, StatusToStringNotFound) {
    EXPECT_EQ(StatusToString(HttpStatus::NotFound), "Not Found");
}

TEST_F(HttpStatusTest, StatusToStringMethodNotAllowed) {
    EXPECT_EQ(StatusToString(HttpStatus::MethodNotAllowed), "Method Not Allowed");
}

TEST_F(HttpStatusTest, StatusToStringRequestTimeout) {
    EXPECT_EQ(StatusToString(HttpStatus::RequestTimeout), "Request Timeout");
}

TEST_F(HttpStatusTest, StatusToStringConflict) {
    EXPECT_EQ(StatusToString(HttpStatus::Conflict), "Conflict");
}

TEST_F(HttpStatusTest, StatusToStringLengthRequired) {
    EXPECT_EQ(StatusToString(HttpStatus::LengthRequired), "Length Required");
}

TEST_F(HttpStatusTest, StatusToStringPayloadTooLarge) {
    EXPECT_EQ(StatusToString(HttpStatus::PayloadTooLarge), "Payload Too Large");
}

TEST_F(HttpStatusTest, StatusToStringUriTooLong) {
    EXPECT_EQ(StatusToString(HttpStatus::UriTooLong), "URI Too Long");
}

TEST_F(HttpStatusTest, StatusToStringUnsupportedMediaType) {
    EXPECT_EQ(StatusToString(HttpStatus::UnsupportedMediaType), "Unsupported Media Type");
}

TEST_F(HttpStatusTest, StatusToStringInternalServerError) {
    EXPECT_EQ(StatusToString(HttpStatus::InternalServerError), "Internal Server Error");
}

TEST_F(HttpStatusTest, StatusToStringNotImplemented) {
    EXPECT_EQ(StatusToString(HttpStatus::NotImplemented), "Not Implemented");
}

TEST_F(HttpStatusTest, StatusToStringBadGateway) {
    EXPECT_EQ(StatusToString(HttpStatus::BadGateway), "Bad Gateway");
}

TEST_F(HttpStatusTest, StatusToStringServiceUnavailable) {
    EXPECT_EQ(StatusToString(HttpStatus::ServiceUnavailable), "Service Unavailable");
}

TEST_F(HttpStatusTest, StatusToStringGatewayTimeout) {
    EXPECT_EQ(StatusToString(HttpStatus::GatewayTimeout), "Gateway Timeout");
}

// HttpStatus enum values

TEST_F(HttpStatusTest, HttpStatusEnumValues) {
    EXPECT_EQ(static_cast<int>(HttpStatus::OK), 200);
    EXPECT_EQ(static_cast<int>(HttpStatus::Created), 201);
    EXPECT_EQ(static_cast<int>(HttpStatus::NoContent), 204);
    EXPECT_EQ(static_cast<int>(HttpStatus::MovedPermanently), 301);
    EXPECT_EQ(static_cast<int>(HttpStatus::Found), 302);
    EXPECT_EQ(static_cast<int>(HttpStatus::NotModified), 304);
    EXPECT_EQ(static_cast<int>(HttpStatus::BadRequest), 400);
    EXPECT_EQ(static_cast<int>(HttpStatus::Unauthorized), 401);
    EXPECT_EQ(static_cast<int>(HttpStatus::Forbidden), 403);
    EXPECT_EQ(static_cast<int>(HttpStatus::NotFound), 404);
    EXPECT_EQ(static_cast<int>(HttpStatus::MethodNotAllowed), 405);
    EXPECT_EQ(static_cast<int>(HttpStatus::InternalServerError), 500);
}

// MethodToString tests

TEST_F(HttpStatusTest, MethodToStringGET) {
    EXPECT_EQ(MethodToString(HttpMethod::GET), "GET");
}

TEST_F(HttpStatusTest, MethodToStringPOST) {
    EXPECT_EQ(MethodToString(HttpMethod::POST), "POST");
}

TEST_F(HttpStatusTest, MethodToStringPUT) {
    EXPECT_EQ(MethodToString(HttpMethod::PUT), "PUT");
}

TEST_F(HttpStatusTest, MethodToStringDELETE) {
    EXPECT_EQ(MethodToString(HttpMethod::DELETE_), "DELETE");
}

TEST_F(HttpStatusTest, MethodToStringPATCH) {
    EXPECT_EQ(MethodToString(HttpMethod::PATCH), "PATCH");
}

TEST_F(HttpStatusTest, MethodToStringHEAD) {
    EXPECT_EQ(MethodToString(HttpMethod::HEAD), "HEAD");
}

TEST_F(HttpStatusTest, MethodToStringOPTIONS) {
    EXPECT_EQ(MethodToString(HttpMethod::OPTIONS), "OPTIONS");
}

TEST_F(HttpStatusTest, MethodToStringUNKNOWN) {
    EXPECT_EQ(MethodToString(HttpMethod::UNKNOWN), "UNKNOWN");
}

// StringToMethod tests

TEST_F(HttpStatusTest, StringToMethodGET) {
    EXPECT_EQ(StringToMethod("GET"), HttpMethod::GET);
}

TEST_F(HttpStatusTest, StringToMethodPOST) {
    EXPECT_EQ(StringToMethod("POST"), HttpMethod::POST);
}

TEST_F(HttpStatusTest, StringToMethodPUT) {
    EXPECT_EQ(StringToMethod("PUT"), HttpMethod::PUT);
}

TEST_F(HttpStatusTest, StringToMethodDELETE) {
    EXPECT_EQ(StringToMethod("DELETE"), HttpMethod::DELETE_);
}

TEST_F(HttpStatusTest, StringToMethodPATCH) {
    EXPECT_EQ(StringToMethod("PATCH"), HttpMethod::PATCH);
}

TEST_F(HttpStatusTest, StringToMethodHEAD) {
    EXPECT_EQ(StringToMethod("HEAD"), HttpMethod::HEAD);
}

TEST_F(HttpStatusTest, StringToMethodOPTIONS) {
    EXPECT_EQ(StringToMethod("OPTIONS"), HttpMethod::OPTIONS);
}

TEST_F(HttpStatusTest, StringToMethodUnknown) {
    EXPECT_EQ(StringToMethod("INVALID"), HttpMethod::UNKNOWN);
    EXPECT_EQ(StringToMethod(""), HttpMethod::UNKNOWN);
    EXPECT_EQ(StringToMethod("get"), HttpMethod::UNKNOWN);
}

// Round-trip tests

TEST_F(HttpStatusTest, MethodRoundTrip) {
    EXPECT_EQ(StringToMethod(MethodToString(HttpMethod::GET)), HttpMethod::GET);
    EXPECT_EQ(StringToMethod(MethodToString(HttpMethod::POST)), HttpMethod::POST);
    EXPECT_EQ(StringToMethod(MethodToString(HttpMethod::PUT)), HttpMethod::PUT);
    EXPECT_EQ(StringToMethod(MethodToString(HttpMethod::DELETE_)), HttpMethod::DELETE_);
    EXPECT_EQ(StringToMethod(MethodToString(HttpMethod::PATCH)), HttpMethod::PATCH);
    EXPECT_EQ(StringToMethod(MethodToString(HttpMethod::HEAD)), HttpMethod::HEAD);
    EXPECT_EQ(StringToMethod(MethodToString(HttpMethod::OPTIONS)), HttpMethod::OPTIONS);
}
