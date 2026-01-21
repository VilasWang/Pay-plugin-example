cmake_minimum_required(VERSION 3.5)
project(PayBackendTests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

set(TEST_SRC
    IdempotencyIntegrationTest.cc
    test_main.cc
    PayAuthFilterTest.cc
    PayAuthMetricsTest.cc
    PayUtilsTest.cc
    WechatPayClientTest.cc
)

add_executable(
    ${PROJECT_NAME}
    ${TEST_SRC}
    ../filters/PayAuthFilter.cc
    ../filters/PayAuthMetrics.cc
    ../models/PayIdempotency.cc
    ../plugins/WechatPayClient.cc
    ../utils/PayUtils.cc
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon OpenSSL::Crypto OpenSSL::SSL)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /FI"${CMAKE_CURRENT_SOURCE_DIR}/../models/orm_compat.h")
endif()

add_test(NAME PayBackendTests COMMAND ${PROJECT_NAME})
