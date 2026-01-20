cmake_minimum_required(VERSION 3.5)
project(PayBackendTests CXX)

find_package(Drogon CONFIG REQUIRED)

set(TEST_SRC
    test_main.cc
    PayAuthFilterTest.cc
    PayUtilsTest.cc
)

add_executable(
    ${PROJECT_NAME}
    ${TEST_SRC}
    ../filters/PayAuthFilter.cc
    ../filters/PayAuthMetrics.cc
    ../utils/PayUtils.cc
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /FI"${CMAKE_CURRENT_SOURCE_DIR}/../models/orm_compat.h")
endif()

add_test(NAME PayBackendTests COMMAND ${PROJECT_NAME})
