# Copyright (C) 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/user-net-lock.git

cmake_minimum_required(VERSION 3.25)

project(user-net-lock VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "user-net-lock supports Windows only")
endif()

add_library(user-net-lock_lib STATIC
    src/user_net_lock.cpp
)
target_include_directories(user-net-lock_lib PUBLIC src)
target_compile_features(user-net-lock_lib PUBLIC cxx_std_23)
target_compile_definitions(user-net-lock_lib PUBLIC
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_compile_options(user-net-lock_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc>
)
target_link_libraries(user-net-lock_lib PUBLIC
    advapi32
    fwpuclnt
    ole32
    ws2_32
)

add_executable(user-net-lock src/main.cpp)
target_link_libraries(user-net-lock PRIVATE user-net-lock_lib)

include(CTest)
if(BUILD_TESTING)
    add_executable(user-net-lock-tests tests/tests.cpp)
    target_link_libraries(user-net-lock-tests PRIVATE user-net-lock_lib)
    add_test(NAME user-net-lock-tests COMMAND user-net-lock-tests)

    add_executable(user-net-lock-integration-tests tests/wfp_integration_tests.cpp)
    target_link_libraries(user-net-lock-integration-tests PRIVATE user-net-lock_lib)

    add_executable(user-net-lock-traffic-integration-tests tests/wfp_traffic_integration_tests.cpp)
    target_link_libraries(user-net-lock-traffic-integration-tests PRIVATE user-net-lock_lib iphlpapi netapi32)
    if(DEFINED ENV{USER_NET_LOCK_INTEGRATION_USER} AND NOT "$ENV{USER_NET_LOCK_INTEGRATION_USER}" STREQUAL ""
       AND DEFINED ENV{USER_NET_LOCK_INTEGRATION_OTHER_USER} AND NOT "$ENV{USER_NET_LOCK_INTEGRATION_OTHER_USER}" STREQUAL "")
        add_test(NAME user-net-lock-integration-tests
                 COMMAND user-net-lock-integration-tests "$ENV{USER_NET_LOCK_INTEGRATION_USER}"
                                                   "$ENV{USER_NET_LOCK_INTEGRATION_OTHER_USER}")
        set_tests_properties(user-net-lock-integration-tests PROPERTIES
            LABELS integration
            RUN_SERIAL TRUE
        )
    endif()
endif()

if(MSVC)
    set(runtime_targets
        user-net-lock_lib
        user-net-lock
    )
    if(BUILD_TESTING)
        list(APPEND runtime_targets user-net-lock-tests)
        list(APPEND runtime_targets user-net-lock-integration-tests)
        list(APPEND runtime_targets user-net-lock-traffic-integration-tests)
    endif()
    set_property(TARGET ${runtime_targets}
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
