# Copyright (C) 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/WFP-tool.git

cmake_minimum_required(VERSION 3.25)

project(net-user-filter VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "net-user-filter supports Windows only")
endif()

add_library(wfp_tool_lib STATIC
    src/sandbox_network.cpp
)
target_include_directories(wfp_tool_lib PUBLIC src)
target_compile_features(wfp_tool_lib PUBLIC cxx_std_23)
target_compile_definitions(wfp_tool_lib PUBLIC
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_compile_options(wfp_tool_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc>
)
target_link_libraries(wfp_tool_lib PUBLIC
    advapi32
    fwpuclnt
    ole32
    ws2_32
)

add_executable(wfp-tool src/main.cpp)
target_link_libraries(wfp-tool PRIVATE wfp_tool_lib)

include(CTest)
if(BUILD_TESTING)
    add_executable(wfp-tool-tests tests/tests.cpp)
    target_link_libraries(wfp-tool-tests PRIVATE wfp_tool_lib)
    add_test(NAME wfp-tool-tests COMMAND wfp-tool-tests)

    add_executable(wfp-tool-integration-tests tests/wfp_integration_tests.cpp)
    target_link_libraries(wfp-tool-integration-tests PRIVATE wfp_tool_lib)
    if(DEFINED ENV{WFP_TOOL_INTEGRATION_USER} AND NOT "$ENV{WFP_TOOL_INTEGRATION_USER}" STREQUAL ""
       AND DEFINED ENV{WFP_TOOL_INTEGRATION_OTHER_USER} AND NOT "$ENV{WFP_TOOL_INTEGRATION_OTHER_USER}" STREQUAL "")
        add_test(NAME wfp-tool-integration-tests
                 COMMAND wfp-tool-integration-tests "$ENV{WFP_TOOL_INTEGRATION_USER}"
                                                   "$ENV{WFP_TOOL_INTEGRATION_OTHER_USER}")
        set_tests_properties(wfp-tool-integration-tests PROPERTIES
            LABELS integration
            RUN_SERIAL TRUE
        )
    endif()
endif()

if(MSVC)
    set(runtime_targets
        wfp_tool_lib
        wfp-tool
    )
    if(BUILD_TESTING)
        list(APPEND runtime_targets wfp-tool-tests)
        list(APPEND runtime_targets wfp-tool-integration-tests)
    endif()
    set_property(TARGET ${runtime_targets}
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
