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

configure_file(
    scripts/setup-gost.ps1
    ${CMAKE_BINARY_DIR}/setup-gost.ps1
    COPYONLY
)

include(CTest)
if(BUILD_TESTING)
    add_executable(wfp-tool-tests tests/tests.cpp)
    target_link_libraries(wfp-tool-tests PRIVATE wfp_tool_lib)
    add_test(NAME wfp-tool-tests COMMAND wfp-tool-tests)
    add_test(
        NAME setup-gost-self-test
        COMMAND powershell.exe -NoLogo -NoProfile -NonInteractive
            -ExecutionPolicy Bypass
            -File ${CMAKE_SOURCE_DIR}/scripts/setup-gost.ps1 -SelfTest
    )
endif()

if(MSVC)
    set(runtime_targets
        wfp_tool_lib
        wfp-tool
    )
    if(BUILD_TESTING)
        list(APPEND runtime_targets wfp-tool-tests)
    endif()
    set_property(TARGET ${runtime_targets}
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
