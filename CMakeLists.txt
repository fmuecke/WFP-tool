cmake_minimum_required(VERSION 3.25)

project(net-user-filter VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "net-user-filter supports Windows only")
endif()

add_library(sandbox_network STATIC
    src/sandbox_network.cpp
)
target_include_directories(sandbox_network PUBLIC src)
target_compile_features(sandbox_network PUBLIC cxx_std_23)
target_compile_definitions(sandbox_network PUBLIC
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_compile_options(sandbox_network PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc>
)
target_link_libraries(sandbox_network PUBLIC
    advapi32
    fwpuclnt
    iphlpapi
    netapi32
    ws2_32
)

add_executable(sandbox-network src/main.cpp)
target_link_libraries(sandbox-network PRIVATE sandbox_network)

include(CTest)
if(BUILD_TESTING)
    add_executable(sandbox-network-tests tests/tests.cpp)
    target_link_libraries(sandbox-network-tests PRIVATE sandbox_network)
    add_test(NAME sandbox-network-tests COMMAND sandbox-network-tests)
endif()

if(MSVC)
    set(runtime_targets sandbox_network sandbox-network)
    if(BUILD_TESTING)
        list(APPEND runtime_targets sandbox-network-tests)
    endif()
    set_property(TARGET ${runtime_targets}
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
