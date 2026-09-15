// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/user-net-lock.git

#include "wfp_object_access.h"
#include "user_net_lock.h"

#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <memory>
#include <sddl.h>
#include <string_view>

namespace
{

int failures = 0;

void check(bool condition, std::string_view message)
{
    if (!condition)
    {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void cli_tests()
{
    check(user_net_lock::run({}) == static_cast<int>(user_net_lock::ExitCode::usage),
        "empty CLI is a usage error");

    constexpr std::wstring_view unknown[] = {L"unknown"};
    check(user_net_lock::run(unknown) == static_cast<int>(user_net_lock::ExitCode::usage),
        "unknown command is a usage error");

    for (const auto command : {L"apply", L"verify"})
    {
        const std::wstring_view missing_port[] = {command, L"--user", L"AgentSandbox"};
        check(user_net_lock::run(missing_port) == static_cast<int>(user_net_lock::ExitCode::usage),
            "apply and verify require a user and port");

        const std::wstring_view config_file[] = {command, L"--config", L"policy.ini"};
        check(user_net_lock::run(config_file) == static_cast<int>(user_net_lock::ExitCode::usage),
            "configuration files are not accepted");
    }

    constexpr std::wstring_view remove_config[] = {L"remove", L"--config", L"policy.ini"};
    check(user_net_lock::run(remove_config) == static_cast<int>(user_net_lock::ExitCode::usage),
        "remove does not accept a configuration file");

    constexpr std::wstring_view missing_remove_user[] = {L"remove"};
    check(
        user_net_lock::run(missing_remove_user) == static_cast<int>(user_net_lock::ExitCode::usage),
        "remove requires a user");

    constexpr std::wstring_view invalid_list[] = {L"list"};
    check(user_net_lock::run(invalid_list) == static_cast<int>(user_net_lock::ExitCode::usage),
        "list requires a user");

    constexpr std::wstring_view removed_clear[] = {L"clear", L"--user", L"AgentSandbox"};
    check(user_net_lock::run(removed_clear) == static_cast<int>(user_net_lock::ExitCode::usage),
        "clear is no longer an alias for remove");
}

PSECURITY_DESCRIPTOR descriptor_from_sddl(PCWSTR sddl)
{
    PSECURITY_DESCRIPTOR descriptor {};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &descriptor, nullptr))
    {
        check(false, "test security descriptor can be created");
    }
    return descriptor;
}

void wfp_object_access_control_tests()
{
    // P prevents inherited WFP engine ACEs from widening the administrative
    // baseline. A managed account receives a separate, read-only ACE.
    constexpr wchar_t expected_sddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    check(
        std::wcscmp(user_net_lock::detail::administrative_wfp_object_dacl_sddl, expected_sddl) == 0,
        "WFP objects retain SYSTEM and Administrators full control baseline");

    PSECURITY_DESCRIPTOR expected =
        descriptor_from_sddl(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)");
    std::unique_ptr<void, decltype(&LocalFree)> expected_memory(expected, LocalFree);
    if (!expected)
    {
        return;
    }
    check(user_net_lock::detail::same_access_control_descriptor(expected, expected),
        "the expected WFP object DACL matches itself");
    check(user_net_lock::detail::has_protected_dacl(expected),
        "the expected WFP object DACL is protected");

    PSECURITY_DESCRIPTOR unprotected =
        descriptor_from_sddl(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)");
    std::unique_ptr<void, decltype(&LocalFree)> unprotected_memory(unprotected, LocalFree);
    if (!unprotected)
    {
        return;
    }
    check(!user_net_lock::detail::has_protected_dacl(unprotected),
        "an unprotected WFP object DACL is rejected");

    // A managed account may read status, but no standard account may receive
    // WFP write, delete, or DACL-changing rights.
    PSECURITY_DESCRIPTOR broader = descriptor_from_sddl(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GW;;;AU)");
    std::unique_ptr<void, decltype(&LocalFree)> broader_memory(broader, LocalFree);
    if (!broader)
    {
        return;
    }
    check(!user_net_lock::detail::same_access_control_descriptor(broader, expected),
        "a WFP object DACL that grants a managed account write access is rejected");
}

} // namespace

int main()
{
    cli_tests();
    wfp_object_access_control_tests();
    if (failures != 0)
    {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "All tests passed\n";
    return EXIT_SUCCESS;
}
