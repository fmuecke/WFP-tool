// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/WFP-tool.git

#include "wfp_tool.h"
#include "wfp_object_access.h"

#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <memory>
#include <string_view>

#include <sddl.h>

namespace {

int failures = 0;

void check(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

void cli_tests() {
  check(wfp_tool::run({}) == static_cast<int>(wfp_tool::ExitCode::usage),
        "empty CLI is a usage error");

  constexpr std::wstring_view unknown[] = {L"unknown"};
  check(wfp_tool::run(unknown) == static_cast<int>(wfp_tool::ExitCode::usage),
        "unknown command is a usage error");

  for (const auto command : {L"apply", L"verify"}) {
    const std::wstring_view missing_port[] = {command, L"--user",
                                              L"AgentSandbox"};
    check(wfp_tool::run(missing_port) ==
              static_cast<int>(wfp_tool::ExitCode::usage),
          "apply and verify require a user and port");

    const std::wstring_view config_file[] = {command, L"--config",
                                             L"policy.ini"};
    check(wfp_tool::run(config_file) ==
              static_cast<int>(wfp_tool::ExitCode::usage),
          "configuration files are not accepted");
  }

  constexpr std::wstring_view remove_config[] = {L"remove", L"--config",
                                                 L"policy.ini"};
  check(wfp_tool::run(remove_config) ==
            static_cast<int>(wfp_tool::ExitCode::usage),
        "remove does not accept a configuration file");

  constexpr std::wstring_view missing_remove_user[] = {L"remove"};
  check(wfp_tool::run(missing_remove_user) ==
            static_cast<int>(wfp_tool::ExitCode::usage),
        "remove requires a user");

  constexpr std::wstring_view invalid_list[] = {L"list"};
  check(wfp_tool::run(invalid_list) ==
            static_cast<int>(wfp_tool::ExitCode::usage),
        "list requires a user");

  constexpr std::wstring_view removed_clear[] = {L"clear", L"--user",
                                                 L"AgentSandbox"};
  check(wfp_tool::run(removed_clear) ==
            static_cast<int>(wfp_tool::ExitCode::usage),
        "clear is no longer an alias for remove");
}

PSECURITY_DESCRIPTOR descriptor_from_sddl(PCWSTR sddl) {
  PSECURITY_DESCRIPTOR descriptor{};
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
    check(false, "test security descriptor can be created");
  }
  return descriptor;
}

void wfp_object_access_control_tests() {
  // Keep the test's independent expected value in sync with the administrative
  // policy contract: P prevents inherited WFP engine ACEs from widening it.
  constexpr wchar_t expected_sddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
  check(std::wcscmp(wfp_tool::detail::expected_wfp_object_dacl_sddl,
                    expected_sddl) == 0,
        "WFP objects grant full control only to SYSTEM and Administrators");

  PSECURITY_DESCRIPTOR expected = descriptor_from_sddl(expected_sddl);
  std::unique_ptr<void, decltype(&LocalFree)> expected_memory(expected,
                                                              LocalFree);
  if (!expected) {
    return;
  }
  check(wfp_tool::detail::same_access_control_descriptor(expected, expected),
        "the expected WFP object DACL matches itself");

  // This intentionally grants Everyone read access and must not match the
  // administrative-only descriptor above.
  PSECURITY_DESCRIPTOR broader =
      descriptor_from_sddl(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)");
  std::unique_ptr<void, decltype(&LocalFree)> broader_memory(broader,
                                                             LocalFree);
  if (!broader) {
    return;
  }
  check(!wfp_tool::detail::same_access_control_descriptor(broader, expected),
        "a WFP object DACL that grants Everyone access is rejected");
}

} // namespace

int main() {
  cli_tests();
  wfp_object_access_control_tests();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "All tests passed\n";
  return EXIT_SUCCESS;
}
