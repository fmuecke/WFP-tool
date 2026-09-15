// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/user-net-lock.git

#include "user_net_lock.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <fwpmtypes.h>
#include <fwpmu.h>
#include <iostream>
#include <memory>
#include <sddl.h>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <windows.h>

namespace
{

constexpr GUID provider_key {
    0x9b2365a6, 0xf9b9, 0x49f9, {0xab, 0xdb, 0x19, 0x65, 0x79, 0xb1, 0x48, 0x1c}
};
constexpr GUID sublayer_key {
    0x42f667f1, 0x2945, 0x48bd, {0x81, 0x44, 0x0b, 0xd0, 0x21, 0xe6, 0x74, 0x31}
};
// Deliberately weak descriptor used to prove verify rejects a policy object
// that grants a regular user access.
constexpr wchar_t weaker_dacl_sddl[] = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)";
constexpr std::wstring_view first_port = L"49152";
constexpr std::wstring_view replacement_port = L"49153";
constexpr std::wstring_view second_port = L"49154";

int failures {};

void check(bool condition, std::string_view message)
{
    if (!condition)
    {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

struct Engine
{
    HANDLE value {};

    ~Engine()
    {
        if (value)
        {
            FwpmEngineClose0(value);
        }
    }
};

class SecurityDescriptor
{
  public:
    explicit SecurityDescriptor(PCWSTR sddl)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &value_, nullptr))
        {
            check(false, "test security descriptor can be created");
        }
    }

    ~SecurityDescriptor()
    {
        if (value_)
        {
            LocalFree(value_);
        }
    }

    SecurityDescriptor(const SecurityDescriptor&) = delete;
    SecurityDescriptor& operator=(const SecurityDescriptor&) = delete;

    PACL dacl() const
    {
        BOOL present {};
        BOOL defaulted {};
        PACL result {};
        if (!value_ || !GetSecurityDescriptorDacl(value_, &present, &result, &defaulted) ||
            !present || !result)
        {
            check(false, "test security descriptor has a DACL");
            return nullptr;
        }
        return result;
    }

  private:
    PSECURITY_DESCRIPTOR value_ {};
};

bool is_elevated()
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators {};
    if (!AllocateAndInitializeSid(&authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &administrators))
    {
        return false;
    }
    BOOL member {};
    const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
    FreeSid(administrators);
    return checked && member != FALSE;
}

bool open_engine(Engine& engine)
{
    const DWORD code = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine.value);
    check(code == ERROR_SUCCESS, "open WFP engine");
    return code == ERROR_SUCCESS;
}

int run_user_port(std::wstring_view command, std::wstring_view user, std::wstring_view port)
{
    const std::array arguments {
        command, std::wstring_view(L"--user"), user, std::wstring_view(L"--port"), port
    };
    return user_net_lock::run(arguments);
}

int run_remove(std::wstring_view user)
{
    const std::array arguments {std::wstring_view(L"remove"), std::wstring_view(L"--user"), user};
    return user_net_lock::run(arguments);
}

class ScopedWcerrCapture
{
  public:
    ScopedWcerrCapture() : original_(std::wcerr.rdbuf(captured_.rdbuf())) {}

    ~ScopedWcerrCapture() { std::wcerr.rdbuf(original_); }

    std::wstring str() const { return captured_.str(); }

    ScopedWcerrCapture(const ScopedWcerrCapture&) = delete;
    ScopedWcerrCapture& operator=(const ScopedWcerrCapture&) = delete;

  private:
    std::wostringstream captured_;
    std::wstreambuf* original_;
};

bool expect_verify_failure(std::wstring_view user, std::wstring_view port)
{
    int exit_code {};
    std::wstring diagnostic;
    {
        // A rejection is the expected assertion here. Keep its CLI error output
        // out of a passing integration-test transcript.
        ScopedWcerrCapture errors;
        exit_code = run_user_port(L"verify", user, port);
        diagnostic = errors.str();
    }
    check(exit_code == static_cast<int>(user_net_lock::ExitCode::verification),
        "verify rejects the tampered WFP object");
    if (exit_code != static_cast<int>(user_net_lock::ExitCode::verification))
    {
        std::wcerr << L"Unexpected verify result (" << exit_code << L"): " << diagnostic;
    }
    return exit_code == static_cast<int>(user_net_lock::ExitCode::verification);
}

bool reapply_and_verify(std::wstring_view user, std::wstring_view port)
{
    const int apply = run_user_port(L"apply", user, port);
    check(apply == static_cast<int>(user_net_lock::ExitCode::success),
        "apply restores the expected policy");
    const int verify = run_user_port(L"verify", user, port);
    check(verify == static_cast<int>(user_net_lock::ExitCode::success),
        "verify accepts the restored policy");
    return apply == static_cast<int>(user_net_lock::ExitCode::success) &&
           verify == static_cast<int>(user_net_lock::ExitCode::success);
}

std::vector<GUID> filter_keys(HANDLE engine)
{
    std::vector<GUID> keys;
    HANDLE enumeration {};
    const DWORD create = FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration);
    if (create != ERROR_SUCCESS)
    {
        check(false, "create WFP filter enumeration");
        return keys;
    }
    for (;;)
    {
        FWPM_FILTER0** filters {};
        UINT32 count {};
        const DWORD code = FwpmFilterEnum0(engine, enumeration, 64, &filters, &count);
        if (code != ERROR_SUCCESS)
        {
            check(false, "enumerate WFP filters");
            break;
        }
        for (UINT32 index = 0; index < count; ++index)
        {
            if (filters[index]->providerKey &&
                IsEqualGUID(*filters[index]->providerKey, provider_key))
            {
                keys.push_back(filters[index]->filterKey);
            }
        }
        FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        if (count == 0)
        {
            break;
        }
    }
    FwpmFilterDestroyEnumHandle0(engine, enumeration);
    return keys;
}

std::vector<BYTE> account_sid(std::wstring_view user)
{
    DWORD sid_size {};
    DWORD domain_size {};
    SID_NAME_USE use {};
    LookupAccountNameW(
        nullptr, std::wstring(user).c_str(), nullptr, &sid_size, nullptr, &domain_size, &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sid_size == 0)
    {
        check(false, "resolve disposable-account SID size");
        return {};
    }
    std::vector<BYTE> sid(sid_size);
    std::wstring domain(domain_size, L'\0');
    if (!LookupAccountNameW(nullptr,
            std::wstring(user).c_str(),
            sid.data(),
            &sid_size,
            domain.data(),
            &domain_size,
            &use))
    {
        check(false, "resolve disposable-account SID");
        return {};
    }
    sid.resize(sid_size);
    return sid;
}

bool filter_container_grants_enumeration(HANDLE engine, std::wstring_view user)
{
    const auto sid = account_sid(user);
    if (sid.empty())
    {
        return false;
    }
    PSECURITY_DESCRIPTOR descriptor {};
    const DWORD read = FwpmFilterGetSecurityInfoByKey0(engine,
        nullptr,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &descriptor);
    if (read != ERROR_SUCCESS)
    {
        check(false, "read WFP filter-container DACL");
        return false;
    }
    BOOL present {};
    BOOL defaulted {};
    PACL dacl {};
    const bool valid =
        GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present && dacl;
    bool grants_enumeration {};
    if (valid)
    {
        for (DWORD index = 0; index < dacl->AceCount; ++index)
        {
            void* entry {};
            if (!GetAce(dacl, index, &entry))
            {
                check(false, "read WFP filter-container ACE");
                break;
            }
            const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(entry);
            if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 &&
                ace->Mask == FWPM_ACTRL_ENUM &&
                EqualSid(const_cast<PSID>(static_cast<const void*>(&ace->SidStart)),
                    const_cast<BYTE*>(sid.data())))
            {
                grants_enumeration = true;
                break;
            }
        }
    }
    else
    {
        check(false, "WFP filter container has a DACL");
    }
    FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
    return grants_enumeration;
}

void lifecycle_tests(HANDLE engine, std::wstring_view user)
{
    check(reapply_and_verify(user, first_port),
        "apply and verify create the disposable-account policy");
    const auto keys = filter_keys(engine);
    check(keys.size() == 7, "apply creates exactly seven persistent WFP filters");
    for (const GUID& key : keys)
    {
        FWPM_FILTER0* filter {};
        const DWORD filter_result = FwpmFilterGetByKey0(engine, &key, &filter);
        const bool persistent =
            filter_result == ERROR_SUCCESS && filter->flags == FWPM_FILTER_FLAG_PERSISTENT;
        if (filter_result == ERROR_SUCCESS)
        {
            FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
        }
        check(persistent, "each user-net-lock filter is persistent");
    }

    check(run_remove(user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove deletes the disposable-account policy");
    check(filter_keys(engine).empty(), "remove leaves no user-net-lock filters");
    check(!filter_container_grants_enumeration(engine, user),
        "remove revokes the account's WFP filter-enumeration access");

    FWPM_PROVIDER0* provider {};
    const DWORD provider_result = FwpmProviderGetByKey0(engine, &provider_key, &provider);
    if (provider_result == ERROR_SUCCESS)
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
    }
    check(provider_result == FWP_E_PROVIDER_NOT_FOUND,
        "remove deletes the unreferenced user-net-lock provider");

    FWPM_SUBLAYER0* sublayer {};
    const DWORD sublayer_result = FwpmSubLayerGetByKey0(engine, &sublayer_key, &sublayer);
    if (sublayer_result == ERROR_SUCCESS)
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
    }
    check(sublayer_result == FWP_E_SUBLAYER_NOT_FOUND,
        "remove deletes the unreferenced user-net-lock sublayer");
}

void tamper_provider(HANDLE engine, PACL dacl)
{
    check(FwpmProviderSetSecurityInfoByKey0(
              engine, &provider_key, DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr) ==
              ERROR_SUCCESS,
        "tamper provider DACL");
}

void tamper_sublayer(HANDLE engine, PACL dacl)
{
    check(FwpmSubLayerSetSecurityInfoByKey0(
              engine, &sublayer_key, DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr) ==
              ERROR_SUCCESS,
        "tamper sublayer DACL");
}

bool tamper_filters(HANDLE engine, PACL dacl)
{
    const auto keys = filter_keys(engine);
    check(keys.size() == 7, "exactly seven WFP filters are present before tampering");
    if (keys.size() != 7)
    {
        return false;
    }
    bool succeeded = true;
    for (const GUID& key : keys)
    {
        const bool changed =
            FwpmFilterSetSecurityInfoByKey0(
                engine, &key, DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr) ==
            ERROR_SUCCESS;
        check(changed, "tamper filter DACL");
        succeeded = succeeded && changed;
    }
    return succeeded;
}

struct Cleanup
{
    std::wstring_view first_user;
    std::wstring_view second_user;

    ~Cleanup()
    {
        run_remove(first_user);
        run_remove(second_user);
    }
};

void idempotence_and_isolation_tests(std::wstring_view first_user, std::wstring_view second_user)
{
    check(reapply_and_verify(first_user, first_port), "apply creates the first account policy");
    check(reapply_and_verify(first_user, replacement_port),
        "reapplying replaces the first account policy");
    expect_verify_failure(first_user, first_port);

    check(reapply_and_verify(second_user, second_port),
        "apply creates an independent second account policy");
    check(run_user_port(L"verify", first_user, replacement_port) ==
              static_cast<int>(user_net_lock::ExitCode::success),
        "the first account policy remains valid after applying the second");

    check(run_remove(first_user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove deletes only the first account policy");
    expect_verify_failure(first_user, replacement_port);
    check(run_user_port(L"verify", second_user, second_port) ==
              static_cast<int>(user_net_lock::ExitCode::success),
        "the second account policy remains valid after removing the first");
}

void concurrent_apply_tests(std::wstring_view first_user, std::wstring_view second_user)
{
    check(run_remove(first_user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove prior first-account policy before concurrent apply");
    check(run_remove(second_user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove prior second-account policy before concurrent apply");

    int first_result {};
    int second_result {};
    std::thread first([&] { first_result = run_user_port(L"apply", first_user, first_port); });
    std::thread second([&] { second_result = run_user_port(L"apply", second_user, second_port); });
    first.join();
    second.join();

    check(first_result == static_cast<int>(user_net_lock::ExitCode::success),
        "concurrent apply succeeds for the first account");
    check(second_result == static_cast<int>(user_net_lock::ExitCode::success),
        "concurrent apply succeeds for the second account");
    check(run_user_port(L"verify", first_user, first_port) ==
              static_cast<int>(user_net_lock::ExitCode::success),
        "first account retains shared-infrastructure status access after concurrent apply");
    check(run_user_port(L"verify", second_user, second_port) ==
              static_cast<int>(user_net_lock::ExitCode::success),
        "second account retains shared-infrastructure status access after concurrent apply");
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3)
    {
        std::wcerr << L"Usage: user-net-lock-integration-tests <first-disposable-account> "
                      L"<second-disposable-account>\n";
        return EXIT_FAILURE;
    }
    if (!is_elevated())
    {
        std::wcerr << L"This integration test requires an elevated Administrator "
                      L"session.\n";
        return EXIT_FAILURE;
    }

    const std::wstring_view first_user(argv[1]);
    const std::wstring_view second_user(argv[2]);
    if (first_user == second_user)
    {
        std::wcerr << L"The integration test requires two different disposable "
                      L"accounts.\n";
        return EXIT_FAILURE;
    }
    Cleanup cleanup {first_user, second_user};
    check(run_remove(first_user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove any prior first-account policy");
    check(run_remove(second_user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove any prior second-account policy");

    Engine engine;
    if (!open_engine(engine))
    {
        return EXIT_FAILURE;
    }
    lifecycle_tests(engine.value, first_user);
    if (failures != 0 || !reapply_and_verify(first_user, first_port))
    {
        return EXIT_FAILURE;
    }
    SecurityDescriptor weaker_dacl(weaker_dacl_sddl);
    PACL dacl = weaker_dacl.dacl();
    if (!dacl)
    {
        return EXIT_FAILURE;
    }

    tamper_provider(engine.value, dacl);
    if (!expect_verify_failure(first_user, first_port) ||
        !reapply_and_verify(first_user, first_port))
    {
        return EXIT_FAILURE;
    }

    tamper_sublayer(engine.value, dacl);
    if (!expect_verify_failure(first_user, first_port) ||
        !reapply_and_verify(first_user, first_port))
    {
        return EXIT_FAILURE;
    }

    if (!tamper_filters(engine.value, dacl) || !expect_verify_failure(first_user, first_port) ||
        !reapply_and_verify(first_user, first_port))
    {
        return EXIT_FAILURE;
    }

    check(run_remove(first_user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove first-account DACL test policy");
    idempotence_and_isolation_tests(first_user, second_user);
    concurrent_apply_tests(first_user, second_user);
    check(run_remove(second_user) == static_cast<int>(user_net_lock::ExitCode::success),
        "remove second-account policy");
    if (failures != 0)
    {
        return EXIT_FAILURE;
    }
    std::cout << "WFP integration tests passed\n";
    return EXIT_SUCCESS;
}
