// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project : https: // github.com/fmuecke/WFP-tool.git

#include "wfp_tool.h"

#include "wfp_object_access.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <expected>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <windows.h>
#include <fwpmtypes.h>
#include <fwpmu.h> // requires include of fwmtypes and windows.h first
#include <objbase.h>
#include <sddl.h>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace wfp_tool::detail
{

bool same_access_control_descriptor(PSECURITY_DESCRIPTOR actual, PSECURITY_DESCRIPTOR expected)
{
    if (!actual || !expected || !IsValidSecurityDescriptor(actual) ||
        !IsValidSecurityDescriptor(expected))
    {
        return false;
    }
    BOOL actual_present {};
    BOOL actual_defaulted {};
    PACL actual_dacl {};
    BOOL expected_present {};
    BOOL expected_defaulted {};
    PACL expected_dacl {};
    if (!GetSecurityDescriptorDacl(actual, &actual_present, &actual_dacl, &actual_defaulted) ||
        !GetSecurityDescriptorDacl(
            expected, &expected_present, &expected_dacl, &expected_defaulted) ||
        actual_present != expected_present || actual_defaulted != expected_defaulted ||
        !actual_dacl || !expected_dacl)
    {
        return false;
    }
    return actual_dacl->AclSize == expected_dacl->AclSize &&
           std::memcmp(actual_dacl, expected_dacl, actual_dacl->AclSize) == 0;
}

bool same_wfp_object_access_control_descriptor(
    PSECURITY_DESCRIPTOR actual, PSECURITY_DESCRIPTOR expected)
{
    if (!actual || !expected || !IsValidSecurityDescriptor(actual) ||
        !IsValidSecurityDescriptor(expected))
    {
        return false;
    }
    BOOL actual_present {};
    BOOL actual_defaulted {};
    PACL actual_dacl {};
    BOOL expected_present {};
    BOOL expected_defaulted {};
    PACL expected_dacl {};
    if (!GetSecurityDescriptorDacl(actual, &actual_present, &actual_dacl, &actual_defaulted) ||
        !GetSecurityDescriptorDacl(
            expected, &expected_present, &expected_dacl, &expected_defaulted) ||
        !actual_present || !expected_present || !actual_dacl || !expected_dacl)
    {
        return false;
    }

    std::vector<const ACCESS_ALLOWED_ACE*> expected_aces;
    for (DWORD index = 0; index < expected_dacl->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(expected_dacl, index, &entry))
        {
            return false;
        }
        const auto* header = static_cast<const ACE_HEADER*>(entry);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || (header->AceFlags & INHERITED_ACE) != 0)
        {
            return false;
        }
        expected_aces.push_back(static_cast<const ACCESS_ALLOWED_ACE*>(entry));
    }

    std::vector<const ACCESS_ALLOWED_ACE*> actual_aces;
    for (DWORD index = 0; index < actual_dacl->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(actual_dacl, index, &entry))
        {
            return false;
        }
        const auto* header = static_cast<const ACE_HEADER*>(entry);
        if ((header->AceFlags & INHERITED_ACE) != 0)
        {
            continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
        {
            return false;
        }
        actual_aces.push_back(static_cast<const ACCESS_ALLOWED_ACE*>(entry));
    }
    if (actual_aces.size() != expected_aces.size())
    {
        return false;
    }

    std::vector<bool> matched(actual_aces.size());
    for (const ACCESS_ALLOWED_ACE* expected_ace : expected_aces)
    {
        const PSID expected_sid =
            const_cast<PSID>(static_cast<const void*>(&expected_ace->SidStart));
        DWORD expected_mask = expected_ace->Mask;
        if ((expected_mask & GENERIC_ALL) != 0)
        {
            expected_mask = (expected_mask & ~GENERIC_ALL) | FWPM_GENERIC_ALL;
        }
        bool found {};
        for (std::size_t index = 0; index < actual_aces.size(); ++index)
        {
            const ACCESS_ALLOWED_ACE* actual_ace = actual_aces[index];
            const PSID actual_sid =
                const_cast<PSID>(static_cast<const void*>(&actual_ace->SidStart));
            if (!matched[index] && actual_ace->Mask == expected_mask &&
                EqualSid(actual_sid, expected_sid))
            {
                matched[index] = true;
                found = true;
                break;
            }
        }
        if (!found)
        {
            return false;
        }
    }
    return true;
}

} // namespace wfp_tool::detail

namespace wfp_tool
{
namespace
{

constexpr GUID provider_key {
    0x9b2365a6, 0xf9b9, 0x49f9, {0xab, 0xdb, 0x19, 0x65, 0x79, 0xb1, 0x48, 0x1c}
};
constexpr GUID sublayer_key {
    0x42f667f1, 0x2945, 0x48bd, {0x81, 0x44, 0x0b, 0xd0, 0x21, 0xe6, 0x74, 0x31}
};
constexpr std::uint64_t permit_weight = 0xF000000000000000ULL;
constexpr std::uint64_t block_weight = 0x1000000000000000ULL;
constexpr std::uint16_t sublayer_weight = 0x8000;
constexpr std::array<UINT8, 16> loopback_v6 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
constexpr std::array<UINT8, 16> mapped_loopback_v6 {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1
};
constexpr std::array<UINT8, 16> policy_tag {
    'w', 'f', 'p', '-', 'l', 'o', 'o', 'p', 'b', 'a', 'c', 'k', '-', 'v', '1', 0
};

using LocalMemory = std::unique_ptr<void, decltype(&LocalFree)>;

struct Error
{
    ExitCode exit_code;
    std::uint32_t native_code;
    std::wstring message;
};

template <typename T> using Result = std::expected<T, Error>;

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

    Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Engine& operator=(Engine&& other) noexcept
    {
        if (this != &other)
        {
            if (value)
            {
                FwpmEngineClose0(value);
            }
            value = std::exchange(other.value, nullptr);
        }
        return *this;
    }
};

struct Rule
{
    const GUID* layer;
    FWP_ACTION_TYPE action;
    std::uint64_t weight;
    std::uint8_t protocol;
    std::optional<std::uint32_t> address_v4;
    std::optional<std::array<UINT8, 16>> address_v6;
    std::optional<std::uint16_t> port;
};

struct UserPort
{
    std::wstring user;
    std::uint16_t port;
};

Error error(ExitCode exit_code, std::uint32_t native_code, std::wstring message)
{
    return Error {exit_code, native_code, std::move(message)};
}

std::wstring system_message(DWORD code)
{
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        0,
        reinterpret_cast<wchar_t*>(&buffer),
        0,
        nullptr);
    LocalMemory memory(buffer, LocalFree);
    if (!length)
    {
        return L"error " + std::to_wstring(code);
    }
    std::wstring text(buffer, length);
    while (!text.empty() && std::iswspace(text.back()))
    {
        text.pop_back();
    }
    return text;
}

Error win32_error(ExitCode exit_code, DWORD code, std::wstring_view operation)
{
    return error(exit_code,
        code,
        std::wstring(operation) + L": " + system_message(code) + L" (" + std::to_wstring(code) +
            L")");
}

Result<std::uint16_t> parse_port(std::wstring_view text)
{
    if (text.empty())
    {
        return std::unexpected(error(ExitCode::usage,
            ERROR_INVALID_DATA,
            L"Port must be a decimal value between 1 and 65535"));
    }
    std::uint32_t value {};
    for (const wchar_t character : text)
    {
        if (!std::iswdigit(character))
        {
            return std::unexpected(error(ExitCode::usage,
                ERROR_INVALID_DATA,
                L"Port must be a decimal value between 1 and 65535"));
        }
        value = value * 10 + static_cast<std::uint32_t>(character - L'0');
        if (value > 65535)
        {
            return std::unexpected(error(ExitCode::usage,
                ERROR_INVALID_DATA,
                L"Port must be a decimal value between 1 and 65535"));
        }
    }
    if (value == 0)
    {
        return std::unexpected(error(ExitCode::usage,
            ERROR_INVALID_DATA,
            L"Port must be a decimal value between 1 and 65535"));
    }
    return static_cast<std::uint16_t>(value);
}

Result<bool> is_elevated()
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
        return std::unexpected(
            win32_error(ExitCode::precondition, GetLastError(), L"Create Administrators SID"));
    }
    BOOL member {};
    const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
    const DWORD code = checked ? ERROR_SUCCESS : GetLastError();
    FreeSid(administrators);
    if (!checked)
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, code, L"Check administrator membership"));
    }
    return member != FALSE;
}

Result<void> require_elevation()
{
    auto elevated = is_elevated();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    if (!*elevated)
    {
        return std::unexpected(error(ExitCode::precondition,
            ERROR_ACCESS_DENIED,
            L"wfp-tool must run from an elevated Administrator session"));
    }
    return {};
}

Result<std::vector<std::byte>> resolve_account_sid(std::wstring_view account)
{
    std::wstring name(account);
    DWORD sid_size {};
    DWORD domain_size {};
    SID_NAME_USE use {};
    LookupAccountNameW(nullptr, name.c_str(), nullptr, &sid_size, nullptr, &domain_size, &use);
    const DWORD first_error = GetLastError();
    if (first_error != ERROR_INSUFFICIENT_BUFFER || sid_size == 0)
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, first_error, L"Resolve local account"));
    }
    std::vector<std::byte> sid(sid_size);
    std::wstring domain(domain_size, L'\0');
    if (!LookupAccountNameW(
            nullptr, name.c_str(), sid.data(), &sid_size, domain.data(), &domain_size, &use))
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, GetLastError(), L"Resolve local account"));
    }
    sid.resize(sid_size);
    return sid;
}

Result<std::wstring> sid_string(PSID sid)
{
    LPWSTR text {};
    if (!ConvertSidToStringSidW(sid, &text))
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, GetLastError(), L"Convert SID to text"));
    }
    LocalMemory memory(text, LocalFree);
    return std::wstring(text);
}

Result<std::vector<std::byte>> user_condition_descriptor(PSID sid)
{
    auto text = sid_string(sid);
    if (!text)
    {
        return std::unexpected(text.error());
    }
    PSECURITY_DESCRIPTOR descriptor {};
    // This descriptor is the FWPM_CONDITION_ALE_USER_ID match value, not the
    // WFP object's management ACL. It binds each filter to the selected account
    // SID so another user's traffic cannot satisfy the rule.
    const std::wstring sddl = L"D:(A;;CC;;;" + *text + L")";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, GetLastError(), L"Build target-user condition"));
    }
    LocalMemory memory(descriptor, LocalFree);
    const DWORD size = GetSecurityDescriptorLength(descriptor);
    std::vector<std::byte> result(size);
    std::memcpy(result.data(), descriptor, size);
    return result;
}

Result<std::vector<std::byte>> wfp_object_descriptor()
{
    PSECURITY_DESCRIPTOR descriptor {};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            detail::expected_wfp_object_dacl_sddl, SDDL_REVISION_1, &descriptor, nullptr))
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, GetLastError(), L"Build WFP object access control"));
    }
    LocalMemory memory(descriptor, LocalFree);
    const DWORD size = GetSecurityDescriptorLength(descriptor);
    std::vector<std::byte> result(size);
    std::memcpy(result.data(), descriptor, size);
    return result;
}

Result<PACL> wfp_object_dacl(const std::vector<std::byte>& descriptor)
{
    if (descriptor.empty())
    {
        return std::unexpected(
            error(ExitCode::wfp, ERROR_INVALID_DATA, L"WFP object access control is empty"));
    }
    BOOL present {};
    BOOL defaulted {};
    PACL dacl {};
    const auto security_descriptor =
        reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(descriptor.data()));
    if (!GetSecurityDescriptorDacl(security_descriptor, &present, &dacl, &defaulted) || !present ||
        !dacl)
    {
        return std::unexpected(
            error(ExitCode::wfp, ERROR_INVALID_DATA, L"WFP object access control has no DACL"));
    }
    return dacl;
}

Result<Engine> open_engine(ExitCode exit_code = ExitCode::wfp)
{
    Engine engine;
    const DWORD code = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine.value);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(exit_code, code, L"Open WFP engine"));
    }
    return engine;
}

std::vector<UINT8> policy_identity(PSID sid)
{
    const auto size = GetLengthSid(sid);
    std::vector<UINT8> identity(policy_tag.begin(), policy_tag.end());
    const auto* sid_bytes = static_cast<const UINT8*>(sid);
    identity.insert(identity.end(), sid_bytes, sid_bytes + size);
    return identity;
}

std::vector<UINT8> policy_data(const std::vector<UINT8>& identity, std::uint16_t port)
{
    std::vector<UINT8> data = identity;
    const auto* port_bytes = reinterpret_cast<const UINT8*>(&port);
    data.insert(data.end(), port_bytes, port_bytes + sizeof(port));
    return data;
}

bool same_blob(const FWP_BYTE_BLOB& blob, const std::vector<UINT8>& expected)
{
    return blob.size == expected.size() && blob.data &&
           std::memcmp(blob.data, expected.data(), expected.size()) == 0;
}

bool is_owned_for(const FWPM_FILTER0& filter, const std::vector<UINT8>& identity)
{
    return filter.providerKey && IsEqualGUID(*filter.providerKey, provider_key) &&
           IsEqualGUID(filter.subLayerKey, sublayer_key) && filter.providerData.data &&
           filter.providerData.size == identity.size() + sizeof(std::uint16_t) &&
           std::memcmp(filter.providerData.data, identity.data(), identity.size()) == 0;
}

const FWPM_FILTER_CONDITION0* find_condition(const FWPM_FILTER0& filter, const GUID& field)
{
    for (UINT32 index = 0; index < filter.numFilterConditions; ++index)
    {
        if (IsEqualGUID(filter.filterCondition[index].fieldKey, field))
        {
            return &filter.filterCondition[index];
        }
    }
    return nullptr;
}

bool same_user_descriptor(const FWP_BYTE_BLOB* actual, const std::vector<std::byte>& expected)
{
    return actual && actual->data &&
           detail::same_access_control_descriptor(
               reinterpret_cast<PSECURITY_DESCRIPTOR>(actual->data),
               reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(expected.data())));
}

std::wstring descriptor_dacl_sddl(PSECURITY_DESCRIPTOR descriptor)
{
    LPWSTR text {};
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text, nullptr))
    {
        return L"<unavailable>";
    }
    LocalMemory memory(text, LocalFree);
    return text;
}

Result<void> verify_provider_access(HANDLE engine, const std::vector<std::byte>& expected)
{
    PSECURITY_DESCRIPTOR actual {};
    const DWORD code = FwpmProviderGetSecurityInfoByKey0(engine,
        &provider_key,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &actual);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, code, L"Read wfp-tool provider access control"));
    }
    const bool matches = detail::same_wfp_object_access_control_descriptor(
        actual, reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(expected.data())));
    const std::wstring actual_sddl = matches ? L"" : descriptor_dacl_sddl(actual);
    FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    if (!matches)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-tool provider access control does not match: " + actual_sddl));
    }
    return {};
}

Result<void> verify_sublayer_access(HANDLE engine, const std::vector<std::byte>& expected)
{
    PSECURITY_DESCRIPTOR actual {};
    const DWORD code = FwpmSubLayerGetSecurityInfoByKey0(engine,
        &sublayer_key,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &actual);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, code, L"Read wfp-tool sublayer access control"));
    }
    const bool matches = detail::same_wfp_object_access_control_descriptor(
        actual, reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(expected.data())));
    FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    if (!matches)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-tool sublayer access control does not match"));
    }
    return {};
}

Result<void> verify_filter_access(
    HANDLE engine, const GUID& key, const std::vector<std::byte>& expected)
{
    PSECURITY_DESCRIPTOR actual {};
    const DWORD code = FwpmFilterGetSecurityInfoByKey0(
        engine, &key, DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &actual);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, code, L"Read wfp-tool filter access control"));
    }
    const bool matches = detail::same_wfp_object_access_control_descriptor(
        actual, reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(expected.data())));
    FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    if (!matches)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-tool filter access control does not match"));
    }
    return {};
}

bool has_expected_provider_properties(const FWPM_PROVIDER0& provider)
{
    return provider.flags == FWPM_PROVIDER_FLAG_PERSISTENT;
}

bool has_expected_sublayer_properties(const FWPM_SUBLAYER0& sublayer)
{
    return sublayer.flags == FWPM_SUBLAYER_FLAG_PERSISTENT && sublayer.providerKey &&
           IsEqualGUID(*sublayer.providerKey, provider_key) && sublayer.weight >= sublayer_weight;
}

Error unexpected_sublayer_properties(ExitCode exit_code, const FWPM_SUBLAYER0& sublayer)
{
    const bool persistent = sublayer.flags == FWPM_SUBLAYER_FLAG_PERSISTENT;
    const bool expected_provider =
        sublayer.providerKey && IsEqualGUID(*sublayer.providerKey, provider_key);
    const bool minimum_weight = sublayer.weight >= sublayer_weight;
    return error(exit_code,
        ERROR_INVALID_DATA,
        L"wfp-tool sublayer does not match the policy (persistent=" + std::to_wstring(persistent) +
            L", expected-provider=" + std::to_wstring(expected_provider) + L", minimum-weight=" +
            std::to_wstring(minimum_weight) + L", weight=" + std::to_wstring(sublayer.weight) +
            L")");
}

bool matches_user(const FWPM_FILTER0& filter, const std::vector<std::byte>& user_sd)
{
    const auto* user = find_condition(filter, FWPM_CONDITION_ALE_USER_ID);
    return user && user->matchType == FWP_MATCH_EQUAL &&
           user->conditionValue.type == FWP_SECURITY_DESCRIPTOR_TYPE &&
           same_user_descriptor(user->conditionValue.sd, user_sd);
}

Result<void> enumerate_filters(
    HANDLE engine, const std::function<Result<void>(const FWPM_FILTER0&)>& visitor)
{
    HANDLE enumeration {};
    DWORD code = FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration);
    if (code == FWP_E_NEVER_MATCH)
    {
        return {};
    }
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Create WFP filter enumeration"));
    }
    const auto close = [&] { FwpmFilterDestroyEnumHandle0(engine, enumeration); };
    for (;;)
    {
        FWPM_FILTER0** filters {};
        UINT32 count {};
        code = FwpmFilterEnum0(engine, enumeration, 64, &filters, &count);
        if (code != ERROR_SUCCESS)
        {
            close();
            return std::unexpected(win32_error(ExitCode::wfp, code, L"Enumerate WFP filters"));
        }
        for (UINT32 index = 0; index < count; ++index)
        {
            auto result = visitor(*filters[index]);
            if (!result)
            {
                FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
                close();
                return std::unexpected(result.error());
            }
        }
        FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        if (count == 0)
        {
            break;
        }
    }
    close();
    return {};
}

Result<void> ensure_infrastructure(HANDLE engine, const std::vector<std::byte>& object_descriptor)
{
    auto dacl = wfp_object_dacl(object_descriptor);
    if (!dacl)
    {
        return std::unexpected(dacl.error());
    }
    FWPM_PROVIDER0* provider {};
    DWORD code = FwpmProviderGetByKey0(engine, &provider_key, &provider);
    if (code == ERROR_SUCCESS)
    {
        const bool properties_match = has_expected_provider_properties(*provider);
        FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
        if (!properties_match)
        {
            return std::unexpected(error(ExitCode::wfp,
                ERROR_INVALID_DATA,
                L"Existing wfp-tool provider does not match the policy"));
        }
        code = FwpmProviderSetSecurityInfoByKey0(
            engine, &provider_key, DACL_SECURITY_INFORMATION, nullptr, nullptr, *dacl, nullptr);
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(
                win32_error(ExitCode::wfp, code, L"Restore wfp-tool provider access control"));
        }
    }
    else if (code == FWP_E_PROVIDER_NOT_FOUND)
    {
        FWPM_PROVIDER0 new_provider {};
        new_provider.providerKey = provider_key;
        new_provider.displayData.name = const_cast<wchar_t*>(L"wfp-tool Provider");
        new_provider.displayData.description =
            const_cast<wchar_t*>(L"Persistent per-user loopback-only filters");
        new_provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        code = FwpmProviderAdd0(engine,
            &new_provider,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(
                const_cast<std::byte*>(object_descriptor.data())));
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(win32_error(ExitCode::wfp, code, L"Add wfp-tool provider"));
        }
    }
    else
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Read wfp-tool provider"));
    }

    FWPM_SUBLAYER0* sublayer {};
    code = FwpmSubLayerGetByKey0(engine, &sublayer_key, &sublayer);
    if (code == ERROR_SUCCESS)
    {
        const bool properties_match = has_expected_sublayer_properties(*sublayer);
        if (!properties_match)
        {
            const Error mismatch = unexpected_sublayer_properties(ExitCode::wfp, *sublayer);
            FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
            return std::unexpected(mismatch);
        }
        FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
        code = FwpmSubLayerSetSecurityInfoByKey0(
            engine, &sublayer_key, DACL_SECURITY_INFORMATION, nullptr, nullptr, *dacl, nullptr);
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(
                win32_error(ExitCode::wfp, code, L"Restore wfp-tool sublayer access control"));
        }
        return {};
    }
    if (code != FWP_E_SUBLAYER_NOT_FOUND)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Read wfp-tool sublayer"));
    }

    FWPM_SUBLAYER0 new_sublayer {};
    new_sublayer.subLayerKey = sublayer_key;
    new_sublayer.displayData.name = const_cast<wchar_t*>(L"wfp-tool Sublayer");
    new_sublayer.displayData.description =
        const_cast<wchar_t*>(L"Per-user loopback permits above default-deny blocks");
    new_sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    new_sublayer.providerKey = const_cast<GUID*>(&provider_key);
    new_sublayer.weight = sublayer_weight;
    code = FwpmSubLayerAdd0(engine,
        &new_sublayer,
        reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(object_descriptor.data())));
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Add wfp-tool sublayer"));
    }
    return {};
}

std::vector<Rule> build_rules(std::uint16_t port)
{
    std::vector<Rule> rules;
    const auto permit = [&](const GUID& layer,
                            std::optional<std::uint32_t>
                                address_v4,
                            std::optional<std::array<UINT8, 16>>
                                address_v6)
    {
        rules.push_back(Rule {
            &layer,
            FWP_ACTION_PERMIT,
            permit_weight,
            static_cast<std::uint8_t>(IPPROTO_TCP),
            address_v4,
            address_v6,
            port
        });
    };
    permit(FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x7f000001, std::nullopt);
    permit(FWPM_LAYER_ALE_AUTH_CONNECT_V6, std::nullopt, loopback_v6);
    permit(FWPM_LAYER_ALE_AUTH_CONNECT_V6, std::nullopt, mapped_loopback_v6);

    for (const GUID* layer : {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6})
    {
        for (const std::uint8_t protocol :
            {static_cast<std::uint8_t>(IPPROTO_TCP), static_cast<std::uint8_t>(IPPROTO_UDP)})
        {
            rules.push_back(Rule {
                layer,
                FWP_ACTION_BLOCK,
                block_weight,
                protocol,
                std::nullopt,
                std::nullopt,
                std::nullopt
            });
        }
    }
    return rules;
}

Result<void> add_rule(HANDLE engine, const Rule& rule, FWP_BYTE_BLOB& user_descriptor,
    const std::vector<UINT8>& data, PSECURITY_DESCRIPTOR object_descriptor)
{
    std::array<FWPM_FILTER_CONDITION0, 4> conditions {};
    UINT32 count {};
    conditions[count].fieldKey = FWPM_CONDITION_ALE_USER_ID;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
    conditions[count].conditionValue.sd = &user_descriptor;
    ++count;

    conditions[count].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_UINT8;
    conditions[count].conditionValue.uint8 = rule.protocol;
    ++count;

    FWP_BYTE_ARRAY16 address_v6 {};
    if (rule.address_v4)
    {
        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_UINT32;
        conditions[count].conditionValue.uint32 = *rule.address_v4;
        ++count;
    }
    else if (rule.address_v6)
    {
        std::memcpy(
            address_v6.byteArray16, rule.address_v6->data(), sizeof(address_v6.byteArray16));
        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        conditions[count].conditionValue.byteArray16 = &address_v6;
        ++count;
    }
    if (rule.port)
    {
        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_UINT16;
        conditions[count].conditionValue.uint16 = *rule.port;
        ++count;
    }

    FWP_VALUE0 weight {};
    weight.type = FWP_UINT64;
    weight.uint64 = const_cast<UINT64*>(&rule.weight);
    FWP_BYTE_BLOB provider_data {static_cast<UINT32>(data.size()), const_cast<UINT8*>(data.data())};
    FWPM_FILTER0 filter {};
    filter.displayData.name = const_cast<wchar_t*>(L"wfp-tool loopback rule");
    filter.displayData.description =
        const_cast<wchar_t*>(L"Per-user loopback proxy permit or default-deny rule");
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.providerKey = const_cast<GUID*>(&provider_key);
    filter.providerData = provider_data;
    filter.layerKey = *rule.layer;
    filter.subLayerKey = sublayer_key;
    filter.weight = weight;
    filter.numFilterConditions = count;
    filter.filterCondition = conditions.data();
    filter.action.type = rule.action;
    const DWORD code = FwpmFilterAdd0(engine, &filter, object_descriptor, nullptr);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Add wfp-tool filter"));
    }
    return {};
}

Result<void> delete_user_filters(HANDLE engine, const std::vector<UINT8>& identity)
{
    std::vector<GUID> keys;
    auto enumerated = enumerate_filters(engine,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (is_owned_for(filter, identity))
            {
                keys.push_back(filter.filterKey);
            }
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    for (const GUID& key : keys)
    {
        const DWORD code = FwpmFilterDeleteByKey0(engine, &key);
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(win32_error(ExitCode::wfp, code, L"Delete wfp-tool filter"));
        }
    }
    return {};
}

Result<void> remove_unused_infrastructure(HANDLE engine)
{
    bool referenced {};
    auto enumerated = enumerate_filters(engine,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            referenced = referenced || IsEqualGUID(filter.subLayerKey, sublayer_key) ||
                         (filter.providerKey && IsEqualGUID(*filter.providerKey, provider_key));
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    if (referenced)
    {
        return {};
    }
    DWORD code = FwpmSubLayerDeleteByKey0(engine, &sublayer_key);
    if (code != ERROR_SUCCESS && code != FWP_E_SUBLAYER_NOT_FOUND)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, code, L"Remove unused wfp-tool sublayer"));
    }
    code = FwpmProviderDeleteByKey0(engine, &provider_key);
    if (code != ERROR_SUCCESS && code != FWP_E_PROVIDER_NOT_FOUND)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, code, L"Remove unused wfp-tool provider"));
    }
    return {};
}

Result<void> clear_user_policy(PSID sid)
{
    auto engine = open_engine();
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    const DWORD begin = FwpmTransactionBegin0(engine->value, 0);
    if (begin != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, begin, L"Begin wfp-tool removal transaction"));
    }
    const auto identity = policy_identity(sid);
    auto deleted = delete_user_filters(engine->value, identity);
    if (!deleted)
    {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(deleted.error());
    }
    auto removed = remove_unused_infrastructure(engine->value);
    if (!removed)
    {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(removed.error());
    }
    const DWORD commit = FwpmTransactionCommit0(engine->value);
    if (commit != ERROR_SUCCESS)
    {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(
            win32_error(ExitCode::wfp, commit, L"Commit wfp-tool removal transaction"));
    }
    return {};
}

bool matches_rule(const FWPM_FILTER0& filter, const Rule& expected, const std::vector<UINT8>& data,
    const std::vector<std::byte>& user_sd)
{
    const UINT32 expected_conditions =
        2 + (expected.address_v4 || expected.address_v6 ? 1 : 0) + (expected.port ? 1 : 0);
    if (!filter.providerKey || !IsEqualGUID(*filter.providerKey, provider_key) ||
        !IsEqualGUID(filter.subLayerKey, sublayer_key) ||
        !IsEqualGUID(filter.layerKey, *expected.layer) ||
        filter.flags != FWPM_FILTER_FLAG_PERSISTENT || filter.action.type != expected.action ||
        filter.weight.type != FWP_UINT64 || !filter.weight.uint64 ||
        *filter.weight.uint64 != expected.weight ||
        filter.numFilterConditions != expected_conditions ||
        !same_blob(filter.providerData, data) || !matches_user(filter, user_sd))
    {
        return false;
    }
    const auto* protocol = find_condition(filter, FWPM_CONDITION_IP_PROTOCOL);
    if (!protocol || protocol->matchType != FWP_MATCH_EQUAL ||
        protocol->conditionValue.type != FWP_UINT8 ||
        protocol->conditionValue.uint8 != expected.protocol)
    {
        return false;
    }
    if (expected.address_v4 || expected.address_v6)
    {
        const auto* address = find_condition(filter, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        if (!address || address->matchType != FWP_MATCH_EQUAL)
        {
            return false;
        }
        if (expected.address_v4 && (address->conditionValue.type != FWP_UINT32 ||
                                       address->conditionValue.uint32 != *expected.address_v4))
        {
            return false;
        }
        if (expected.address_v6 && (address->conditionValue.type != FWP_BYTE_ARRAY16_TYPE ||
                                       !address->conditionValue.byteArray16 ||
                                       std::memcmp(address->conditionValue.byteArray16->byteArray16,
                                           expected.address_v6->data(),
                                           16) != 0))
        {
            return false;
        }
    }
    if (expected.port)
    {
        const auto* port = find_condition(filter, FWPM_CONDITION_IP_REMOTE_PORT);
        if (!port || port->matchType != FWP_MATCH_EQUAL ||
            port->conditionValue.type != FWP_UINT16 ||
            port->conditionValue.uint16 != *expected.port)
        {
            return false;
        }
    }
    return true;
}

Result<void> verify_loopback_policy(PSID sid, std::uint16_t port)
{
    auto engine = open_engine(ExitCode::verification);
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    FWPM_PROVIDER0* provider {};
    const DWORD provider_result = FwpmProviderGetByKey0(engine->value, &provider_key, &provider);
    if (provider_result != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, provider_result, L"Read wfp-tool provider"));
    }
    const bool provider_properties_match = has_expected_provider_properties(*provider);
    FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
    if (!provider_properties_match)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-tool provider does not match the policy"));
    }
    FWPM_SUBLAYER0* sublayer {};
    const DWORD sublayer_result = FwpmSubLayerGetByKey0(engine->value, &sublayer_key, &sublayer);
    if (sublayer_result != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, sublayer_result, L"Read wfp-tool sublayer"));
    }
    const bool sublayer_properties_match = has_expected_sublayer_properties(*sublayer);
    if (!sublayer_properties_match)
    {
        const Error mismatch = unexpected_sublayer_properties(ExitCode::verification, *sublayer);
        FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
        return std::unexpected(mismatch);
    }
    FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));

    auto user_sd = user_condition_descriptor(sid);
    if (!user_sd)
    {
        return std::unexpected(user_sd.error());
    }
    auto object_sd = wfp_object_descriptor();
    if (!object_sd)
    {
        return std::unexpected(object_sd.error());
    }
    auto provider_access = verify_provider_access(engine->value, *object_sd);
    if (!provider_access)
    {
        return std::unexpected(provider_access.error());
    }
    auto sublayer_access = verify_sublayer_access(engine->value, *object_sd);
    if (!sublayer_access)
    {
        return std::unexpected(sublayer_access.error());
    }
    const auto identity = policy_identity(sid);
    const auto data = policy_data(identity, port);
    const auto expected = build_rules(port);
    std::vector<bool> matched(expected.size());
    std::size_t found {};
    auto enumerated = enumerate_filters(engine->value,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (!is_owned_for(filter, identity))
            {
                return {};
            }
            ++found;
            for (std::size_t index = 0; index < expected.size(); ++index)
            {
                if (!matched[index] && matches_rule(filter, expected[index], data, *user_sd))
                {
                    auto filter_access =
                        verify_filter_access(engine->value, filter.filterKey, *object_sd);
                    if (!filter_access)
                    {
                        return std::unexpected(filter_access.error());
                    }
                    matched[index] = true;
                    return {};
                }
            }
            return std::unexpected(error(ExitCode::verification,
                ERROR_INVALID_DATA,
                L"Installed loopback policy contains an unexpected filter"));
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    if (found != expected.size() ||
        std::find(matched.begin(), matched.end(), false) != matched.end())
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"Installed loopback filters do not match the "
            L"requested user and port"));
    }
    return {};
}

Result<void> apply_loopback_policy(PSID sid, std::uint16_t port)
{
    auto engine = open_engine();
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    auto user_sd = user_condition_descriptor(sid);
    if (!user_sd)
    {
        return std::unexpected(user_sd.error());
    }
    auto object_sd = wfp_object_descriptor();
    if (!object_sd)
    {
        return std::unexpected(object_sd.error());
    }
    auto infrastructure = ensure_infrastructure(engine->value, *object_sd);
    if (!infrastructure)
    {
        return std::unexpected(infrastructure.error());
    }
    const DWORD begin = FwpmTransactionBegin0(engine->value, 0);
    if (begin != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, begin, L"Begin wfp-tool transaction"));
    }
    bool active = true;
    const auto abort = [&]
    {
        if (active)
        {
            FwpmTransactionAbort0(engine->value);
            active = false;
        }
    };
    const auto identity = policy_identity(sid);
    auto deleted = delete_user_filters(engine->value, identity);
    if (!deleted)
    {
        abort();
        return std::unexpected(deleted.error());
    }
    FWP_BYTE_BLOB user_blob {
        static_cast<UINT32>(user_sd->size()), reinterpret_cast<UINT8*>(user_sd->data())
    };
    const auto data = policy_data(identity, port);
    for (const Rule& rule : build_rules(port))
    {
        auto added = add_rule(engine->value,
            rule,
            user_blob,
            data,
            static_cast<PSECURITY_DESCRIPTOR>(object_sd->data()));
        if (!added)
        {
            abort();
            return std::unexpected(added.error());
        }
    }
    const DWORD commit = FwpmTransactionCommit0(engine->value);
    if (commit != ERROR_SUCCESS)
    {
        abort();
        return std::unexpected(win32_error(ExitCode::wfp, commit, L"Commit wfp-tool transaction"));
    }
    active = false;
    return {};
}

std::wstring address_text(const FWPM_FILTER_CONDITION0* address)
{
    if (!address)
    {
        return L"*";
    }
    wchar_t buffer[INET6_ADDRSTRLEN] {};
    if (address->conditionValue.type == FWP_UINT32)
    {
        const std::uint32_t network_address = htonl(address->conditionValue.uint32);
        std::array<UINT8, 4> bytes {};
        std::memcpy(bytes.data(), &network_address, sizeof(network_address));
        if (InetNtopW(AF_INET, bytes.data(), buffer, std::size(buffer)))
        {
            return buffer;
        }
    }
    else if (address->conditionValue.type == FWP_BYTE_ARRAY16_TYPE &&
             address->conditionValue.byteArray16 &&
             InetNtopW(AF_INET6,
                 address->conditionValue.byteArray16->byteArray16,
                 buffer,
                 std::size(buffer)))
    {
        return L"[" + std::wstring(buffer) + L"]";
    }
    return L"<invalid address>";
}

std::wstring protocol_text(const FWPM_FILTER_CONDITION0* protocol)
{
    if (!protocol || protocol->conditionValue.type != FWP_UINT8)
    {
        return L"<invalid protocol>";
    }
    if (protocol->conditionValue.uint8 == IPPROTO_TCP)
    {
        return L"tcp";
    }
    if (protocol->conditionValue.uint8 == IPPROTO_UDP)
    {
        return L"udp";
    }
    return L"<other protocol>";
}

Result<void> apply_command(std::wstring_view user, std::uint16_t port)
{
    auto elevated = require_elevation();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    auto applied = apply_loopback_policy(sid->data(), port);
    if (!applied)
    {
        return std::unexpected(applied.error());
    }
    return verify_loopback_policy(sid->data(), port);
}

Result<void> verify_command(std::wstring_view user, std::uint16_t port)
{
    auto elevated = require_elevation();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    return verify_loopback_policy(sid->data(), port);
}

Result<void> remove_command(std::wstring_view user)
{
    auto elevated = require_elevation();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    return clear_user_policy(sid->data());
}

Result<void> list_command(std::wstring_view user)
{
    auto elevated = require_elevation();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    auto text = sid_string(sid->data());
    if (!text)
    {
        return std::unexpected(text.error());
    }
    auto engine = open_engine();
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    const auto identity = policy_identity(sid->data());
    std::wcout << L"wfp-tool loopback filters for " << *text << L":\n";
    std::size_t count {};
    auto enumerated = enumerate_filters(engine->value,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (!is_owned_for(filter, identity))
            {
                return {};
            }
            ++count;
            const auto* protocol = find_condition(filter, FWPM_CONDITION_IP_PROTOCOL);
            const auto* address = find_condition(filter, FWPM_CONDITION_IP_REMOTE_ADDRESS);
            const auto* port = find_condition(filter, FWPM_CONDITION_IP_REMOTE_PORT);
            const wchar_t* layer = IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4)
                                       ? L"ALE_AUTH_CONNECT_V4"
                                       : L"ALE_AUTH_CONNECT_V6";
            std::wcout << L"[" << filter.filterId << L"] "
                       << (filter.action.type == FWP_ACTION_PERMIT ? L"permit " : L"block ")
                       << protocol_text(protocol) << L" " << address_text(address);
            if (port && port->conditionValue.type == FWP_UINT16)
            {
                std::wcout << L":" << port->conditionValue.uint16;
            }
            std::wcout << L" at " << layer << L"\n";
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    if (count == 0)
    {
        std::wcout << L"(none)\n";
    }
    return {};
}

Result<UserPort> parse_user_port(std::span<const std::wstring_view> arguments)
{
    if (arguments.size() != 5 || arguments[1] != L"--user" || arguments[3] != L"--port" ||
        arguments[2].empty())
    {
        return std::unexpected(error(
            ExitCode::usage, ERROR_INVALID_PARAMETER, L"Expected --user <account> --port <port>"));
    }
    auto port = parse_port(arguments[4]);
    if (!port)
    {
        return std::unexpected(port.error());
    }
    return UserPort {std::wstring(arguments[2]), *port};
}

void print_usage()
{
    std::wcerr << L"Usage:\n"
               << L"  wfp-tool apply --user <account> --port <port>\n"
               << L"  wfp-tool verify --user <account> --port <port>\n"
               << L"  wfp-tool remove --user <account>\n"
               << L"  wfp-tool list --user <account>\n";
}

int finish(Result<void> result, std::wstring_view success_message)
{
    if (!result)
    {
        std::wcerr << L"Error: " << result.error().message << L'\n';
        return static_cast<int>(result.error().exit_code);
    }
    std::wcout << success_message << L'\n';
    return static_cast<int>(ExitCode::success);
}

} // namespace

int run(std::span<const std::wstring_view> arguments)
{
    if (arguments.empty())
    {
        print_usage();
        return static_cast<int>(ExitCode::usage);
    }
    if (arguments[0] == L"apply" || arguments[0] == L"verify")
    {
        auto input = parse_user_port(arguments);
        if (!input)
        {
            print_usage();
            return static_cast<int>(input.error().exit_code);
        }
        if (arguments[0] == L"apply")
        {
            return finish(apply_command(input->user, input->port),
                L"wfp-tool loopback policy applied and verified.");
        }
        return finish(verify_command(input->user, input->port),
            L"wfp-tool loopback policy matches the requested user and port.");
    }
    if (arguments[0] == L"remove" || arguments[0] == L"list")
    {
        if (arguments.size() != 3 || arguments[1] != L"--user" || arguments[2].empty())
        {
            print_usage();
            return static_cast<int>(ExitCode::usage);
        }
        if (arguments[0] == L"remove")
        {
            return finish(remove_command(arguments[2]), L"wfp-tool loopback policy removed.");
        }
        return finish(list_command(arguments[2]), L"wfp-tool filters listed.");
    }
    print_usage();
    return static_cast<int>(ExitCode::usage);
}

} // namespace wfp_tool
