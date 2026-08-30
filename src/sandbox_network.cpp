#include "sandbox_network.h"

#include <fwpmu.h>
#include <objbase.h>
#include <sddl.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <system_error>
#include <utility>

namespace sandbox_network {
namespace {

constexpr GUID provider_key{0x9b2365a6,
                            0xf9b9,
                            0x49f9,
                            {0xab, 0xdb, 0x19, 0x65, 0x79, 0xb1, 0x48, 0x1c}};
constexpr GUID sublayer_key{0x42f667f1,
                            0x2945,
                            0x48bd,
                            {0x81, 0x44, 0x0b, 0xd0, 0x21, 0xe6, 0x74, 0x31}};

constexpr std::uint64_t permit_weight = 0xF000000000000000ULL;
constexpr std::uint64_t block_weight = 0x1000000000000000ULL;
constexpr std::uint16_t sublayer_weight = 0x8000;
constexpr std::array<UINT8, 8> policy_tag_prefix{'w', 'f', 'p', 't',
                                                 'o', 'o', 'l', '1'};

using LocalMemory = std::unique_ptr<void, decltype(&LocalFree)>;

struct Engine {
  HANDLE value{};
  ~Engine() {
    if (value) {
      FwpmEngineClose0(value);
    }
  }
  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;
  Engine() = default;
  Engine(Engine &&other) noexcept
      : value(std::exchange(other.value, nullptr)) {}
  Engine &operator=(Engine &&other) noexcept {
    if (this != &other) {
      if (value) {
        FwpmEngineClose0(value);
      }
      value = std::exchange(other.value, nullptr);
    }
    return *this;
  }
};

struct Rule {
  const GUID *layer;
  FWP_ACTION_TYPE action;
  std::uint64_t weight;
  std::optional<std::uint8_t> protocol;
  std::optional<std::uint32_t> address_v4;
  std::optional<std::array<UINT8, 16>> address_v6;
  std::optional<std::uint16_t> port;
};

Error error(ExitCode exit_code, std::uint32_t native_code,
            std::wstring message) {
  return Error{exit_code, native_code, std::move(message)};
}

std::wstring system_message(DWORD code) {
  wchar_t *buffer = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, 0, reinterpret_cast<wchar_t *>(&buffer), 0, nullptr);
  LocalMemory memory(buffer, LocalFree);
  if (!length) {
    return L"error " + std::to_wstring(code);
  }
  std::wstring text(buffer, length);
  while (!text.empty() && std::iswspace(text.back())) {
    text.pop_back();
  }
  return text;
}

Error win32_error(ExitCode exit_code, DWORD code, std::wstring_view operation) {
  return error(exit_code, code,
               std::wstring(operation) + L": " + system_message(code) + L" (" +
                   std::to_wstring(code) + L")");
}

std::string_view trim(std::string_view text) {
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.front()))) {
    text.remove_prefix(1);
  }
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.back()))) {
    text.remove_suffix(1);
  }
  return text;
}

std::string ascii_lower(std::string_view text) {
  std::string result(text);
  for (char &c : result) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return result;
}

Result<std::wstring> utf8_to_wide(std::string_view text) {
  if (text.empty()) {
    return std::wstring{};
  }
  const int length =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                          static_cast<int>(text.size()), nullptr, 0);
  if (!length) {
    return std::unexpected(win32_error(ExitCode::usage_or_config,
                                       GetLastError(), L"Decode UTF-8"));
  }
  std::wstring result(static_cast<std::size_t>(length), L'\0');
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                           static_cast<int>(text.size()), result.data(),
                           length)) {
    return std::unexpected(win32_error(ExitCode::usage_or_config,
                                       GetLastError(), L"Decode UTF-8"));
  }
  return result;
}

Result<std::uint16_t> parse_port(std::string_view text) {
  unsigned value{};
  const auto [end, status] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (status != std::errc{} || end != text.data() + text.size() || value == 0 ||
      value > 65535) {
    return std::unexpected(
        error(ExitCode::usage_or_config, ERROR_INVALID_DATA,
              L"Ports must be decimal values between 1 and 65535"));
  }
  return static_cast<std::uint16_t>(value);
}

Result<std::uint32_t> parse_version(std::string_view text) {
  std::uint32_t value{};
  const auto [end, status] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (status != std::errc{} || end != text.data() + text.size() || value == 0) {
    return std::unexpected(
        error(ExitCode::usage_or_config, ERROR_INVALID_DATA,
              L"policy_version must be a non-zero unsigned integer"));
  }
  return value;
}

bool is_v4_mapped(const std::array<UINT8, 16> &address) {
  return std::all_of(address.begin(), address.begin() + 10,
                     [](UINT8 value) { return value == 0; }) &&
         address[10] == 0xff && address[11] == 0xff;
}

Result<Config::Endpoint> parse_endpoint(std::string_view endpoint_text,
                                        std::string_view protocols_text) {
  Config::Endpoint endpoint{};
  endpoint_text = trim(endpoint_text);
  const std::string protocols = ascii_lower(trim(protocols_text));
  std::size_t protocol_start = 0;
  while (protocol_start <= protocols.size()) {
    const std::size_t comma = protocols.find(',', protocol_start);
    const std::string_view protocol = trim(std::string_view(protocols).substr(
        protocol_start, comma == std::string::npos ? std::string::npos
                                                   : comma - protocol_start));
    if (protocol == "tcp" && !endpoint.tcp) {
      endpoint.tcp = true;
    } else if (protocol == "udp" && !endpoint.udp) {
      endpoint.udp = true;
    } else {
      return std::unexpected(error(ExitCode::usage_or_config,
                                   ERROR_INVALID_DATA,
                                   L"[wfp-allow] values must be tcp, udp, or "
                                   L"tcp,udp without duplicates"));
    }
    if (comma == std::string::npos) {
      break;
    }
    protocol_start = comma + 1;
  }
  if (!endpoint.tcp && !endpoint.udp) {
    return std::unexpected(error(ExitCode::usage_or_config, ERROR_INVALID_DATA,
                                 L"[wfp-allow] must enable TCP, UDP, or both"));
  }

  std::string_view address_text;
  std::string_view port_text;
  if (endpoint_text.starts_with('[')) {
    const std::size_t close = endpoint_text.find(']');
    if (close == std::string::npos || close + 2 > endpoint_text.size() ||
        endpoint_text[close + 1] != ':') {
      return std::unexpected(error(ExitCode::usage_or_config,
                                   ERROR_INVALID_DATA,
                                   L"IPv6 endpoints must use [address]:port"));
    }
    address_text = endpoint_text.substr(1, close - 1);
    port_text = endpoint_text.substr(close + 2);
    endpoint.ipv6 = true;
  } else {
    const std::size_t colon = endpoint_text.rfind(':');
    if (colon == std::string::npos || endpoint_text.find(':') != colon) {
      return std::unexpected(error(ExitCode::usage_or_config,
                                   ERROR_INVALID_DATA,
                                   L"IPv4 endpoints must use address:port"));
    }
    address_text = endpoint_text.substr(0, colon);
    port_text = endpoint_text.substr(colon + 1);
  }
  auto port = parse_port(port_text);
  if (!port) {
    return std::unexpected(port.error());
  }
  auto address_wide = utf8_to_wide(address_text);
  if (!address_wide || address_wide->empty()) {
    return std::unexpected(address_wide ? error(ExitCode::usage_or_config,
                                                ERROR_INVALID_ADDRESS,
                                                L"Endpoint address is empty")
                                        : address_wide.error());
  }
  const int family = endpoint.ipv6 ? AF_INET6 : AF_INET;
  const int parsed =
      InetPtonW(family, address_wide->c_str(), endpoint.address.data());
  if (parsed != 1) {
    return std::unexpected(
        error(ExitCode::usage_or_config, ERROR_INVALID_ADDRESS,
              L"[wfp-allow] keys must contain exact IPv4 or IPv6 literals"));
  }
  if (endpoint.ipv6 && is_v4_mapped(endpoint.address)) {
    return std::unexpected(
        error(ExitCode::usage_or_config, ERROR_INVALID_ADDRESS,
              L"IPv4-mapped IPv6 endpoints must be written as IPv4 addresses"));
  }
  endpoint.port = *port;
  return endpoint;
}

bool same_endpoint(const Config::Endpoint &left,
                   const Config::Endpoint &right) {
  return left.ipv6 == right.ipv6 && left.address == right.address &&
         left.port == right.port;
}

Result<void> validate_config(const Config &config) {
  if (config.account.empty() || config.policy_version == 0 ||
      config.allow.empty()) {
    return std::unexpected(error(ExitCode::usage_or_config, ERROR_INVALID_DATA,
                                 L"[policy] account, policy_version, and at "
                                 L"least one [wfp-allow] entry are required"));
  }
  return {};
}

Result<bool> is_elevated() {
  SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
  PSID administrators{};
  if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                &administrators)) {
    return std::unexpected(win32_error(ExitCode::precondition, GetLastError(),
                                       L"Create Administrators SID"));
  }
  const auto release = [&] { FreeSid(administrators); };
  BOOL member{};
  if (!CheckTokenMembership(nullptr, administrators, &member)) {
    const DWORD code = GetLastError();
    release();
    return std::unexpected(win32_error(ExitCode::precondition, code,
                                       L"Check administrator membership"));
  }
  release();
  return member != FALSE;
}

Result<void> require_elevation() {
  auto elevated = is_elevated();
  if (!elevated) {
    return std::unexpected(elevated.error());
  }
  if (!*elevated) {
    return std::unexpected(
        error(ExitCode::precondition, ERROR_ACCESS_DENIED,
              L"wfptool must run from an elevated Administrator session"));
  }
  return {};
}

Result<std::vector<std::byte>> resolve_account_sid(std::wstring_view account) {
  std::wstring account_name(account);
  DWORD sid_size{};
  DWORD domain_size{};
  SID_NAME_USE use{};
  LookupAccountNameW(nullptr, account_name.c_str(), nullptr, &sid_size, nullptr,
                     &domain_size, &use);
  const DWORD first_error = GetLastError();
  if (first_error != ERROR_INSUFFICIENT_BUFFER || sid_size == 0) {
    return std::unexpected(win32_error(ExitCode::precondition, first_error,
                                       L"Resolve configured account"));
  }
  std::vector<std::byte> sid(sid_size);
  std::wstring domain(domain_size, L'\0');
  if (!LookupAccountNameW(nullptr, account_name.c_str(), sid.data(), &sid_size,
                          domain.data(), &domain_size, &use)) {
    return std::unexpected(win32_error(ExitCode::precondition, GetLastError(),
                                       L"Resolve configured account"));
  }
  sid.resize(sid_size);
  return sid;
}

Result<std::wstring> sid_string(PSID sid) {
  LPWSTR text{};
  if (!ConvertSidToStringSidW(sid, &text)) {
    return std::unexpected(win32_error(ExitCode::precondition, GetLastError(),
                                       L"Convert SID to text"));
  }
  LocalMemory memory(text, LocalFree);
  return std::wstring(text);
}

Result<std::vector<std::byte>> security_descriptor(std::wstring_view sddl) {
  PSECURITY_DESCRIPTOR descriptor{};
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          std::wstring(sddl).c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
    return std::unexpected(win32_error(ExitCode::wfp, GetLastError(),
                                       L"Build security descriptor"));
  }
  LocalMemory memory(descriptor, LocalFree);
  const DWORD size = GetSecurityDescriptorLength(descriptor);
  std::vector<std::byte> result(size);
  std::memcpy(result.data(), descriptor, size);
  return result;
}

Result<std::vector<std::byte>> user_condition_descriptor(PSID sid) {
  auto text = sid_string(sid);
  if (!text) {
    return std::unexpected(text.error());
  }
  return security_descriptor(L"D:(A;;CC;;;" + *text + L")");
}

Result<std::vector<std::byte>> wfp_object_descriptor() {
  return security_descriptor(L"D:(A;;GA;;;SY)(A;;GA;;;BA)");
}

Result<Engine> open_engine(ExitCode exit_code = ExitCode::wfp) {
  Engine engine;
  const DWORD code = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr,
                                     nullptr, &engine.value);
  if (code != ERROR_SUCCESS) {
    return std::unexpected(win32_error(exit_code, code, L"Open WFP engine"));
  }
  return engine;
}

std::vector<UINT8> policy_identity(PSID sid) {
  const auto size = GetLengthSid(sid);
  std::vector<UINT8> result(policy_tag_prefix.begin(), policy_tag_prefix.end());
  const auto *sid_bytes = static_cast<const UINT8 *>(sid);
  result.insert(result.end(), sid_bytes, sid_bytes + size);
  return result;
}

std::vector<UINT8> policy_data(const std::vector<UINT8> &identity,
                               std::uint32_t version) {
  std::vector<UINT8> result = identity;
  const auto *version_bytes = reinterpret_cast<const UINT8 *>(&version);
  result.insert(result.end(), version_bytes, version_bytes + sizeof(version));
  return result;
}

bool same_blob(const FWP_BYTE_BLOB &blob, const std::vector<UINT8> &expected) {
  return blob.size == expected.size() && blob.data &&
         std::memcmp(blob.data, expected.data(), expected.size()) == 0;
}

bool is_owned_for(const FWPM_FILTER0 &filter,
                  const std::vector<UINT8> &identity) {
  return filter.providerKey && IsEqualGUID(*filter.providerKey, provider_key) &&
         IsEqualGUID(filter.subLayerKey, sublayer_key) &&
         filter.providerData.size == identity.size() + sizeof(std::uint32_t) &&
         filter.providerData.data &&
         std::memcmp(filter.providerData.data, identity.data(),
                     identity.size()) == 0;
}

const FWPM_FILTER_CONDITION0 *find_condition(const FWPM_FILTER0 &filter,
                                             const GUID &field) {
  for (UINT32 index = 0; index < filter.numFilterConditions; ++index) {
    if (IsEqualGUID(filter.filterCondition[index].fieldKey, field)) {
      return &filter.filterCondition[index];
    }
  }
  return nullptr;
}

bool same_user_descriptor(const FWP_BYTE_BLOB *actual,
                          const std::vector<std::byte> &expected) {
  if (!actual || !actual->data || expected.empty()) {
    return false;
  }
  const auto actual_descriptor =
      reinterpret_cast<PSECURITY_DESCRIPTOR>(actual->data);
  const auto expected_descriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(
      const_cast<std::byte *>(expected.data()));
  if (!IsValidSecurityDescriptor(actual_descriptor) ||
      !IsValidSecurityDescriptor(expected_descriptor)) {
    return false;
  }
  BOOL actual_present{};
  BOOL actual_defaulted{};
  PACL actual_dacl{};
  BOOL expected_present{};
  BOOL expected_defaulted{};
  PACL expected_dacl{};
  if (!GetSecurityDescriptorDacl(actual_descriptor, &actual_present,
                                 &actual_dacl, &actual_defaulted) ||
      !GetSecurityDescriptorDacl(expected_descriptor, &expected_present,
                                 &expected_dacl, &expected_defaulted) ||
      actual_present != expected_present ||
      actual_defaulted != expected_defaulted || actual_dacl == nullptr ||
      expected_dacl == nullptr) {
    return false;
  }
  return actual_dacl->AclSize == expected_dacl->AclSize &&
         std::memcmp(actual_dacl, expected_dacl, actual_dacl->AclSize) == 0;
}

bool matches_user(const FWPM_FILTER0 &filter,
                  const std::vector<std::byte> &user_sd) {
  const auto *user = find_condition(filter, FWPM_CONDITION_ALE_USER_ID);
  return user && user->matchType == FWP_MATCH_EQUAL &&
         user->conditionValue.type == FWP_SECURITY_DESCRIPTOR_TYPE &&
         same_user_descriptor(user->conditionValue.sd, user_sd);
}

bool descriptor_mentions_sid(const FWP_BYTE_BLOB *descriptor, PSID target_sid) {
  if (!descriptor || !descriptor->data || !target_sid) {
    return false;
  }
  const auto security_descriptor =
      reinterpret_cast<PSECURITY_DESCRIPTOR>(descriptor->data);
  BOOL present{};
  BOOL defaulted{};
  PACL dacl{};
  if (!IsValidSecurityDescriptor(security_descriptor) ||
      !GetSecurityDescriptorDacl(security_descriptor, &present, &dacl,
                                 &defaulted) ||
      !present || !dacl) {
    return false;
  }
  for (DWORD index = 0; index < dacl->AceCount; ++index) {
    void *raw_ace{};
    if (!GetAce(dacl, index, &raw_ace)) {
      return false;
    }
    const auto *header = static_cast<ACE_HEADER *>(raw_ace);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
        header->AceType != ACCESS_DENIED_ACE_TYPE) {
      continue;
    }
    const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw_ace);
    const auto ace_sid =
        reinterpret_cast<PSID>(const_cast<DWORD *>(&ace->SidStart));
    if (IsValidSid(ace_sid) && EqualSid(ace_sid, target_sid)) {
      return true;
    }
  }
  return false;
}

bool filter_mentions_user(const FWPM_FILTER0 &filter, PSID target_sid) {
  const auto *user = find_condition(filter, FWPM_CONDITION_ALE_USER_ID);
  return user && user->conditionValue.type == FWP_SECURITY_DESCRIPTOR_TYPE &&
         descriptor_mentions_sid(user->conditionValue.sd, target_sid);
}

Result<void> enumerate_filters(
    HANDLE engine, const GUID *provider,
    const std::function<Result<void>(const FWPM_FILTER0 &)> &visitor) {
  FWPM_FILTER_ENUM_TEMPLATE0 filter_template{};
  filter_template.providerKey = const_cast<GUID *>(provider);
  HANDLE enumeration{};
  DWORD code = FwpmFilterCreateEnumHandle0(
      engine, provider ? &filter_template : nullptr, &enumeration);
  // WFP reports this instead of an empty enumeration when the provider has
  // never owned a filter. For list/remove, that is simply an empty policy.
  if (code == FWP_E_NEVER_MATCH) {
    return {};
  }
  if (code != ERROR_SUCCESS) {
    return std::unexpected(
        win32_error(ExitCode::wfp, code, L"Create WFP filter enumeration"));
  }
  const auto close = [&] { FwpmFilterDestroyEnumHandle0(engine, enumeration); };
  for (;;) {
    FWPM_FILTER0 **filters{};
    UINT32 count{};
    code = FwpmFilterEnum0(engine, enumeration, 64, &filters, &count);
    if (code != ERROR_SUCCESS) {
      close();
      return std::unexpected(
          win32_error(ExitCode::wfp, code, L"Enumerate WFP filters"));
    }
    for (UINT32 index = 0; index < count; ++index) {
      auto result = visitor(*filters[index]);
      if (!result) {
        FwpmFreeMemory0(reinterpret_cast<void **>(&filters));
        close();
        return std::unexpected(result.error());
      }
    }
    FwpmFreeMemory0(reinterpret_cast<void **>(&filters));
    if (count == 0) {
      break;
    }
  }
  close();
  return {};
}

Result<void> enumerate_wfptool_filters(
    HANDLE engine,
    const std::function<Result<void>(const FWPM_FILTER0 &)> &visitor) {
  // FwpmFilterCreateEnumHandle0 can report FWP_E_NEVER_MATCH for a
  // providerKey-only template even while this provider has filters.  Enumerate
  // once without a template and keep the provider boundary here instead.
  return enumerate_filters(
      engine, nullptr, [&](const FWPM_FILTER0 &filter) -> Result<void> {
        return filter.providerKey &&
                       IsEqualGUID(*filter.providerKey, provider_key)
                   ? visitor(filter)
                   : Result<void>{};
      });
}

Result<void> enumerate_owned_filters(
    HANDLE engine, const std::vector<UINT8> &identity,
    const std::function<Result<void>(const FWPM_FILTER0 &)> &visitor) {
  return enumerate_wfptool_filters(
      engine, [&](const FWPM_FILTER0 &filter) -> Result<void> {
        return is_owned_for(filter, identity) ? visitor(filter)
                                              : Result<void>{};
      });
}

Result<void> ensure_infrastructure(HANDLE engine,
                                   PSECURITY_DESCRIPTOR object_sd) {
  FWPM_PROVIDER0 *existing_provider{};
  DWORD code = FwpmProviderGetByKey0(engine, &provider_key, &existing_provider);
  if (code == ERROR_SUCCESS) {
    const bool valid =
        (existing_provider->flags & FWPM_PROVIDER_FLAG_PERSISTENT) != 0 &&
        existing_provider->serviceName == nullptr;
    FwpmFreeMemory0(reinterpret_cast<void **>(&existing_provider));
    if (!valid) {
      return std::unexpected(
          error(ExitCode::wfp, ERROR_INVALID_DATA,
                L"Existing WfpTool provider metadata is invalid"));
    }
  } else if (code == FWP_E_PROVIDER_NOT_FOUND) {
    FWPM_PROVIDER0 provider{};
    provider.providerKey = provider_key;
    provider.displayData.name = const_cast<wchar_t *>(L"WfpTool Provider");
    provider.displayData.description = const_cast<wchar_t *>(
        L"Persistent per-user allowlist and default-deny WFP policies");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    code = FwpmProviderAdd0(engine, &provider, object_sd);
    if (code != ERROR_SUCCESS) {
      return std::unexpected(
          win32_error(ExitCode::wfp, code, L"Add WfpTool provider"));
    }
  } else {
    return std::unexpected(
        win32_error(ExitCode::wfp, code, L"Read WfpTool provider"));
  }

  const auto add_sublayer = [&]() -> Result<void> {
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = sublayer_key;
    sublayer.displayData.name = const_cast<wchar_t *>(L"WfpTool Sublayer");
    sublayer.displayData.description = const_cast<wchar_t *>(
        L"Per-user allowlist permits above default-deny blocks");
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.providerKey = const_cast<GUID *>(&provider_key);
    sublayer.weight = sublayer_weight;
    code = FwpmSubLayerAdd0(engine, &sublayer, object_sd);
    if (code != ERROR_SUCCESS) {
      return std::unexpected(
          win32_error(ExitCode::wfp, code, L"Add WfpTool sublayer"));
    }
    return {};
  };

  FWPM_SUBLAYER0 *existing_sublayer{};
  code = FwpmSubLayerGetByKey0(engine, &sublayer_key, &existing_sublayer);
  if (code == ERROR_SUCCESS) {
    FwpmFreeMemory0(reinterpret_cast<void **>(&existing_sublayer));
  } else if (code == FWP_E_SUBLAYER_NOT_FOUND) {
    return add_sublayer();
  } else {
    return std::unexpected(
        win32_error(ExitCode::wfp, code, L"Read WfpTool sublayer"));
  }
  return {};
}

Result<void> verify_infrastructure(HANDLE engine) {
  FWPM_PROVIDER0 *provider{};
  DWORD code = FwpmProviderGetByKey0(engine, &provider_key, &provider);
  if (code != ERROR_SUCCESS) {
    return std::unexpected(
        win32_error(ExitCode::verification, code, L"Read WfpTool provider"));
  }
  const bool provider_valid =
      (provider->flags & FWPM_PROVIDER_FLAG_PERSISTENT) != 0 &&
      provider->serviceName == nullptr;
  FwpmFreeMemory0(reinterpret_cast<void **>(&provider));
  if (!provider_valid) {
    return std::unexpected(
        error(ExitCode::verification, ERROR_INVALID_DATA,
              L"Existing WfpTool provider metadata is invalid"));
  }

  FWPM_SUBLAYER0 *sublayer{};
  code = FwpmSubLayerGetByKey0(engine, &sublayer_key, &sublayer);
  if (code != ERROR_SUCCESS) {
    return std::unexpected(
        win32_error(ExitCode::verification, code, L"Read WfpTool sublayer"));
  }
  FwpmFreeMemory0(reinterpret_cast<void **>(&sublayer));
  return {};
}

std::vector<Rule> build_rules(const Config &config) {
  std::vector<Rule> rules;
  const auto permit = [&](const GUID &layer, std::uint8_t protocol,
                          std::optional<std::uint32_t> address_v4,
                          std::optional<std::array<UINT8, 16>> address_v6,
                          std::uint16_t port) {
    rules.push_back(Rule{&layer, FWP_ACTION_PERMIT, permit_weight, protocol,
                         address_v4, address_v6, port});
  };
  for (const auto &endpoint : config.allow) {
    for (const std::uint8_t protocol :
         {static_cast<std::uint8_t>(IPPROTO_TCP),
          static_cast<std::uint8_t>(IPPROTO_UDP)}) {
      if ((protocol == IPPROTO_TCP && !endpoint.tcp) ||
          (protocol == IPPROTO_UDP && !endpoint.udp)) {
        continue;
      }
      if (endpoint.ipv6) {
        permit(FWPM_LAYER_ALE_AUTH_CONNECT_V6, protocol, std::nullopt,
               endpoint.address, endpoint.port);
      } else {
        std::uint32_t network_address{};
        std::memcpy(&network_address, endpoint.address.data(),
                    sizeof(network_address));
        const std::uint32_t address = ntohl(network_address);
        permit(FWPM_LAYER_ALE_AUTH_CONNECT_V4, protocol, address, std::nullopt,
               endpoint.port);
        std::array<UINT8, 16> mapped{};
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        std::copy_n(endpoint.address.begin(), 4, mapped.begin() + 12);
        permit(FWPM_LAYER_ALE_AUTH_CONNECT_V6, protocol, std::nullopt, mapped,
               endpoint.port);
      }
    }
  }
  rules.push_back(Rule{&FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK,
                       block_weight, std::nullopt, std::nullopt, std::nullopt,
                       std::nullopt});
  rules.push_back(Rule{&FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK,
                       block_weight, std::nullopt, std::nullopt, std::nullopt,
                       std::nullopt});
  return rules;
}

Result<void> add_rule(HANDLE engine, const Rule &rule,
                      FWP_BYTE_BLOB &user_descriptor,
                      const std::vector<UINT8> &data,
                      PSECURITY_DESCRIPTOR object_sd) {
  std::array<FWPM_FILTER_CONDITION0, 4> conditions{};
  UINT32 count{};
  conditions[count].fieldKey = FWPM_CONDITION_ALE_USER_ID;
  conditions[count].matchType = FWP_MATCH_EQUAL;
  conditions[count].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
  conditions[count].conditionValue.sd = &user_descriptor;
  ++count;
  if (rule.protocol) {
    conditions[count].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_UINT8;
    conditions[count].conditionValue.uint8 = *rule.protocol;
    ++count;
  }
  FWP_BYTE_ARRAY16 address_v6{};
  if (rule.address_v4) {
    conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_UINT32;
    conditions[count].conditionValue.uint32 = *rule.address_v4;
    ++count;
  } else if (rule.address_v6) {
    std::memcpy(address_v6.byteArray16, rule.address_v6->data(),
                sizeof(address_v6.byteArray16));
    conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
    conditions[count].conditionValue.byteArray16 = &address_v6;
    ++count;
  }
  if (rule.port) {
    conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_UINT16;
    conditions[count].conditionValue.uint16 = *rule.port;
    ++count;
  }
  FWP_VALUE0 weight{};
  weight.type = FWP_UINT64;
  weight.uint64 = const_cast<UINT64 *>(&rule.weight);
  FWP_BYTE_BLOB provider_data{static_cast<UINT32>(data.size()),
                              const_cast<UINT8 *>(data.data())};
  FWPM_FILTER0 filter{};
  filter.displayData.name = const_cast<wchar_t *>(L"WfpTool policy rule");
  filter.displayData.description = const_cast<wchar_t *>(
      L"Per-user allowlist or default-deny rule managed by WfpTool");
  filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
  filter.providerKey = const_cast<GUID *>(&provider_key);
  filter.providerData = provider_data;
  filter.layerKey = *rule.layer;
  filter.subLayerKey = sublayer_key;
  filter.weight = weight;
  filter.numFilterConditions = count;
  filter.filterCondition = conditions.data();
  filter.action.type = rule.action;
  const DWORD code = FwpmFilterAdd0(engine, &filter, object_sd, nullptr);
  if (code != ERROR_SUCCESS) {
    return std::unexpected(
        win32_error(ExitCode::wfp, code, L"Add WfpTool filter"));
  }
  return {};
}

Result<void> delete_wfptool_filters_for_user(HANDLE engine, PSID target_sid) {
  std::vector<GUID> keys;
  auto enumerated =
      enumerate_wfptool_filters(engine, [&](const FWPM_FILTER0 &filter) {
        if (IsEqualGUID(filter.subLayerKey, sublayer_key) &&
            filter_mentions_user(filter, target_sid)) {
          keys.push_back(filter.filterKey);
        }
        return Result<void>{};
      });
  if (!enumerated) {
    return std::unexpected(enumerated.error());
  }
  for (const auto &key : keys) {
    const DWORD code = FwpmFilterDeleteByKey0(engine, &key);
    if (code != ERROR_SUCCESS) {
      return std::unexpected(
          win32_error(ExitCode::wfp, code, L"Delete WfpTool filter"));
    }
  }
  return {};
}

Result<void> remove_unused_wfptool_infrastructure(HANDLE engine) {
  bool referenced{};
  auto enumerated =
      enumerate_filters(engine, nullptr, [&](const FWPM_FILTER0 &filter) {
        referenced = referenced ||
                     IsEqualGUID(filter.subLayerKey, sublayer_key) ||
                     (filter.providerKey &&
                      IsEqualGUID(*filter.providerKey, provider_key));
        return Result<void>{};
      });
  if (!enumerated) {
    return std::unexpected(enumerated.error());
  }
  if (referenced) {
    return {};
  }

  DWORD code = FwpmSubLayerDeleteByKey0(engine, &sublayer_key);
  if (code != ERROR_SUCCESS && code != FWP_E_SUBLAYER_NOT_FOUND) {
    return std::unexpected(
        win32_error(ExitCode::wfp, code, L"Remove unused WfpTool sublayer"));
  }
  code = FwpmProviderDeleteByKey0(engine, &provider_key);
  if (code != ERROR_SUCCESS && code != FWP_E_PROVIDER_NOT_FOUND) {
    return std::unexpected(
        win32_error(ExitCode::wfp, code, L"Remove unused WfpTool provider"));
  }
  return {};
}

Result<void> clear_user_filters(HANDLE engine, PSID target_sid) {
  auto removed = delete_wfptool_filters_for_user(engine, target_sid);
  if (!removed) {
    return std::unexpected(removed.error());
  }
  return remove_unused_wfptool_infrastructure(engine);
}

bool matches_rule(const FWPM_FILTER0 &filter, const Rule &expected,
                  const std::vector<UINT8> &data,
                  const std::vector<std::byte> &user_sd) {
  const UINT32 condition_count =
      1 + (expected.protocol ? 1 : 0) +
      (expected.address_v4 || expected.address_v6 ? 1 : 0) +
      (expected.port ? 1 : 0);
  if (!filter.providerKey || !IsEqualGUID(*filter.providerKey, provider_key) ||
      !IsEqualGUID(filter.subLayerKey, sublayer_key) ||
      !IsEqualGUID(filter.layerKey, *expected.layer) ||
      filter.flags != FWPM_FILTER_FLAG_PERSISTENT ||
      filter.action.type != expected.action ||
      filter.weight.type != FWP_UINT64 || !filter.weight.uint64 ||
      *filter.weight.uint64 != expected.weight ||
      filter.numFilterConditions != condition_count ||
      !same_blob(filter.providerData, data)) {
    return false;
  }
  if (!matches_user(filter, user_sd)) {
    return false;
  }
  if (expected.protocol) {
    const auto *protocol = find_condition(filter, FWPM_CONDITION_IP_PROTOCOL);
    if (!protocol || protocol->matchType != FWP_MATCH_EQUAL ||
        protocol->conditionValue.type != FWP_UINT8 ||
        protocol->conditionValue.uint8 != *expected.protocol) {
      return false;
    }
  }
  if (expected.address_v4 || expected.address_v6) {
    const auto *address =
        find_condition(filter, FWPM_CONDITION_IP_REMOTE_ADDRESS);
    if (!address || address->matchType != FWP_MATCH_EQUAL) {
      return false;
    }
    if (expected.address_v4 &&
        (address->conditionValue.type != FWP_UINT32 ||
         address->conditionValue.uint32 != *expected.address_v4)) {
      return false;
    }
    if (expected.address_v6 &&
        (address->conditionValue.type != FWP_BYTE_ARRAY16_TYPE ||
         !address->conditionValue.byteArray16 ||
         std::memcmp(address->conditionValue.byteArray16->byteArray16,
                     expected.address_v6->data(), 16) != 0)) {
      return false;
    }
  }
  if (expected.port) {
    const auto *port = find_condition(filter, FWPM_CONDITION_IP_REMOTE_PORT);
    if (!port || port->matchType != FWP_MATCH_EQUAL ||
        port->conditionValue.type != FWP_UINT16 ||
        port->conditionValue.uint16 != *expected.port) {
      return false;
    }
  }
  return true;
}

Result<void> verify_wfp_policy(const Config &config, PSID sid) {
  auto engine = open_engine(ExitCode::verification);
  if (!engine) {
    return std::unexpected(engine.error());
  }
  auto infrastructure = verify_infrastructure(engine->value);
  if (!infrastructure) {
    return std::unexpected(infrastructure.error());
  }
  auto user_sd = user_condition_descriptor(sid);
  if (!user_sd) {
    return std::unexpected(user_sd.error());
  }
  const auto identity = policy_identity(sid);
  const auto data = policy_data(identity, config.policy_version);
  const auto expected = build_rules(config);
  std::vector<bool> matched(expected.size());
  std::size_t found{};
  auto enumerated = enumerate_owned_filters(
      engine->value, identity, [&](const FWPM_FILTER0 &filter) -> Result<void> {
        ++found;
        for (std::size_t index = 0; index < expected.size(); ++index) {
          if (!matched[index] &&
              matches_rule(filter, expected[index], data, *user_sd)) {
            matched[index] = true;
            return Result<void>{};
          }
        }
        return std::unexpected(
            error(ExitCode::verification, ERROR_INVALID_DATA,
                  L"Installed WfpTool policy contains an unexpected filter"));
      });
  if (!enumerated) {
    return std::unexpected(enumerated.error());
  }
  if (found != expected.size() ||
      std::find(matched.begin(), matched.end(), false) != matched.end()) {
    return std::unexpected(
        error(ExitCode::verification, ERROR_INVALID_DATA,
              L"Installed WfpTool filters do not match the configuration"));
  }
  return {};
}

Result<void> apply_wfp_policy(const Config &config, PSID sid) {
  auto engine = open_engine();
  if (!engine) {
    return std::unexpected(engine.error());
  }
  auto user_sd = user_condition_descriptor(sid);
  if (!user_sd) {
    return std::unexpected(user_sd.error());
  }
  auto object_sd = wfp_object_descriptor();
  if (!object_sd) {
    return std::unexpected(object_sd.error());
  }
  const DWORD begin = FwpmTransactionBegin0(engine->value, 0);
  if (begin != ERROR_SUCCESS) {
    return std::unexpected(
        win32_error(ExitCode::wfp, begin, L"Begin WfpTool transaction"));
  }
  bool active = true;
  const auto abort = [&] {
    if (active) {
      FwpmTransactionAbort0(engine->value);
      active = false;
    }
  };
  const auto identity = policy_identity(sid);
  auto cleared = clear_user_filters(engine->value, sid);
  if (!cleared) {
    abort();
    return std::unexpected(cleared.error());
  }
  auto infrastructure = ensure_infrastructure(
      engine->value, static_cast<PSECURITY_DESCRIPTOR>(object_sd->data()));
  if (!infrastructure) {
    abort();
    return std::unexpected(infrastructure.error());
  }
  FWP_BYTE_BLOB user_blob{static_cast<UINT32>(user_sd->size()),
                          reinterpret_cast<UINT8 *>(user_sd->data())};
  const auto data = policy_data(identity, config.policy_version);
  for (const auto &rule : build_rules(config)) {
    auto added = add_rule(engine->value, rule, user_blob, data,
                          static_cast<PSECURITY_DESCRIPTOR>(object_sd->data()));
    if (!added) {
      abort();
      return std::unexpected(added.error());
    }
  }
  const DWORD commit = FwpmTransactionCommit0(engine->value);
  if (commit != ERROR_SUCCESS) {
    abort();
    return std::unexpected(
        win32_error(ExitCode::wfp, commit, L"Commit WfpTool transaction"));
  }
  active = false;
  return {};
}

std::wstring address_text(const FWPM_FILTER_CONDITION0 *address) {
  if (!address) {
    return L"*";
  }
  wchar_t buffer[INET6_ADDRSTRLEN]{};
  if (address->conditionValue.type == FWP_UINT32) {
    const std::uint32_t network_address = htonl(address->conditionValue.uint32);
    std::array<UINT8, 4> bytes{};
    std::memcpy(bytes.data(), &network_address, sizeof(network_address));
    if (InetNtopW(AF_INET, bytes.data(), buffer, std::size(buffer))) {
      return buffer;
    }
  } else if (address->conditionValue.type == FWP_BYTE_ARRAY16_TYPE &&
             address->conditionValue.byteArray16 &&
             InetNtopW(AF_INET6,
                       address->conditionValue.byteArray16->byteArray16, buffer,
                       std::size(buffer))) {
    return L"[" + std::wstring(buffer) + L"]";
  }
  return L"<invalid address>";
}

std::wstring guid_text(const GUID &guid) {
  wchar_t buffer[39]{};
  StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer)));
  return buffer;
}

std::wstring provider_text(const GUID *key) {
  if (!key) {
    return L"<none>";
  }
  return IsEqualGUID(*key, provider_key) ? L"wfptool" : guid_text(*key);
}

std::wstring protocol_text(const FWPM_FILTER_CONDITION0 *protocol) {
  if (!protocol) {
    return L"any";
  }
  if (protocol->conditionValue.type == FWP_UINT8) {
    if (protocol->conditionValue.uint8 == IPPROTO_TCP) {
      return L"tcp";
    }
    if (protocol->conditionValue.uint8 == IPPROTO_UDP) {
      return L"udp";
    }
    if (protocol->conditionValue.uint8 == IPPROTO_ICMP) {
      return L"icmp";
    }
    if (protocol->conditionValue.uint8 == IPPROTO_ICMPV6) {
      return L"icmpv6";
    }
  }
  return L"<invalid protocol>";
}

Result<void> apply_command(const std::filesystem::path &source) {
  auto elevated = require_elevation();
  if (!elevated) {
    return std::unexpected(elevated.error());
  }
  auto config = load_config(source);
  if (!config) {
    return std::unexpected(config.error());
  }
  auto sid = resolve_account_sid(config->account);
  if (!sid) {
    return std::unexpected(sid.error());
  }
  auto applied = apply_wfp_policy(*config, sid->data());
  if (!applied) {
    return std::unexpected(applied.error());
  }
  return verify_wfp_policy(*config, sid->data());
}

Result<void> verify_command(const std::filesystem::path &source) {
  auto elevated = require_elevation();
  if (!elevated) {
    return std::unexpected(elevated.error());
  }
  auto config = load_config(source);
  if (!config) {
    return std::unexpected(config.error());
  }
  auto sid = resolve_account_sid(config->account);
  if (!sid) {
    return std::unexpected(sid.error());
  }
  return verify_wfp_policy(*config, sid->data());
}

Result<void> clear_user_policy(PSID sid) {
  auto engine = open_engine();
  if (!engine) {
    return std::unexpected(engine.error());
  }
  const DWORD begin = FwpmTransactionBegin0(engine->value, 0);
  if (begin != ERROR_SUCCESS) {
    return std::unexpected(win32_error(ExitCode::wfp, begin,
                                       L"Begin WfpTool removal transaction"));
  }
  auto cleared = clear_user_filters(engine->value, sid);
  if (!cleared) {
    FwpmTransactionAbort0(engine->value);
    return std::unexpected(cleared.error());
  }
  const DWORD commit = FwpmTransactionCommit0(engine->value);
  if (commit != ERROR_SUCCESS) {
    FwpmTransactionAbort0(engine->value);
    return std::unexpected(win32_error(ExitCode::wfp, commit,
                                       L"Commit WfpTool removal transaction"));
  }
  return {};
}

Result<void> clear_command(std::wstring_view account) {
  auto elevated = require_elevation();
  if (!elevated) {
    return std::unexpected(elevated.error());
  }
  auto sid = resolve_account_sid(account);
  if (!sid) {
    return std::unexpected(sid.error());
  }
  return clear_user_policy(sid->data());
}

Result<void> remove_command(const std::filesystem::path &source) {
  auto config = load_config(source);
  if (!config) {
    return std::unexpected(config.error());
  }
  return clear_command(config->account);
}

Result<void> list_command(std::wstring_view account) {
  auto elevated = require_elevation();
  if (!elevated) {
    return std::unexpected(elevated.error());
  }
  auto sid = resolve_account_sid(account);
  if (!sid) {
    return std::unexpected(sid.error());
  }
  auto text = sid_string(sid->data());
  if (!text) {
    return std::unexpected(text.error());
  }
  auto engine = open_engine();
  if (!engine) {
    return std::unexpected(engine.error());
  }
  std::wcout << L"WFP filters for " << *text << L":\n";
  std::size_t count{};
  auto enumerated = enumerate_filters(
      engine->value, nullptr, [&](const FWPM_FILTER0 &filter) -> Result<void> {
        const bool matches_account = filter_mentions_user(filter, sid->data());
        const bool references_wfptool_sublayer =
            IsEqualGUID(filter.subLayerKey, sublayer_key);
        if (!matches_account && !references_wfptool_sublayer) {
          return {};
        }
        ++count;
        const auto *protocol =
            find_condition(filter, FWPM_CONDITION_IP_PROTOCOL);
        const auto *address =
            find_condition(filter, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        const auto *port =
            find_condition(filter, FWPM_CONDITION_IP_REMOTE_PORT);
        const wchar_t *layer =
            IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4)
                ? L"ALE_AUTH_CONNECT_V4"
            : IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6)
                ? L"ALE_AUTH_CONNECT_V6"
            : IsEqualGUID(filter.layerKey,
                          FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4)
                ? L"ALE_RESOURCE_ASSIGNMENT_V4"
                : L"ALE_RESOURCE_ASSIGNMENT_V6";
        std::wcout << L"[" << filter.filterId << L"] "
                   << (matches_account ? L"account " : L"WfpTool-sublayer ")
                   << (filter.action.type == FWP_ACTION_PERMIT ? L"permit "
                                                               : L"block ")
                   << protocol_text(protocol) << L" " << address_text(address);
        if (port && port->conditionValue.type == FWP_UINT16) {
          std::wcout << L":" << port->conditionValue.uint16;
        }
        std::wcout << L" at " << layer << L" (weight=";
        if (filter.weight.type == FWP_UINT64 && filter.weight.uint64) {
          std::wcout << *filter.weight.uint64;
        } else {
          std::wcout << L"invalid";
        }
        std::wcout << L", provider=" << provider_text(filter.providerKey)
                   << L", key=" << guid_text(filter.filterKey) << L")\n";
        return Result<void>{};
      });
  if (!enumerated) {
    return std::unexpected(enumerated.error());
  }
  if (count == 0) {
    std::wcout << L"(none)\n";
  }
  return {};
}

void print_usage() {
  std::wcerr << L"Usage:\n"
             << L"  wfptool apply --config <path>\n"
             << L"  wfptool verify --config <path>\n"
             << L"  wfptool remove --config <path>\n"
             << L"  wfptool clear --user <account>\n"
             << L"  wfptool list --user <account>\n";
}

int finish(Result<void> result, std::wstring_view success_message) {
  if (!result) {
    std::wcerr << L"Error: " << result.error().message << L'\n';
    return static_cast<int>(result.error().exit_code);
  }
  std::wcout << success_message << L'\n';
  return static_cast<int>(ExitCode::success);
}

} // namespace

Result<Config> parse_config(std::string_view text) {
  Config config{};
  std::string section;
  bool account_seen{};
  bool version_seen{};
  std::size_t line_start{};
  while (line_start <= text.size()) {
    const std::size_t line_end = text.find('\n', line_start);
    std::string_view line =
        trim(text.substr(line_start, line_end == std::string_view::npos
                                         ? std::string_view::npos
                                         : line_end - line_start));
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (!line.empty() && line.front() != '#' && line.front() != ';') {
      if (line.front() == '[' && line.back() == ']') {
        section = ascii_lower(trim(line.substr(1, line.size() - 2)));
      } else {
        const std::size_t equals = line.find('=');
        if (equals == std::string_view::npos || equals == 0) {
          return std::unexpected(
              error(ExitCode::usage_or_config, ERROR_INVALID_DATA,
                    L"Configuration lines must use key=value"));
        }
        const std::string_view key = trim(line.substr(0, equals));
        const std::string_view value = trim(line.substr(equals + 1));
        if (section == "policy") {
          const std::string lowered_key = ascii_lower(key);
          if (lowered_key == "account") {
            if (account_seen) {
              return std::unexpected(error(ExitCode::usage_or_config,
                                           ERROR_DUP_NAME,
                                           L"Duplicate [policy] account"));
            }
            auto account = utf8_to_wide(value);
            if (!account || account->empty()) {
              return std::unexpected(
                  account ? error(ExitCode::usage_or_config, ERROR_INVALID_DATA,
                                  L"[policy] account must not be empty")
                          : account.error());
            }
            config.account = std::move(*account);
            account_seen = true;
          } else if (lowered_key == "policy_version") {
            if (version_seen) {
              return std::unexpected(
                  error(ExitCode::usage_or_config, ERROR_DUP_NAME,
                        L"Duplicate [policy] policy_version"));
            }
            auto version = parse_version(value);
            if (!version) {
              return std::unexpected(version.error());
            }
            config.policy_version = *version;
            version_seen = true;
          }
        } else if (section == "wfp-allow") {
          auto endpoint = parse_endpoint(key, value);
          if (!endpoint) {
            return std::unexpected(endpoint.error());
          }
          if (std::any_of(config.allow.begin(), config.allow.end(),
                          [&](const Config::Endpoint &existing) {
                            return same_endpoint(existing, *endpoint);
                          })) {
            return std::unexpected(error(ExitCode::usage_or_config,
                                         ERROR_DUP_NAME,
                                         L"Duplicate [wfp-allow] endpoint"));
          }
          config.allow.push_back(*endpoint);
        }
      }
    }
    if (line_end == std::string_view::npos) {
      break;
    }
    line_start = line_end + 1;
  }
  auto valid = validate_config(config);
  if (!valid) {
    return std::unexpected(valid.error());
  }
  return config;
}

Result<Config> load_config(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return std::unexpected(error(ExitCode::usage_or_config,
                                 static_cast<std::uint32_t>(GetLastError()),
                                 L"Open configuration: " + path.wstring()));
  }
  std::ostringstream text;
  text << file.rdbuf();
  if (!file.good() && !file.eof()) {
    return std::unexpected(error(ExitCode::usage_or_config, ERROR_READ_FAULT,
                                 L"Read configuration: " + path.wstring()));
  }
  return parse_config(text.str());
}

int run(std::span<const std::wstring_view> arguments) {
  if (arguments.empty()) {
    print_usage();
    return static_cast<int>(ExitCode::usage_or_config);
  }
  const auto command = arguments.front();
  if (command == L"apply" || command == L"verify" || command == L"remove") {
    if (arguments.size() != 3 || arguments[1] != L"--config") {
      print_usage();
      return static_cast<int>(ExitCode::usage_or_config);
    }
    const auto config = std::filesystem::path(arguments[2]);
    if (command == L"apply") {
      return finish(apply_command(config),
                    L"WfpTool policy applied and verified.");
    }
    if (command == L"verify") {
      return finish(verify_command(config),
                    L"WfpTool policy matches the configuration.");
    }
    return finish(remove_command(config), L"WfpTool policy removed.");
  }
  if (command == L"list") {
    if (arguments.size() != 3 || arguments[1] != L"--user") {
      print_usage();
      return static_cast<int>(ExitCode::usage_or_config);
    }
    return finish(list_command(arguments[2]), L"WfpTool filters listed.");
  }
  if (command == L"clear") {
    if (arguments.size() != 3 || arguments[1] != L"--user") {
      print_usage();
      return static_cast<int>(ExitCode::usage_or_config);
    }
    return finish(clear_command(arguments[2]), L"WfpTool filters cleared.");
  }
  print_usage();
  return static_cast<int>(ExitCode::usage_or_config);
}

} // namespace sandbox_network
