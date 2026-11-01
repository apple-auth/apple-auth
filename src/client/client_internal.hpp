#pragma once

#include <apple_auth/client.hpp>
#include <apple_auth/srp.hpp>
#include <nlohmann/json.hpp>

namespace apple_auth::netdetail {
using View = ByteView;
using Json = nlohmann::json;
using Path = std::filesystem::path;

struct Error : apple_auth::Error {
    using apple_auth::Error::Error;

    explicit Error(std::string message)
        : apple_auth::Error(ErrorCode::invalid_data, std::move(message)) {}
};

void require(bool valid, const std::string& message);
void validate_device_headers(const ClientOptions& options);
void apply_device_headers(Headers& headers, const ClientOptions& options);
void merge_headers(Headers& headers, const Headers& overrides);
Transport configured_transport(const ClientOptions& options);
Bytes bytes(const std::string& value);
std::string str(View value);
Bytes read_file(const Path& path, std::size_t limit = 64 * 1024);
std::uint64_t download_file(const std::string& url, const Path& destination);
void write_private(const Path& path, View data);
Bytes random_bytes(std::size_t size);
Bytes unhex(const std::string& value);
std::string hex(View value);
Bytes unbase64(const std::string& value);
Bytes digest(const std::string& name, View value);
Bytes hmac_sha256(View key, View value);
Bytes aes_cbc(View input, View key, View iv, bool decrypt, bool padding = false);
Bytes password_key(const std::string& password, View salt, int iterations, bool hex_password);
Json parse_plist(View input);
Bytes encode_plist(const Json& value);
HttpResponse curl_transport(const HttpRequest& request);
std::int64_t http_date(const std::string& value);
void check_apple_endpoint(const std::string& url);
Json lookup_grandslam_urls(const Headers& headers, const Transport& transport);
std::string grandslam_url(const Json& urls, const char* name);

using apple_auth::SrpHandshake;

enum class AccountState {
    requires_two_factor,
    requires_sms,
    authenticated
};
Json parse_grandslam_session(View clear);
AccountState grandslam_account_state(const Json& response, const Json& session);
void verify_grandslam_two_factor(const Json& response);
Json grandslam_login(const std::string& email,
                     const std::string& password,
                     const std::function<Headers()>& fresh_headers,
                     const TwoFactor& two_factor,
                     const Transport& transport,
                     const std::function<std::int64_t()>& clock,
                     const VerificationOptions* verification = nullptr);
DeveloperSession exchange_developer_session(const AccountSession& account,
                                            const std::function<Headers()>& fresh_headers,
                                            const Transport& transport,
                                            const std::function<std::int64_t()>& clock);
} // namespace apple_auth::netdetail
