#include "client/client_internal.hpp"
#include <apple_auth/session_crypto.hpp>

namespace apple_auth {
namespace {
constexpr std::size_t file_limit = 16 * 1024 * 1024 + session_encryption_overhead;
Bytes encode(ByteView data, std::optional<ByteView> key) {
    return key ? encrypt_session(data, *key) : Bytes(data.begin(), data.end());
}
Bytes decode(ByteView data, std::optional<ByteView> key) {
    return key ? decrypt_session(data, *key) : Bytes(data.begin(), data.end());
}
} // namespace

Bytes AccountSession::serialize(std::optional<ByteView> key) const { return encode(plist, key); }
AccountSession AccountSession::deserialize(ByteView data, std::optional<ByteView> key) {
    return from_plist(decode(data, key));
}
AccountSession AccountSession::load(const std::filesystem::path& file, ByteView key) {
    return deserialize(netdetail::read_file(file, file_limit), key);
}
void AccountSession::save(const std::filesystem::path& file, ByteView key) const {
    netdetail::write_private(file, serialize(key));
}

Bytes StoreSession::serialize(std::optional<ByteView> key) const { return encode(plist(), key); }
StoreSession StoreSession::deserialize(ByteView data, std::optional<ByteView> key) {
    return from_plist(decode(data, key));
}
StoreSession StoreSession::load(const std::filesystem::path& file, ByteView key) {
    return deserialize(netdetail::read_file(file, file_limit), key);
}
void StoreSession::save(const std::filesystem::path& file, ByteView key) const {
    netdetail::write_private(file, serialize(key));
}

Bytes DeveloperSession::serialize(std::optional<ByteView> key) const {
    return encode(netdetail::bytes(netdetail::Json{{"account_id", account_id}, {"token", token},
                    {"expires_at_ms", expires_at_ms}}.dump()), key);
}
DeveloperSession DeveloperSession::deserialize(ByteView data, std::optional<ByteView> key) {
    const auto clear = decode(data, key);
    const auto fields = netdetail::Json::parse(clear);
    DeveloperSession result{fields.at("account_id").get<std::string>(),
        fields.at("token").get<std::string>(), fields.at("expires_at_ms").get<std::int64_t>()};
    netdetail::require(!result.account_id.empty() && !result.token.empty() && result.expires_at_ms >= 0,
                       "Invalid saved Developer Session");
    return result;
}
DeveloperSession DeveloperSession::load(const std::filesystem::path& file, std::optional<ByteView> key) {
    return deserialize(netdetail::read_file(file, file_limit), key);
}
void DeveloperSession::save(const std::filesystem::path& file, std::optional<ByteView> key) const {
    netdetail::write_private(file, serialize(key));
}
} // namespace apple_auth
