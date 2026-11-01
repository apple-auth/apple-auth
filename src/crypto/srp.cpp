#include <apple_auth/srp.hpp>
#include "crypto/protocol.hpp"

// SRP formulas adapted from ipsw/ipatool; see THIRD_PARTY_NOTICES.md.
namespace apple_auth {
using View = ByteView;
using crypto::require;
using crypto::unhex;
using crypto::bytes;
using crypto::digest;
using crypto::random_bytes;
using crypto::password_key;

namespace {
using BigNumber = crypto::Number;

BigNumber decode_number(ByteView encoded) {
    return BigNumber(encoded);
}

BigNumber make_number() {
    return BigNumber();
}

constexpr auto group_prime =
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A1"
    "3DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B"
    "93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A43"
    "6C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861602790"
    "04E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE23"
    "6D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

BigNumber group_modulus() {
    return decode_number(unhex(group_prime));
}

Bytes encode_number(const BigNumber& number) {
    return number.encode();
}

Bytes join_parts(std::initializer_list<View> parts) {
    Bytes out;
    for (auto part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

Bytes hash_parts(std::initializer_list<View> parts) {
    return digest("SHA256", join_parts(parts));
}
} // namespace

SrpHandshake::SrpHandshake(Bytes secret)
    : secret_(secret.empty() ? random_bytes(32) : std::move(secret)) {
    require(secret_.size() <= 32, "Invalid SRP ephemeral size");
    auto private_value = decode_number(secret_);
    require(secret_.size() <= 32 && !private_value.zero(), "Invalid SRP ephemeral");
}

SrpHandshake::~SrpHandshake() {
    crypto::wipe(secret_.data(), secret_.size());
}

SrpHandshake::Proof::~Proof() {
    crypto::wipe(key.data(), key.size());
}

Bytes SrpHandshake::public_key() const {
    auto modulus = group_modulus();
    auto generator = make_number();
    auto private_value = decode_number(secret_);
    auto client_public = make_number();
    crypto::check(mbedtls_mpi_lset(generator.get(), 2), "SRP generator initialization failed");
    crypto::power(client_public, generator, private_value, modulus);
    return encode_number(client_public);
}

SrpHandshake::Proof SrpHandshake::complete(const std::string& user,
                                           const std::string& password,
                                           ByteView salt,
                                           ByteView server,
                                           int iterations,
                                           const std::string& protocol) const {
    // SrpHandshake uses RFC 5054's 2048-bit group with Apple's password derivation.

    require(user.size() <= 4096 && !server.empty() && server.size() <= 257 &&
                (protocol == "s2k" || protocol == "s2k_fo"),
            "Invalid SRP challenge");
    auto modulus = group_modulus();
    auto generator = make_number();
    auto private_value = decode_number(secret_);
    auto client_public = make_number();
    auto server_public = decode_number(server);
    auto remainder = make_number();
    crypto::check(mbedtls_mpi_lset(generator.get(), 2), "SRP generator initialization failed");
    crypto::check(mbedtls_mpi_mod_mpi(remainder.get(), server_public.get(), modulus.get()),
                  "SRP reduction failed");
    require(!remainder.zero(), "Invalid SRP server public key");
    crypto::power(client_public, generator, private_value, modulus);
    const auto encoded_client = encode_number(client_public);
    const auto encoded_server = encode_number(server_public);
    const auto encoded_modulus = encode_number(modulus);
    Bytes padded_generator(encoded_modulus.size());
    padded_generator.back() = 2;
    auto scrambling = decode_number(hash_parts({encoded_client, encoded_server}));
    auto multiplier = decode_number(hash_parts({encoded_modulus, padded_generator}));
    require(!scrambling.zero(), "Invalid SRP scrambling parameter");
    auto derived_password = password_key(password, salt, iterations, protocol == "s2k_fo");
    auto colon = bytes(":");
    auto password_hash = hash_parts({colon, derived_password});
    crypto::wipe(derived_password.data(), derived_password.size());
    auto password_exponent = decode_number(hash_parts({salt, password_hash}));
    auto verifier = make_number();
    auto multiplied_verifier = make_number();
    auto shared_base = make_number();
    auto scrambled_exponent = make_number();
    auto shared_exponent = make_number();
    auto premaster = make_number();
    // S = (B - k * g^x) ^ (a + u * x) mod N.
    crypto::power(verifier, generator, password_exponent, modulus);
    crypto::check(mbedtls_mpi_mul_mpi(multiplied_verifier.get(), multiplier.get(), verifier.get()),
                  "SRP multiplication failed");
    crypto::check(
        mbedtls_mpi_sub_mpi(shared_base.get(), server_public.get(), multiplied_verifier.get()),
        "SRP subtraction failed");
    crypto::check(mbedtls_mpi_mod_mpi(shared_base.get(), shared_base.get(), modulus.get()),
                  "SRP reduction failed");
    crypto::check(
        mbedtls_mpi_mul_mpi(scrambled_exponent.get(), scrambling.get(), password_exponent.get()),
        "SRP multiplication failed");
    crypto::check(
        mbedtls_mpi_add_mpi(shared_exponent.get(), private_value.get(), scrambled_exponent.get()),
        "SRP addition failed");
    crypto::power(premaster, shared_base, shared_exponent, modulus);
    auto session_key = hash_parts({encode_number(premaster)});
    auto group_hash = hash_parts({encoded_modulus});
    const auto generator_hash = hash_parts({padded_generator});
    for (std::size_t i = 0; i < group_hash.size(); ++i) {
        group_hash[i] ^= generator_hash[i];
    }
    auto username_hash = hash_parts({bytes(user)});
    const auto client_proof =
        hash_parts({group_hash, username_hash, salt, encoded_client, encoded_server, session_key});
    const auto server_proof = hash_parts({encoded_client, client_proof, session_key});
    return {client_proof, server_proof, session_key};
}

void SrpHandshake::Proof::verify(ByteView reply) const {
    require(reply.size() == m2.size() && crypto::equal(reply, m2),
            "SrpHandshake server proof is invalid");
}

Bytes SrpHandshake::Proof::decrypt_session(ByteView server_proof, ByteView encrypted) const {
    verify(server_proof);
    auto cipher_key = crypto::hmac_sha256(key, crypto::bytes("extra data key:"));
    auto iv = crypto::hmac_sha256(key, crypto::bytes("extra data iv:"));
    iv.resize(16);
    struct Cleanup {
        Bytes& key;
        ~Cleanup() { crypto::wipe(key.data(), key.size()); }
    } cleanup{cipher_key};
    return crypto::aes_cbc(encrypted, cipher_key, iv, true, true);
}

} // namespace apple_auth
