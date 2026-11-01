#pragma once

#include "apple_auth/core.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <vector>

namespace apple_auth::detail {
using AesBlock = std::array<std::uint8_t, 16>;

using Aes128Schedule = std::array<AesBlock, 11>;

using Sha1Digest = std::array<std::uint8_t, 20>;

using Sha256Digest = std::array<std::uint8_t, 32>;

using Md5Digest = std::array<std::uint8_t, 16>;

Aes128Schedule expand_aes128_key(std::span<const std::uint8_t, 16> key);

void aes_add_round_key(AesBlock& state, const AesBlock& key);

AesBlock recover_aes128_key(AesBlock key);

AesBlock encrypt_aes128_block(AesBlock state, const Aes128Schedule& key);

AesBlock decrypt_aes128_block(AesBlock state, const Aes128Schedule& key);

Sha1Digest sha1(std::span<const std::uint8_t> input);

Sha256Digest sha256(std::span<const std::uint8_t> input);

Md5Digest md5(std::span<const std::uint8_t> input);

struct StateFileView {
    std::uint32_t version;
    std::span<const std::uint8_t> prefix;
    std::span<const std::uint8_t, 16> iv;
    std::span<const std::uint8_t> ciphertext;
    std::span<const std::uint8_t, 20> authentication_tag;
};

std::uint32_t read_state_file_word(std::span<const std::uint8_t, 4> bytes);

StateFileView parse_state_file(std::span<const std::uint8_t> bytes);

struct StateBodySchemaParameters {
    AesBlock field_mask;
    std::uint32_t outer_tag;
    std::array<std::uint32_t, 6> record_tags;
};

struct StateBody {
    std::uint64_t profile;
    std::array<std::uint8_t, 60> profile_data;
    std::vector<std::uint8_t> secondary;
    std::array<std::uint8_t, 32> encrypted_seed;
    std::optional<std::uint32_t> option;
    std::array<std::uint8_t, 8> extra_data;
};

std::vector<std::uint8_t> serialize_state_body(const StateBody& state,
                                               const StateBodySchemaParameters& parameters,
                                               std::span<const std::uint8_t> padding = {});

std::uint64_t read_state_body_integer(std::span<const std::uint8_t> bytes);

StateBody parse_state_body(std::span<const std::uint8_t> encoded,
                           const StateBodySchemaParameters& parameters);

using FileKeyDiffusionState = std::array<std::uint8_t, 319>;

struct FileKeyNonlinearState {
    FileKeyDiffusionState state;
    std::array<std::uint8_t, 128> tables;
    std::array<std::uint8_t, 16> input;
};

namespace file_key_detail {

constexpr std::uint8_t byte(std::uint32_t value) {
    return static_cast<std::uint8_t>(value);
}

constexpr std::uint32_t word(std::uint32_t value) {
    return value;
}

constexpr std::uint8_t cube_byte(std::uint8_t value) {
    return byte(word(value) * value * value);
}

constexpr std::uint8_t xor_shifts(std::uint32_t value, std::uint32_t left, std::uint32_t right) {
    return byte((value << left) ^ (value >> right));
}

} // namespace file_key_detail

FileKeyNonlinearState mutate_file_key_state(const FileKeyDiffusionState& initial,
                                            std::span<const std::uint8_t, 128> tables);

using FileKeyPreparedBuffer = std::array<std::uint8_t, 255>;

FileKeyPreparedBuffer
prepare_file_key_buffer(std::span<const std::uint8_t, 20> hardware_digest,
                        std::span<const std::uint8_t> prefix,
                        std::optional<std::uint32_t> binding_word = std::nullopt);

std::vector<std::uint8_t>
prepare_file_key_input(std::span<const std::uint8_t, 20> hardware_digest,
                       std::span<const std::uint8_t> prefix,
                       std::optional<std::uint32_t> binding_word = std::nullopt);

FileKeyPreparedBuffer
assemble_file_key_md5_message(std::span<const std::uint8_t, 20> hardware_digest,
                              std::span<const std::uint8_t> prefix,
                              std::span<const std::uint8_t, 16> reduced,
                              std::optional<std::uint32_t> binding_word = std::nullopt);

FileKeyDiffusionState mix_file_key_state(FileKeyDiffusionState state, std::uint32_t steps = 1276);

FileKeyDiffusionState diffuse_file_key_input(std::span<const std::uint8_t> input);

void fold_file_key_bytes(std::span<std::uint8_t> input, std::span<const std::uint8_t> values);

void mix_file_key_input(std::span<std::uint8_t> input, std::uint32_t steps = 256);

void reduce_file_key_state(std::span<std::uint8_t> input,
                           std::span<const std::uint8_t, 319> state,
                           std::span<const std::uint8_t, 128> tables);

Md5Digest derive_state_file_tag_key(std::span<const std::uint8_t, 16> first_stage_digest);

Md5Digest derive_file_key_digest(std::span<const std::uint8_t, 20> hardware_digest,
                                 std::span<const std::uint8_t> prefix,
                                 std::optional<std::uint32_t> binding_word = std::nullopt);

struct StateBodyKeyParameters {
    AesBlock program_key;
    AesBlock input_whitening;
    AesBlock output_whitening;
};

AesBlock derive_state_file_body_key(std::span<const std::uint8_t, 16> first_stage_digest,
                                    const StateBodyKeyParameters& parameters);

Sha1Digest compute_state_file_tag(std::span<const std::uint8_t> file, const AesBlock& key);

bool verify_state_file_tag(std::span<const std::uint8_t> file, const AesBlock& key);

std::vector<std::uint8_t> decode_state_file_body(std::span<const std::uint8_t> ciphertext,
                                                 std::span<const std::uint8_t, 16> key,
                                                 std::span<const std::uint8_t, 16> iv);

std::vector<std::uint8_t> encode_state_file_body(std::span<const std::uint8_t> body,
                                                 std::span<const std::uint8_t, 16> key,
                                                 std::span<const std::uint8_t, 16> iv);

std::vector<std::uint8_t>
encode_bound_state_file(std::uint32_t version,
                        std::span<const std::uint8_t> body,
                        std::span<const std::uint8_t, 20> hardware_digest,
                        std::span<const std::uint8_t> prefix,
                        std::span<const std::uint8_t, 16> iv,
                        const StateBodyKeyParameters& body_key_parameters,
                        std::optional<std::uint32_t> binding_word = std::nullopt);

std::vector<std::uint8_t>
decode_bound_state_file(std::span<const std::uint8_t> file,
                        std::span<const std::uint8_t, 20> hardware_digest,
                        const StateBodyKeyParameters& body_key_parameters,
                        std::optional<std::uint32_t> binding_word = std::nullopt);

struct StateSeedCipherParameters {
    AesBlock key;
    AesBlock iv;
};

std::array<std::uint8_t, 32> decode_state_seed(std::span<const std::uint8_t, 32> ciphertext,
                                               const StateSeedCipherParameters& parameters);

using OtpHashes = std::array<std::array<std::uint8_t, 32>, 3>;

AesBlock compute_otp_mac(const OtpHashes& hashes, std::span<const std::uint8_t, 16> device_key);

struct LinearByteMap {
    std::array<std::uint8_t, 8> basis;

    std::uint8_t apply(std::uint8_t value) const {
        std::uint8_t result{};
        for (std::size_t bit = 0; bit < basis.size(); ++bit) {
            if ((value & (1U << bit)) != 0) {
                result ^= basis[bit];
            }
        }
        return result;
    }
};

struct SecondaryCipherParameters {
    AesBlock key;
    AesBlock iv;
    AesBlock whitening;
    std::array<LinearByteMap, 4> output_maps;
};

std::vector<std::uint8_t> decode_store_secondary(std::span<const std::uint8_t> input,
                                                 const SecondaryCipherParameters& parameters);

struct MatrixColumn {
    std::size_t source_byte;
    std::uint8_t row_mask;
    LinearByteMap column_map;
};

struct MatrixCodec {
    std::uint8_t offset;
    std::array<std::uint8_t, 8> basis_offset;
    std::array<MatrixColumn, 8> columns;
};

struct AffineByteMap {
    std::uint8_t offset;
    LinearByteMap linear;

    std::uint8_t apply(std::uint8_t value) const {
        return offset ^ linear.apply(value);
    }
};

std::array<AffineByteMap, 8> decode_store_byte_maps(std::span<const std::uint8_t, 64> parameters);

AesBlock decode_store_device_key(std::span<const std::uint8_t, 272> secondary);

using ArithmeticHashState = std::array<std::uint32_t, 8>;

ArithmeticHashState arithmetic_hash_round(const ArithmeticHashState& state,
                                          std::uint32_t message_word,
                                          std::uint32_t round_constant);

std::uint32_t arithmetic_hash_schedule_word(std::uint32_t oldest,
                                            std::uint32_t previous_fifteen,
                                            std::uint32_t previous_seven,
                                            std::uint32_t previous_two);

ArithmeticHashState arithmetic_hash_compress(const ArithmeticHashState& initial,
                                             std::span<const std::uint8_t, 64> block);

std::array<std::uint8_t, 32> arithmetic_hash(std::span<const std::uint8_t> message);

std::array<std::uint8_t, 64> expand_arithmetic_digest(std::span<const std::uint8_t, 32> digest);

std::array<std::uint8_t, 55> store_counter_message(std::span<const std::uint8_t, 32> seed,
                                                   std::uint32_t counter);

struct StoreHashMaterial {
    std::array<std::uint8_t, 32> seed_hash;
    std::array<std::uint8_t, 32> expanded_hash;
    std::array<std::uint8_t, 32> counter_hash;
};

StoreHashMaterial derive_store_hash_material(std::span<const std::uint8_t, 32> seed,
                                             std::uint32_t counter);

AesBlock generate_store_otp(std::span<const std::uint8_t, 32> seed,
                            std::uint32_t counter,
                            std::span<const std::uint8_t, 16> device_key);

struct StateStoreParameters {
    StateBodyKeyParameters body_key;
    StateBodySchemaParameters schema;
    StateSeedCipherParameters seed_cipher;
    SecondaryCipherParameters secondary_cipher;
};

using GsaKeyState = std::array<std::uint8_t, 208>;

GsaKeyState mix_gsa_key_state(std::span<const std::uint8_t, 208> input);

struct GsaMixedKeyParameters {
    // Each byte uses one direct source followed by two sources in a shared
    // linear encoding. These offsets address the mixed 208-byte key state.
    std::array<std::array<std::uint8_t, 3>, 16> sources;
    AesBlock offsets;
    LinearByteMap mapped_sources;
};

AesBlock decode_gsa_final_round_key(std::span<const std::uint8_t, 208> mixed_state,
                                    const GsaMixedKeyParameters& parameters);

AesBlock decode_gsa_device_key_from_mixed_state(std::span<const std::uint8_t, 208> mixed_state,
                                                const GsaMixedKeyParameters& parameters);

std::vector<std::uint8_t> decode_gsa_secondary(std::span<const std::uint8_t> ciphertext,
                                               const SecondaryCipherParameters& parameters);

struct GsaKeyParameters {
    SecondaryCipherParameters secondary_cipher;
    GsaMixedKeyParameters mixed_key;
};

AesBlock decode_gsa_device_key(std::span<const std::uint8_t, 208> opaque_state,
                               const GsaKeyParameters& parameters);

AesBlock decode_mac_device_key(std::span<const std::uint8_t, 400> opaque_state);
AesBlock decode_android_device_key(std::span<const std::uint8_t, 384> opaque_state);
AesBlock generate_android_otp(std::span<const std::uint8_t, 32> seed,
                              std::uint32_t counter,
                              std::span<const std::uint8_t, 16> device_key);
AesBlock generate_mac_otp(std::span<const std::uint8_t, 32> seed,
                          std::uint32_t counter,
                          std::span<const std::uint8_t, 16> device_key);

using GsaHashState = std::array<std::uint32_t, 8>;

using GsaHashDigest = std::array<std::uint8_t, 32>;

GsaHashState
gsa_hash_round(const GsaHashState& state, std::uint32_t message, std::uint32_t constant);

std::uint32_t gsa_hash_schedule_word(std::uint32_t oldest,
                                     std::uint32_t previous_fifteen,
                                     std::uint32_t previous_seven,
                                     std::uint32_t previous_two);

GsaHashState gsa_hash_compress(const GsaHashState& initial,
                               std::span<const std::uint8_t, 64> block);

GsaHashDigest gsa_hash(std::span<const std::uint8_t> message);

struct GsaHashMaterial {
    GsaHashDigest seed_hash;
    GsaHashDigest expanded_hash;
    GsaHashDigest counter_hash;
};

GsaHashMaterial derive_gsa_hash_material(std::span<const std::uint8_t, 32> seed,
                                         std::uint32_t counter);

struct StateGsaHashParameters {
    StateBodyKeyParameters body_key;
    StateBodySchemaParameters schema;
    StateSeedCipherParameters seed_cipher;
};

AesBlock generate_gsa_otp(std::span<const std::uint8_t, 32> seed,
                          std::uint32_t counter,
                          std::span<const std::uint8_t, 16> device_key);

std::optional<std::uint32_t> state_file_profile_hash(std::string_view name);

inline constexpr std::uint32_t native_state_binding(std::uint32_t profile_hash) {
    return profile_hash + 0x6D50370CU;
}

struct StateGsaParameters {
    StateBodyKeyParameters body_key;
    StateBodySchemaParameters schema;
    StateSeedCipherParameters seed_cipher;
    GsaKeyParameters key;
};

struct ProvisioningResponseKeyParameters {
    std::array<MatrixCodec, 4> input_matrix_codecs;
    std::array<LinearByteMap, 4> encoded_key_maps;
    std::array<LinearByteMap, 4> decoded_key_maps;
    std::array<std::uint8_t, 176> round_key_masks;
};

LinearByteMap invert_provisioning_byte_map(const LinearByteMap& map);

std::array<LinearByteMap, 4>
decode_provisioning_response_input_matrices(std::span<const std::uint8_t, 64> encoded,
                                            const ProvisioningResponseKeyParameters& parameters);

Aes128Schedule
decode_provisioning_response_round_keys(std::span<const std::uint8_t, 240> material,
                                        const ProvisioningResponseKeyParameters& parameters);

AesBlock decode_provisioning_response_key(std::span<const std::uint8_t, 240> material,
                                          const ProvisioningResponseKeyParameters& parameters);

struct ProvisioningSpimParameters {
    AesBlock key;
    AesBlock iv;
};

std::array<std::uint8_t, 240>
decode_provisioning_spim_material(std::span<const std::uint8_t, 240> ciphertext,
                                  const ProvisioningSpimParameters& parameters);

struct ProvisioningEndParameters {
    ProvisioningSpimParameters spim;
    ProvisioningResponseKeyParameters response_key;
    AesBlock key_derivation_key;
};

AesBlock derive_provisioning_end_payload_key(std::span<const std::uint8_t, 240> spim_ciphertext,
                                             std::span<const std::uint8_t, 16> trust_key,
                                             const ProvisioningEndParameters& parameters);

std::array<std::uint8_t, 256>
decrypt_provisioning_end_payload(std::span<const std::uint8_t, 256> ciphertext,
                                 std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 16> iv);

std::array<std::uint8_t, 256>
decrypt_provisioning_end_payload_from_spim(std::span<const std::uint8_t, 240> spim_ciphertext,
                                           std::span<const std::uint8_t, 256> ciphertext,
                                           std::span<const std::uint8_t, 16> trust_key,
                                           std::span<const std::uint8_t, 16> iv,
                                           const ProvisioningEndParameters& parameters);

struct ProvisioningEndPacketParameters {
    ProvisioningEndParameters payload;
    AesBlock authentication_key;
};

std::uint32_t read_provisioning_end_word(std::span<const std::uint8_t, 4> bytes);

Sha1Digest transform_provisioning_end_digest(Sha1Digest digest, const AesBlock& key);

bool has_provisioning_end_packet_format(std::span<const std::uint8_t> packet);

Sha1Digest compute_provisioning_end_packet_tag(std::span<const std::uint8_t> packet,
                                               const AesBlock& key);

bool verify_provisioning_end_packet(std::span<const std::uint8_t> packet, const AesBlock& key);

std::vector<std::uint8_t>
decrypt_authenticated_provisioning_end_packet(std::span<const std::uint8_t, 240> spim_ciphertext,
                                              std::span<const std::uint8_t> packet,
                                              std::span<const std::uint8_t, 16> trust_key,
                                              const ProvisioningEndPacketParameters& parameters);

struct ProvisioningBodyEntropy {
    std::array<std::uint8_t, 32> session_random;
    std::array<std::uint8_t, 20> first_nonce;
    std::array<std::uint8_t, 20> second_nonce;
    std::array<std::uint8_t, 12> padding;
};

std::array<std::uint8_t, 160>
make_provisioning_body(std::span<const std::uint8_t, 32> encrypted_material,
                       std::span<const std::uint8_t, 20> device_tag,
                       const ProvisioningBodyEntropy& entropy,
                       std::int64_t dsid,
                       std::uint32_t unix_seconds,
                       std::uint32_t platform = 2);

struct ProvisioningCipherParameters {
    AesBlock key;
    AesBlock iv;
    AesBlock input_mask;
};

std::array<std::uint8_t, 32>
encrypt_provisioning_input(std::span<const std::uint8_t, 32> input,
                           const ProvisioningCipherParameters& parameters);

std::array<std::uint8_t, 276>
assemble_provisioning_cpim(std::span<const std::uint8_t, 16> nonce,
                           std::span<const std::uint8_t, 192> response,
                           std::span<const std::uint8_t, 60> echoed_server_field);

AesBlock decrypt_provisioning_digest_parameter(std::span<const std::uint8_t, 16> ciphertext,
                                               std::span<const std::uint8_t, 16> key);

struct ProvisioningDigestByteCodec {
    std::uint8_t shift;
    std::uint8_t offset;
    LinearByteMap linear;
};

struct ProvisioningDigestParameters {
    AesBlock key;
    std::array<std::uint8_t, 16> input_positions;
    std::array<std::uint8_t, 16> output_positions;
    std::array<ProvisioningDigestByteCodec, 16> input_codecs;
    std::array<ProvisioningDigestByteCodec, 16> output_codecs;
};

struct HardwareInputs {
    std::optional<std::uint32_t> volume_serial;
    std::optional<std::span<const std::uint8_t>> bios;
    std::optional<std::span<const std::uint8_t>> processor;
};

Sha1Digest hash_hardware_inputs(const HardwareInputs& inputs);

namespace provisioning_mixer_detail {

constexpr std::uint8_t byte(std::uint32_t value) {
    return static_cast<std::uint8_t>(value);
}

constexpr std::uint32_t word(std::uint32_t value) {
    return value;
}

constexpr std::uint8_t cube_byte(std::uint8_t value) {
    return byte(word(value) * value * value);
}

constexpr std::uint8_t xor_shifts(std::uint32_t value, std::uint32_t left, std::uint32_t right) {
    return byte((value << left) ^ (value >> right));
}

void adjust_hardware_mixer(std::array<std::uint8_t, 384>& state,
                           std::span<std::uint8_t> output,
                           std::span<const std::uint8_t, 128> parameters);

} // namespace provisioning_mixer_detail

std::vector<std::uint8_t>
mix_provisioning_hardware_seed(std::span<const std::uint8_t> input,
                               std::span<const std::uint8_t, 128> parameters);

namespace provisioning_seed_detail {

using provisioning_mixer_detail::byte;

using provisioning_mixer_detail::cube_byte;

using provisioning_mixer_detail::word;

using provisioning_mixer_detail::xor_shifts;

void adjust_hardware_seed(std::array<std::uint8_t, 384>& state,
                          std::span<std::uint8_t> output,
                          std::span<const std::uint8_t, 128> parameters);

} // namespace provisioning_seed_detail

std::vector<std::uint8_t>
make_provisioning_hardware_seed(std::span<const std::uint8_t, 20> hardware_hash,
                                std::span<const std::uint8_t, 128> parameters);

Sha1Digest make_provisioning_hardware_digest(std::span<const std::uint8_t, 20> hardware_hash,
                                             std::span<const std::uint8_t, 256> parameters);

Sha1Digest make_provisioning_hardware_digest(const HardwareInputs& hardware,
                                             std::span<const std::uint8_t, 256> parameters);

Sha1Digest make_provisioning_hardware_tag(std::span<const std::uint8_t, 20> hardware_hash,
                                          std::span<const std::uint8_t, 272> parameters);

Sha1Digest make_provisioning_hardware_tag(const HardwareInputs& hardware,
                                          std::span<const std::uint8_t, 272> parameters);

Sha256Digest provisioning_payload_digest(std::span<const std::uint8_t, 160> ciphertext,
                                         std::span<const std::uint8_t, 16> parameter,
                                         std::span<const std::uint8_t, 24> suffix);

std::array<std::uint8_t, 192>
make_provisioning_payload(std::span<const std::uint8_t, 160> ciphertext,
                          std::span<const std::uint8_t, 16> parameter,
                          std::span<const std::uint8_t, 24> suffix);

struct ProvisioningResponseParameters {
    ProvisioningSpimParameters spim;
    ProvisioningResponseKeyParameters key;
    std::array<std::uint8_t, 24> hash_suffix;
};

std::array<std::uint8_t, 160>
encrypt_provisioning_response_body(std::span<const std::uint8_t, 160> plaintext,
                                   std::span<const std::uint8_t, 16> key,
                                   std::span<const std::uint8_t, 16> nonce);

std::array<std::uint8_t, 192>
encrypt_provisioning_response(std::span<const std::uint8_t, 160> plaintext,
                              std::span<const std::uint8_t, 16> key,
                              std::span<const std::uint8_t, 16> nonce,
                              std::span<const std::uint8_t, 16> parameter,
                              std::span<const std::uint8_t, 24> suffix);

std::array<std::uint8_t, 192>
make_provisioning_response_from_spim(std::span<const std::uint8_t, 240> spim_ciphertext,
                                     std::span<const std::uint8_t, 160> plaintext,
                                     std::span<const std::uint8_t, 16> nonce,
                                     std::span<const std::uint8_t, 16> parameter,
                                     const ProvisioningResponseParameters& parameters);

struct ProvisioningSelectorSourceParameters {
    AesBlock key;
    AesBlock iv;
};

struct ProvisioningSelectorEntropy {
    std::array<std::uint8_t, 32> bytes;
    std::size_t consumed;
};

ProvisioningSelectorEntropy
take_provisioning_selector_entropy(std::span<const std::uint8_t> random_bytes);

std::array<std::uint8_t, 32>
make_provisioning_selector_input(std::span<const std::uint8_t, 32> random_bytes,
                                 const ProvisioningSelectorSourceParameters& parameters,
                                 std::span<const std::uint8_t, 16> selector_input_mask);

struct ProvisioningChallengeFields {
    std::span<const std::uint8_t, 240> encrypted_material;
    std::span<const std::uint8_t, 16> encrypted_digest_parameter;
    std::span<const std::uint8_t, 60> echoed_server_field;
};

struct ProvisioningStartParameters {
    ProvisioningResponseParameters response;
    AesBlock digest_key;
};

struct ProvisioningRequestParameters {
    ProvisioningCipherParameters selector;
    std::array<std::uint8_t, 272> hardware;
    ProvisioningStartParameters response;
};

ProvisioningChallengeFields read_provisioning_challenge_fields(std::span<const std::uint8_t> spim);

std::array<std::uint8_t, 276> make_provisioning_cpim(std::span<const std::uint8_t> spim,
                                                     std::span<const std::uint8_t, 160> body,
                                                     std::span<const std::uint8_t, 16> nonce,
                                                     const ProvisioningStartParameters& parameters);

std::array<std::uint8_t, 160>
make_provisioning_start_body(std::span<const std::uint8_t, 32> selector_input,
                             std::span<const std::uint8_t, 20> hardware_hash,
                             const ProvisioningBodyEntropy& entropy,
                             std::int64_t dsid,
                             std::uint32_t unix_seconds,
                             const ProvisioningRequestParameters& parameters,
                             std::uint32_t platform = 2);

struct ProvisioningProfileStart {
    std::array<std::uint8_t, 276> packet;
    std::array<std::uint8_t, 160> body;
};

bool verify_provisioning_profile_challenge(std::span<const std::uint8_t> spim,
                                           const AesBlock& authentication_key);

ProvisioningProfileStart
begin_provisioning_profile(std::span<const std::uint8_t> spim,
                           std::span<const std::uint8_t> selector_random,
                           std::span<const std::uint8_t, 20> hardware_hash,
                           const ProvisioningBodyEntropy& entropy,
                           std::uint32_t unix_seconds,
                           std::span<const std::uint8_t, 16> nonce,
                           const ProvisioningSelectorSourceParameters& source_parameters,
                           const ProvisioningRequestParameters& request_parameters,
                           const AesBlock& authentication_key,
                           std::uint32_t platform = 2);

StateBody make_provisioned_profile(std::span<const std::uint8_t, 160> start_body,
                                   std::span<const std::uint8_t> payload);

StateBody finish_provisioning_profile(std::span<const std::uint8_t> spim,
                                      std::span<const std::uint8_t, 160> start_body,
                                      std::span<const std::uint8_t> ptm,
                                      std::span<const std::uint8_t, 16> trust_key,
                                      const ProvisioningEndPacketParameters& parameters);

namespace parameters {

const ProvisioningRequestParameters& request();
ProvisioningSelectorSourceParameters selector_source();
const ProvisioningEndPacketParameters& end();
const StateGsaParameters& state();
const StateStoreParameters& store();

} // namespace parameters
} // namespace apple_auth::detail
