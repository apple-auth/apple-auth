#include "adi/internal.hpp"
#include "crypto/backend.hpp"

#include <climits>
#include <fstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace apple_auth {
namespace {

Bytes random_bytes(std::size_t size, bool nonzero = false) {
    if (size > INT_MAX) {
        throw Error(ErrorCode::invalid_argument, "Random buffer is too large");
    }
    Bytes result(size);
    crypto::random(result);
    if (nonzero) {
        for (auto& byte : result) {
            while (byte == 0) {
                crypto::random(std::span(&byte, 1));
            }
        }
    }
    return result;
}

template <class Operation> auto checked(Operation&& operation) {
    try {
        return operation();
    } catch (const std::invalid_argument& error) {
        throw Error(ErrorCode::invalid_data, error.what());
    }
}

std::optional<std::uint32_t> binding(std::string_view filename) {
    const auto hash = detail::state_file_profile_hash(filename);
    return hash ? std::optional(detail::native_state_binding(*hash)) : std::nullopt;
}

#ifdef _WIN32
std::optional<Bytes> registry_value(const char* path, const char* name) {
    HKEY raw = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &raw) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    struct RegistryKey {
        HKEY value;

        ~RegistryKey() {
            RegCloseKey(value);
        }
    } key{raw};

    DWORD size = 0;
    if (RegQueryValueExA(raw, name, nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    Bytes value(std::max<DWORD>(size, 1));
    if (RegQueryValueExA(raw, name, nullptr, nullptr, value.data(), &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    value.resize(size);
    return value;
}
#endif
} // namespace

Error::Error(ErrorCode code, std::string message)
    : std::runtime_error(std::move(message)), code_(code) {}

ErrorCode Error::code() const noexcept {
    return code_;
}

const char* version() noexcept {
    return "0.1.0";
}

HardwareId hardware_id(const HardwareFields& fields) {
    return detail::hash_hardware_inputs({fields.volume_serial, fields.bios, fields.processor});
}

HardwareId local_hardware_id() {
#ifdef _WIN32
    HardwareFields fields;
    DWORD serial = 0;
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        fields.volume_serial = serial;
    }
    const auto bios = registry_value("HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion");
    const auto cpu =
        registry_value("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
    if (bios) {
        fields.bios = *bios;
    }
    if (cpu) {
        fields.processor = *cpu;
    }
    return hardware_id(fields);
#else
    constexpr std::string_view binding_domain = "apple-auth:hardware:v1:";
    Bytes material(binding_domain.begin(), binding_domain.end());
    for (const char* path : {"/etc/machine-id",
                             "/sys/class/dmi/id/product_uuid",
                             "/sys/class/dmi/id/board_serial",
                             "/sys/class/dmi/id/bios_version",
                             "/etc/hostid"}) {
        std::ifstream input(path, std::ios::binary);
        std::array<char, 4096> field{};
        if (input) {
            input.read(field.data(), field.size());
            const auto size = input.gcount();
            if (size > 0) {
                material.insert(material.end(), path, path + std::char_traits<char>::length(path));
                material.push_back(0);
                material.insert(material.end(), field.begin(), field.begin() + size);
                material.push_back(0);
            }
        }
    }
    if (material.size() == binding_domain.size()) {
        const auto fallback = random_bytes(32);
        material.insert(material.end(), fallback.begin(), fallback.end());
    }
    return detail::sha1(material);
#endif
}

std::uint32_t time_counter(std::int64_t seconds) {
    if (seconds < 0 || static_cast<std::uint64_t>(seconds / 30) > UINT32_MAX) {
        throw Error(ErrorCode::invalid_argument, "Time is outside the supported OTP counter range");
    }
    return static_cast<std::uint32_t>(seconds / 30);
}

std::string base64(ByteView value) {
    if (value.size() > INT_MAX) {
        throw Error(ErrorCode::invalid_argument, "Base64 input is too large");
    }
    if (value.empty()) {
        return {};
    }
    std::string output(4 * ((value.size() + 2) / 3) + 1, '\0');
    std::size_t written = 0;
    crypto::check(mbedtls_base64_encode(reinterpret_cast<unsigned char*>(output.data()),
                                        output.size(),
                                        &written,
                                        value.data(),
                                        value.size()),
                  "Base64 encoding failed");
    output.resize(written);
    return output;
}

FileEncoding FileEncoding::random() {
    FileEncoding result;
    result.prefix = random_bytes(32);
    const auto iv = random_bytes(16);
    std::copy(iv.begin(), iv.end(), result.iv.begin());
    return result;
}

struct Profile::Impl {
    detail::StateBody state;
    std::array<std::uint8_t, 32> seed{};
    Block key{};

    explicit Impl(detail::StateBody value) : state(std::move(value)) {
        seed = detail::decode_state_seed(state.encrypted_seed,
                                         detail::parameters::state().seed_cipher);
        if (state.profile == UINT64_MAX - 1) {
            if (state.secondary.size() == 400) {
                key = detail::decode_mac_device_key(
                    std::span<const std::uint8_t, 400>(state.secondary.data(), 400));
            } else if (state.secondary.size() == 384) {
                key = detail::decode_android_device_key(
                    std::span<const std::uint8_t, 384>(state.secondary.data(), 384));
            } else {
                key = detail::decode_gsa_device_key(
                    std::span<const std::uint8_t, 208>(state.secondary.data(), 208),
                    detail::parameters::state().key);
            }
        } else {
            const auto decoded = detail::decode_store_secondary(
                state.secondary, detail::parameters::store().secondary_cipher);
            key = detail::decode_store_device_key(
                std::span<const std::uint8_t, 272>(decoded.data(), 272));
        }
    }

    ~Impl() {
        crypto::wipe(seed.data(), seed.size());
        crypto::wipe(key.data(), key.size());
    }
};

Profile::Profile(std::shared_ptr<const Impl> impl) : impl_(std::move(impl)) {}

Profile Profile::import_file(ByteView file, const HardwareId& hardware, std::string_view name) {
    return checked([&] {
        const auto body = detail::decode_bound_state_file(
            file, hardware, detail::parameters::state().body_key, binding(name));
        return Profile(std::make_shared<Impl>(
            detail::parse_state_body(body, detail::parameters::state().schema)));
    });
}

ProfileKind Profile::kind() const noexcept {
    return impl_->state.profile == UINT64_MAX ? ProfileKind::store : ProfileKind::grandslam;
}

ProfilePlatform Profile::platform() const noexcept {
    switch (impl_->state.secondary.size()) {
    case 400:
        return ProfilePlatform::mac;
    case 384:
        return ProfilePlatform::android;
    default:
        return ProfilePlatform::windows;
    }
}

MachineId Profile::machine_id() const noexcept {
    return impl_->state.profile_data;
}

Block Profile::otp(std::uint32_t counter) const {
    if (platform() == ProfilePlatform::mac) {
        return detail::generate_mac_otp(impl_->seed, counter, impl_->key);
    }
    if (platform() == ProfilePlatform::android) {
        return detail::generate_android_otp(impl_->seed, counter, impl_->key);
    }
    return kind() == ProfileKind::grandslam
               ? detail::generate_gsa_otp(impl_->seed, counter, impl_->key)
               : detail::generate_store_otp(impl_->seed, counter, impl_->key);
}

Bytes Profile::otp_envelope(std::uint32_t counter) const {
    // Store uses format version 4 without a GrandSlam ADI platform trailer.
    Bytes result = {
        0, 0, 0, kind() == ProfileKind::grandslam ? std::uint8_t(5) : std::uint8_t(4), 0, 0, 0, 16};
    const auto payload = otp(counter);
    result.insert(result.end(), payload.begin(), payload.end());
    if (kind() == ProfileKind::grandslam) {
        result.insert(result.end(), {0, 0, 0, static_cast<std::uint8_t>(platform())});
    }
    return result;
}

std::string Profile::otp_header(std::uint32_t counter) const {
    return base64(otp_envelope(counter));
}

std::string Profile::machine_id_header() const {
    return base64(machine_id());
}

std::string_view Profile::filename() const noexcept {
    return "adi.pb";
}

Bytes Profile::export_file(const HardwareId& hardware,
                           std::string_view name,
                           const FileEncoding& encoding) const {
    return checked([&] {
        const auto& schema = detail::parameters::state().schema;
        // The observed record sizes leave either zero or four alignment bytes.
        const std::size_t size = 12 + 8 + 60 + impl_->state.secondary.size() + 32 + 8 + 5 * 8 +
                                 (impl_->state.option ? 12 : 0);
        const Bytes padding((16 - size % 16) % 16, 0);
        const auto body = detail::serialize_state_body(impl_->state, schema, padding);
        return detail::encode_bound_state_file(encoding.version,
                                               body,
                                               hardware,
                                               encoding.prefix,
                                               encoding.iv,
                                               detail::parameters::state().body_key,
                                               binding(name));
    });
}

ProvisioningEntropy ProvisioningEntropy::random() {
    ProvisioningEntropy result;
    result.selector = random_bytes(32, true);
    const auto body = random_bytes(result.body.size(), true);
    const auto nonce = random_bytes(result.nonce.size(), true);
    std::copy(body.begin(), body.end(), result.body.begin());
    std::copy(nonce.begin(), nonce.end(), result.nonce.begin());
    return result;
}

struct ProvisioningSession::Impl {
    Bytes challenge;
    detail::ProvisioningProfileStart start;
    Bytes store_packet;
    bool finished = false;
};

ProvisioningSession::ProvisioningSession(ByteView challenge,
                                         const HardwareId& hardware,
                                         std::uint32_t seconds,
                                         const ProvisioningEntropy& entropy)
    : ProvisioningSession(challenge, hardware, seconds, ProfilePlatform::windows, entropy) {}

ProvisioningSession::ProvisioningSession(ByteView challenge,
                                         const HardwareId& hardware,
                                         std::uint32_t seconds,
                                         ProfilePlatform platform,
                                         const ProvisioningEntropy& entropy)
    : impl_(std::make_unique<Impl>()) {
    checked([&] {
        detail::ProvisioningBodyEntropy body{};
        std::copy_n(entropy.body.begin(), 32, body.session_random.begin());
        std::copy_n(entropy.body.begin() + 32, 20, body.first_nonce.begin());
        std::copy_n(entropy.body.begin() + 52, 20, body.second_nonce.begin());
        std::copy_n(entropy.body.begin() + 72, 12, body.padding.begin());
        impl_->start =
            detail::begin_provisioning_profile(challenge,
                                               entropy.selector,
                                               hardware,
                                               body,
                                               seconds,
                                               entropy.nonce,
                                               detail::parameters::selector_source(),
                                               detail::parameters::request(),
                                               detail::parameters::end().authentication_key,
                                               static_cast<std::uint32_t>(platform));
        impl_->challenge.assign(challenge.begin(), challenge.end());
    });
}

ProvisioningSession::ProvisioningSession(ByteView challenge,
                                         const HardwareId& hardware,
                                         std::uint32_t seconds,
                                         ProfileKind kind,
                                         const ProvisioningEntropy& entropy)
    : ProvisioningSession(challenge, hardware, seconds, ProfilePlatform::windows, entropy) {
    if (kind == ProfileKind::grandslam) {
        return;
    }
    if (kind != ProfileKind::store) {
        throw Error(ErrorCode::invalid_argument, "Unsupported profile kind");
    }
    checked([&] {
        const auto& parameters = detail::parameters::request();
        const auto selected = detail::take_provisioning_selector_entropy(entropy.selector);
        const auto selector = detail::make_provisioning_selector_input(
            selected.bytes, detail::parameters::selector_source(), parameters.selector.input_mask);
        detail::ProvisioningBodyEntropy body_entropy{};
        std::copy_n(entropy.body.begin(), 32, body_entropy.session_random.begin());
        std::copy_n(entropy.body.begin() + 32, 20, body_entropy.first_nonce.begin());
        std::copy_n(entropy.body.begin() + 52, 20, body_entropy.second_nonce.begin());
        std::copy_n(entropy.body.begin() + 72, 12, body_entropy.padding.begin());
        impl_->start.body = detail::make_provisioning_start_body(
            selector, hardware, body_entropy, -1, seconds, parameters, 2);
        const auto& response = parameters.response;
        const auto fields = detail::read_provisioning_challenge_fields(challenge);
        const auto material = detail::decode_provisioning_spim_material(fields.encrypted_material,
                                                                        response.response.spim);
        const auto key = detail::decode_provisioning_response_key(material, response.response.key);
        const auto schedule = detail::expand_aes128_key(key);
        Bytes cipher(144);
        auto previous = entropy.nonce;
        for (unsigned offset = 0; offset < 144; offset += 16) {
            for (unsigned byte = 0; byte < 16; ++byte) {
                previous[byte] ^= impl_->start.body[offset + byte];
            }
            previous = detail::encrypt_aes128_block(previous, schedule);
            std::copy(previous.begin(), previous.end(), cipher.begin() + offset);
        }
        const auto parameter = detail::decrypt_provisioning_digest_parameter(
            fields.encrypted_digest_parameter, response.digest_key);
        Bytes signed_data = cipher;
        signed_data.insert(signed_data.end(), parameter.begin(), parameter.end());
        signed_data.insert(signed_data.end(),
                           response.response.hash_suffix.begin(),
                           response.response.hash_suffix.end());
        const auto tag = detail::sha256(signed_data);
        auto& packet = impl_->store_packet;
        packet.resize(260);
        packet[3] = 4; // Store CPIM format version, separate from an ADI platform ID.
        std::copy(entropy.nonce.begin(), entropy.nonce.end(), packet.begin() + 4);
        packet[23] = 144;
        std::copy(cipher.begin(), cipher.end(), packet.begin() + 24);
        std::copy(tag.begin(), tag.end(), packet.begin() + 168);
        std::copy(fields.echoed_server_field.begin(),
                  fields.echoed_server_field.end(),
                  packet.begin() + 200);
    });
}

ProvisioningSession::~ProvisioningSession() = default;
ProvisioningSession::ProvisioningSession(ProvisioningSession&&) noexcept = default;
ProvisioningSession& ProvisioningSession::operator=(ProvisioningSession&&) noexcept = default;

ByteView ProvisioningSession::request() const noexcept {
    return !impl_                         ? ByteView{}
           : !impl_->store_packet.empty() ? ByteView(impl_->store_packet)
                                          : ByteView(impl_->start.packet);
}

Profile ProvisioningSession::finish(ByteView ptm, const Block& trust_key) {
    if (!impl_ || impl_->finished) {
        throw Error(ErrorCode::invalid_argument,
                    "Provisioning session is already completed or moved");
    }
    return checked([&] {
        auto body = detail::finish_provisioning_profile(
            impl_->challenge, impl_->start.body, ptm, trust_key, detail::parameters::end());
        Profile profile(std::make_shared<Profile::Impl>(std::move(body)));
        impl_->finished = true;
        return profile;
    });
}

} // namespace apple_auth
