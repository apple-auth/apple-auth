#include "sap/data/session.hpp"
#include "adi/internal.hpp"
#include "crypto/backend.hpp"
#include "sap/certificate.hpp"
#include "sap/initial.hpp"
#include "sap/macos_certificate.hpp"
#include "sap/session_blob.hpp"
#include "sap/session_material.hpp"
#include "sap/signing.hpp"

namespace apple_auth {
namespace {
using namespace detail::sap;

template <class Operation> auto sap_checked(Operation&& operation) {
    try {
        return operation();
    } catch (const std::invalid_argument& error) {
        throw Error(ErrorCode::invalid_data, error.what());
    }
}

MacKeyParameters mac_parameters() {
    MacKeyParameters result{};
    auto cursor = decoder_constants.begin() + 48;
    auto take = [&](auto& target) {
        std::copy_n(cursor, target.size(), target.begin());
        cursor += target.size();
    };
    take(result.word_bias);
    for (auto& round : result.rounds) {
        for (auto& columns : round.word_columns) {
            take(columns);
        }
        for (auto& columns : round.pair_columns) {
            take(columns);
        }
        take(round.constant);
    }
    return result;
}

void secure_random(std::span<std::uint8_t> value) {
    crypto::random(value);
}
} // namespace

struct SapSession::Impl {
    Bytes request, profile, blob, certificate;
    Block loader{}, setup_nonce{}, mac{};
    std::uint32_t device_type = 66;

    ~Impl() {
        crypto::wipe(loader.data(), loader.size());
        crypto::wipe(setup_nonce.data(), setup_nonce.size());
        crypto::wipe(mac.data(), mac.size());
        crypto::wipe(profile.data(), profile.size());
        crypto::wipe(blob.data(), blob.size());
        crypto::wipe(certificate.data(), certificate.size());
    }
};

SapEntropy SapEntropy::random() {
    SapEntropy result;
    secure_random(result.initial);
    secure_random(result.profile);
    secure_random(result.certificate);
    for (auto& byte : result.certificate) {
        while (byte == 0) {
            secure_random(std::span<std::uint8_t>(&byte, 1));
        }
    }
    return result;
}

SapSession::SapSession(ByteView certificate, const SapEntropy& entropy)
    : SapSession(certificate, SapPlatform::android, entropy) {}

SapSession::SapSession(ByteView certificate, SapPlatform platform, const SapEntropy& entropy)
    : impl_(std::make_unique<Impl>()) {
    sap_checked([&] {
        if (platform != SapPlatform::android && platform != SapPlatform::macos) {
            throw std::invalid_argument("Unsupported SAP platform");
        }
        impl_->device_type = static_cast<std::uint32_t>(platform);
        const auto profile_certificate = platform == SapPlatform::macos
                                             ? make_macos_profile_certificate(entropy.certificate)
                                             : make_profile_certificate();
        impl_->certificate.assign(profile_certificate.begin(), profile_certificate.end());
        const auto parsed = certificate_parameters(certificate);
        const auto data = ByteView(entropy.initial);
        std::copy_n(data.begin() + 56, 16, impl_->loader.begin());
        std::copy_n(data.begin() + 72, 16, impl_->setup_nonce.begin());
        impl_->profile = make_profile_info(entropy.profile);
        const auto oaep = encode_initial_oaep(data.first(36), data.subspan(36, 20));
        const auto rsa = rsa_public(oaep, parsed.modulus);
        const auto ciphertext = encrypt_initial_payload(impl_->loader,
                                                        impl_->setup_nonce,
                                                        payload_padding,
                                                        data.first(16),
                                                        data.subspan(88, 16),
                                                        impl_->device_type);
        const auto packet = assemble_initial_request(
            parsed.identifier, rsa, data.subspan(88, 16), ciphertext, data.subspan(16, 20));
        impl_->request.assign(packet.begin(), packet.end());
    });
}

SapSession::~SapSession() = default;
SapSession::SapSession(SapSession&&) noexcept = default;
SapSession& SapSession::operator=(SapSession&&) noexcept = default;

ByteView SapSession::request() const noexcept {
    return impl_ ? ByteView(impl_->request) : ByteView{};
}

bool SapSession::ready() const noexcept {
    return impl_ && !impl_->blob.empty();
}

void SapSession::finish(ByteView reply) {
    if (!impl_ || ready()) {
        throw Error(ErrorCode::invalid_argument, "SAP session is already completed or moved");
    }
    sap_checked([&] {
        if (reply.size() != 1428 || reply[0] != 2 || reply[17] != 0 || reply[18] != 0 ||
            reply[19] != 4 || reply[20] != 0xe0) {
            throw std::invalid_argument("Unsupported SAP setup reply framing");
        }
        KeyMaterialParameters loader{};
        loader.key = impl_->loader;
        std::copy_n(reply.begin() + 1, 16, loader.iv.begin());
        std::copy_n(decoder_constants.begin(), 16, loader.input_mask.begin());
        std::copy_n(decoder_constants.begin() + 16, 16, loader.output_mask.begin());
        Block mask{};
        std::copy_n(decoder_constants.begin() + 32, 16, mask.begin());
        const auto keys = decode_session_keys(reply.subspan(21, 1248),
                                              loader,
                                              mask,
                                              mac_parameters(),
                                              ByteView(decoder_constants).subspan(596),
                                              impl_->setup_nonce);
        auto blob = make_session_blob(impl_->certificate,
                                      impl_->profile,
                                      keys.profile,
                                      reply.subspan(1269),
                                      impl_->device_type);
        impl_->mac = keys.mac;
        impl_->blob = std::move(blob);
        crypto::wipe(impl_->loader.data(), impl_->loader.size());
        crypto::wipe(impl_->setup_nonce.data(), impl_->setup_nonce.size());
    });
}

Bytes SapSession::sign(ByteView body) const {
    Block nonce{};
    secure_random(nonce);
    return sign(body, nonce);
}

Bytes SapSession::sign(ByteView body, const Block& nonce) const {
    if (!ready()) {
        throw Error(ErrorCode::invalid_argument, "SAP session is not established");
    }
    return sap_checked([&] {
        return sign_request(impl_->mac, nonce, impl_->blob, body);
    });
}
} // namespace apple_auth
