#pragma once
#include <apple_auth/core.hpp>

namespace apple_auth::detail::sap {
struct CertificateParameters {
    std::array<std::uint8_t, 256> modulus;
    std::array<std::uint8_t, 8> identifier;
};

CertificateParameters certificate_parameters(ByteView container);
std::array<std::uint8_t, 256> rsa_public(ByteView encoded, ByteView modulus);
} // namespace apple_auth::detail::sap
