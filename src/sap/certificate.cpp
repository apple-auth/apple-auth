#include "sap/certificate.hpp"
#include "crypto/backend.hpp"
#include "sap/data/certificate.hpp"
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>

namespace apple_auth::detail::sap {
namespace {
using Certificate = crypto::Context<mbedtls_x509_crt, mbedtls_x509_crt_init, mbedtls_x509_crt_free>;

int parse_sap_extension(void*,
                        const mbedtls_x509_crt*,
                        const mbedtls_x509_buf* oid,
                        int,
                        const unsigned char* begin,
                        const unsigned char* end) {
    // Apple's SAP leaf marker (1.2.840.113635.100.6.12.2) contains a DER NULL.
    const auto& marker = certificate_marker;
    if (oid->len == marker.size() && std::equal(marker.begin(), marker.end(), oid->p) &&
        end - begin == 2 && begin[0] == 0x05 && begin[1] == 0x00) {
        return 0;
    }
    return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
}

void verify_issuer(mbedtls_x509_crt* certificate, mbedtls_x509_crt* issuer) {
    auto profile = mbedtls_x509_crt_profile_default;
    // SAP certificates use SHA-1 and a separate validity policy from HTTPS.
    profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
    profile.rsa_min_bitlen = 1024;
    std::uint32_t flags = 0;
    const auto status = mbedtls_x509_crt_verify_with_profile(
        certificate,
        issuer,
        nullptr,
        &profile,
        nullptr,
        &flags,
        +[](void*, mbedtls_x509_crt*, int, std::uint32_t* errors) {
            *errors &= ~static_cast<std::uint32_t>(MBEDTLS_X509_BADCERT_EXPIRED |
                                                   MBEDTLS_X509_BADCERT_FUTURE);
            return 0;
        },
        nullptr);
    if (status != 0) {
        throw std::invalid_argument("Invalid SAP certificate chain signature");
    }
}
} // namespace

CertificateParameters certificate_parameters(ByteView data) {
    if (data.size() < 6 || data[0] != 1 || data[1] == 0 || data[1] > 8) {
        throw std::invalid_argument("Unsupported SAP certificate container");
    }
    std::vector<std::unique_ptr<Certificate>> chain;
    std::size_t offset = 2;
    for (unsigned index = 0; index < data[1]; ++index) {
        if (data.size() - offset < 4) {
            throw std::invalid_argument("Truncated certificate length");
        }
        std::uint32_t length = 0;
        for (unsigned byte = 0; byte < 4; ++byte) {
            length = (length << 8) | data[offset++];
        }
        if (length == 0 || length > data.size() - offset) {
            throw std::invalid_argument("Truncated certificate data");
        }
        auto certificate = std::make_unique<Certificate>();
        const auto parse_status = mbedtls_x509_crt_parse_der_with_ext_cb(
            certificate->get(), data.data() + offset, length, 1, parse_sap_extension, nullptr);
        if (parse_status != 0) {
            throw std::invalid_argument("Invalid DER certificate (Mbed TLS " +
                                        std::to_string(parse_status) + ")");
        }
        if (certificate->get()->raw.len != length) {
            throw std::invalid_argument("Invalid DER certificate");
        }
        if (!chain.empty()) {
            verify_issuer(certificate->get(), chain.back()->get());
        }
        chain.push_back(std::move(certificate));
        offset += length;
    }
    // The container may include protocol-specific bytes after the chain.
    auto* certificate = chain.back()->get();
    if (!mbedtls_pk_can_do(&certificate->pk, MBEDTLS_PK_RSA) || certificate->serial.len != 8) {
        throw std::invalid_argument("Unsupported SAP certificate key or identifier");
    }
    crypto::Number modulus, exponent;
    crypto::check(mbedtls_rsa_export(mbedtls_pk_rsa(certificate->pk),
                                     modulus.get(),
                                     nullptr,
                                     nullptr,
                                     nullptr,
                                     exponent.get()),
                  "Cannot read SAP public key");
    if (mbedtls_mpi_bitlen(modulus.get()) != 2048 ||
        mbedtls_mpi_cmp_int(exponent.get(), 65537) != 0) {
        throw std::invalid_argument("Unsupported SAP certificate key or identifier");
    }
    CertificateParameters result{};
    const auto encoded = modulus.encode(result.modulus.size());
    std::copy(encoded.begin(), encoded.end(), result.modulus.begin());
    std::copy_n(certificate->serial.p, result.identifier.size(), result.identifier.begin());
    return result;
}

std::array<std::uint8_t, 256> rsa_public(ByteView encoded, ByteView modulus) {
    if (encoded.size() != 256 || modulus.size() != 256 || (modulus[0] & 0x80) == 0 ||
        (modulus[255] & 1) == 0) {
        throw std::invalid_argument("Expected a 256-byte RSA block and odd 2048-bit modulus");
    }
    crypto::Number input(encoded), key(modulus), exponent(65537), result;
    if (mbedtls_mpi_cmp_mpi(input.get(), key.get()) >= 0) {
        throw std::invalid_argument("RSA input exceeds modulus");
    }
    crypto::power(result, input, exponent, key);
    const auto value = result.encode(256);
    std::array<std::uint8_t, 256> output{};
    std::copy(value.begin(), value.end(), output.begin());
    return output;
}
} // namespace apple_auth::detail::sap
