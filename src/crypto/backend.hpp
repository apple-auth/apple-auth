#pragma once

#include <algorithm>
#include <apple_auth/core.hpp>
#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform_util.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <memory>

namespace apple_auth::crypto {

inline void check(int status, const char* message) {
    if (status != 0) {
        throw Error(ErrorCode::internal, message);
    }
}

template <class T, auto Initialize, auto Release> class Context {
  public:
    Context() {
        Initialize(&value_);
    }

    ~Context() {
        Release(&value_);
    }

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    T* get() noexcept {
        return &value_;
    }

  private:
    T value_{};
};

inline void wipe(void* data, std::size_t size) noexcept {
    if (size != 0) {
        mbedtls_platform_zeroize(data, size);
    }
}

inline bool equal(ByteView left, ByteView right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }
    volatile unsigned difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference = difference | (left[index] ^ right[index]);
    }
    return difference == 0;
}

inline void random(std::span<std::uint8_t> output) {
    struct Generator {
        Context<mbedtls_entropy_context, mbedtls_entropy_init, mbedtls_entropy_free> entropy;
        Context<mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free> drbg;
#ifndef _WIN32
        pid_t process = getpid();
#endif

        Generator() {
            constexpr unsigned char label[] = "apple-auth";
            check(mbedtls_ctr_drbg_seed(
                      drbg.get(), mbedtls_entropy_func, entropy.get(), label, sizeof(label) - 1),
                  "Secure random initialization failed");
        }
    };

    thread_local Generator generator;
#ifndef _WIN32
    // Reseed after fork to avoid reusing the parent's random stream.
    if (generator.process != getpid()) {
        check(mbedtls_ctr_drbg_reseed(generator.drbg.get(), nullptr, 0),
              "Secure random reseeding failed");
        generator.process = getpid();
    }
#endif
    while (!output.empty()) {
        const auto count = std::min<std::size_t>(output.size(), MBEDTLS_CTR_DRBG_MAX_REQUEST);
        check(mbedtls_ctr_drbg_random(generator.drbg.get(), output.data(), count),
              "Secure random generation failed");
        output = output.subspan(count);
    }
}

inline Bytes digest(mbedtls_md_type_t algorithm, ByteView input) {
    const auto* info = mbedtls_md_info_from_type(algorithm);
    if (!info) {
        throw Error(ErrorCode::internal, "Digest algorithm is unavailable");
    }
    Bytes output(mbedtls_md_get_size(info));
    check(mbedtls_md(info, input.data(), input.size(), output.data()), "Digest computation failed");
    return output;
}

class Number {
    struct Deleter {
        void operator()(mbedtls_mpi* value) const noexcept {
            mbedtls_mpi_free(value);
            delete value;
        }
    };

    std::unique_ptr<mbedtls_mpi, Deleter> value_;

  public:
    Number() : value_(new mbedtls_mpi{}) {
        mbedtls_mpi_init(get());
    }

    explicit Number(ByteView encoded) : Number() {
        check(mbedtls_mpi_read_binary(get(), encoded.data(), encoded.size()),
              "Integer decoding failed");
    }

    explicit Number(int value) : Number() {
        check(mbedtls_mpi_lset(get(), value), "Integer initialization failed");
    }

    mbedtls_mpi* get() const noexcept {
        return value_.get();
    }

    bool zero() const noexcept {
        return mbedtls_mpi_cmp_int(get(), 0) == 0;
    }

    Bytes encode(std::size_t width = 0) const {
        Bytes output(width == 0 ? std::max<std::size_t>(1, mbedtls_mpi_size(get())) : width);
        check(mbedtls_mpi_write_binary(get(), output.data(), output.size()),
              "Integer encoding failed");
        return output;
    }
};

inline void
power(Number& result, const Number& base, const Number& exponent, const Number& modulus) {
    check(mbedtls_mpi_exp_mod(result.get(), base.get(), exponent.get(), modulus.get(), nullptr),
          "Modular exponentiation failed");
}

} // namespace apple_auth::crypto
