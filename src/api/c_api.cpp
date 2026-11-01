#include <apple_auth/c_api.h>
#include <apple_auth/core.hpp>
#include <apple_auth/srp.hpp>
#include "crypto/backend.hpp"

#include <algorithm>
#include <cstring>
#include <new>

using namespace apple_auth;

struct aauth_profile {
    Profile value;
};

struct aauth_provisioning {
    ProvisioningSession value;
};

struct aauth_srp {
    SrpHandshake value;
    explicit aauth_srp(Bytes secret) : value(std::move(secret)) {}
};

struct aauth_srp_proof {
    SrpHandshake::Proof value;
};

namespace {
thread_local std::array<char, 512> last_error{};

void set_error(const char* message) noexcept {
    const auto size = std::min(std::strlen(message), last_error.size() - 1);
    std::copy_n(message, size, last_error.begin());
    last_error[size] = '\0';
}

void require(bool valid) {
    if (!valid) {
        throw Error(ErrorCode::invalid_argument, "Null pointer or inconsistent buffer length");
    }
}

template <class Function> aauth_status guard(Function&& function) noexcept {
    try {
        last_error[0] = '\0';
        function();
        return AAUTH_OK;
    } catch (const Error& error) {
        set_error(error.what());
        return static_cast<aauth_status>(error.code());
    } catch (const std::exception& error) {
        set_error(error.what());
        return AAUTH_INTERNAL_ERROR;
    } catch (...) {
        set_error("Unknown library failure");
        return AAUTH_INTERNAL_ERROR;
    }
}

template <std::size_t Size> std::array<std::uint8_t, Size> fixed(const std::uint8_t* input) {
    require(input != nullptr);
    std::array<std::uint8_t, Size> result{};
    std::copy_n(input, Size, result.begin());
    return result;
}

ByteView view(const std::uint8_t* input, std::size_t size) {
    require(input != nullptr || size == 0);
    return {input, size};
}

void copy(ByteView value,
          std::uint8_t* output,
          std::size_t capacity,
          std::size_t* written = nullptr) {
    require(output != nullptr || capacity == 0);
    if (written) {
        *written = value.size();
    }
    if (output == nullptr && written) {
        return;
    }
    require(output != nullptr);
    if (capacity < value.size()) {
        throw Error(ErrorCode::buffer_too_small, "Output buffer is too small");
    }
    std::copy(value.begin(), value.end(), output);
}
} // namespace

extern "C" {
aauth_status aauth_srp_create(const std::uint8_t* secret, std::size_t size, aauth_srp** output) {
    return guard([&] {
        require(output && size <= 32);
        const auto supplied = view(secret, size);
        auto result = std::make_unique<aauth_srp>(Bytes(supplied.begin(), supplied.end()));
        *output = result.release();
    });
}

void aauth_srp_free(aauth_srp* session) { delete session; }
void aauth_srp_proof_free(aauth_srp_proof* proof) { delete proof; }

aauth_status aauth_srp_public_key(const aauth_srp* session, std::uint8_t* output,
                                  std::size_t capacity, std::size_t* written) {
    return guard([&] {
        require(session && written);
        copy(session->value.public_key(), output, capacity, written);
    });
}

aauth_status aauth_srp_complete(const aauth_srp* session, const char* user, const char* password,
                                const std::uint8_t* salt, std::size_t salt_size,
                                const std::uint8_t* server, std::size_t server_size,
                                int iterations, const char* protocol, aauth_srp_proof** output) {
    return guard([&] {
        require(session && user && password && protocol && output && salt_size <= 1024 &&
                server_size <= 257);
        auto proof = session->value.complete(user, password, view(salt, salt_size),
                                             view(server, server_size), iterations, protocol);
        auto result = std::make_unique<aauth_srp_proof>(proof);
        *output = result.release();
    });
}

aauth_status aauth_srp_client_proof(const aauth_srp_proof* proof, std::uint8_t* output,
                                    std::size_t capacity, std::size_t* written) {
    return guard([&] {
        require(proof && written);
        copy(proof->value.m1, output, capacity, written);
    });
}

aauth_status aauth_srp_verify_session(const aauth_srp_proof* proof,
                                      const std::uint8_t* server_proof, std::size_t proof_size,
                                      const std::uint8_t* encrypted, std::size_t encrypted_size,
                                      std::uint8_t* output, std::size_t capacity, std::size_t* written) {
    return guard([&] {
        require(proof && written && proof_size == 32 && encrypted_size <= 16 * 1024 * 1024);
        auto clear = proof->value.decrypt_session(view(server_proof, proof_size),
                                                  view(encrypted, encrypted_size));
        struct Cleanup {
            Bytes& value;
            ~Cleanup() { crypto::wipe(value.data(), value.size()); }
        } cleanup{clear};
        copy(clear, output, capacity, written);
    });
}

const char* aauth_last_error(void) {
    return last_error.data();
}

const char* aauth_version(void) {
    return version();
}

aauth_status aauth_local_hardware_id(std::uint8_t* output, std::size_t capacity) {
    return guard([&] {
        copy(local_hardware_id(), output, capacity);
    });
}

aauth_status aauth_time_counter(std::int64_t seconds, std::uint32_t* output) {
    return guard([&] {
        require(output != nullptr);
        const auto value = time_counter(seconds);
        *output = value;
    });
}

aauth_status aauth_profile_import(const std::uint8_t* file,
                                  std::size_t size,
                                  const std::uint8_t* hardware,
                                  const char* filename,
                                  aauth_profile** output) {
    return guard([&] {
        require(output != nullptr && filename != nullptr);
        auto result = std::make_unique<aauth_profile>(
            aauth_profile{Profile::import_file(view(file, size), fixed<20>(hardware), filename)});
        *output = result.release();
    });
}

void aauth_profile_free(aauth_profile* profile) {
    delete profile;
}

aauth_status aauth_profile_kind(const aauth_profile* profile, int* output) {
    return guard([&] {
        require(profile != nullptr && output != nullptr);
        *output = static_cast<int>(profile->value.kind());
    });
}

aauth_status
aauth_profile_machine_id(const aauth_profile* profile, std::uint8_t* output, std::size_t capacity) {
    return guard([&] {
        require(profile != nullptr);
        copy(profile->value.machine_id(), output, capacity);
    });
}

aauth_status aauth_profile_otp(const aauth_profile* profile,
                               std::uint32_t counter,
                               std::uint8_t* output,
                               std::size_t capacity) {
    return guard([&] {
        require(profile != nullptr);
        copy(profile->value.otp(counter), output, capacity);
    });
}

aauth_status aauth_profile_export(const aauth_profile* profile,
                                  const std::uint8_t* hardware,
                                  const char* filename,
                                  std::uint32_t version,
                                  const std::uint8_t* prefix,
                                  std::size_t prefix_size,
                                  const std::uint8_t* iv,
                                  std::uint8_t* output,
                                  std::size_t capacity,
                                  std::size_t* written) {
    return guard([&] {
        require(profile != nullptr && filename != nullptr && written != nullptr);
        const auto bytes = view(prefix, prefix_size);
        FileEncoding encoding{version, Bytes(bytes.begin(), bytes.end()), fixed<16>(iv)};
        const auto value = profile->value.export_file(fixed<20>(hardware), filename, encoding);
        copy(value, output, capacity, written);
    });
}

aauth_status aauth_provisioning_begin(const std::uint8_t* challenge,
                                      std::size_t size,
                                      const std::uint8_t* hardware,
                                      std::uint32_t seconds,
                                      const std::uint8_t* selector,
                                      std::size_t selector_size,
                                      const std::uint8_t* body,
                                      const std::uint8_t* nonce,
                                      aauth_provisioning** output) {
    return guard([&] {
        require(output != nullptr);
        ProvisioningEntropy entropy;
        if (!selector && !body && !nonce) {
            require(selector_size == 0);
            entropy = ProvisioningEntropy::random();
        } else {
            require(selector && body && nonce);
            const auto selected = view(selector, selector_size);
            entropy.selector.assign(selected.begin(), selected.end());
            entropy.body = fixed<84>(body);
            entropy.nonce = fixed<16>(nonce);
        }
        auto result = std::make_unique<aauth_provisioning>(aauth_provisioning{
            ProvisioningSession(view(challenge, size), fixed<20>(hardware), seconds, entropy)});
        *output = result.release();
    });
}

aauth_status aauth_provisioning_request(const aauth_provisioning* session,
                                        std::uint8_t* output,
                                        std::size_t capacity,
                                        std::size_t* written) {
    return guard([&] {
        require(session != nullptr && written != nullptr);
        copy(session->value.request(), output, capacity, written);
    });
}

aauth_status aauth_provisioning_finish(aauth_provisioning* session,
                                       const std::uint8_t* ptm,
                                       std::size_t size,
                                       const std::uint8_t* trust,
                                       aauth_profile** output) {
    return guard([&] {
        require(session != nullptr && output != nullptr);
        // Allocate the handle before consuming the session, preserving retry on allocation failure.
        auto result = std::unique_ptr<aauth_profile>(
            new aauth_profile{session->value.finish(view(ptm, size), fixed<16>(trust))});
        *output = result.release();
    });
}

void aauth_provisioning_free(aauth_provisioning* session) {
    delete session;
}
} // extern "C"
