#include "crypto/protocol.hpp"
#include "store/kbsync/fresh.hpp"
#include "store/transport.hpp"
#include <apple_auth/store_core.hpp>

namespace apple_auth {

Bytes generate_kbsync(std::uint64_t dsid, ByteView hardware, ByteView entropy) {
    crypto::require(dsid && (hardware.size() == 6 || hardware.size() == 20),
                    "kbSync requires nonzero DSID and hardware6 or hardware20");
    auto owned = entropy.empty() ? crypto::random_bytes(1024) : Bytes{};

    struct Cleanup {
        Bytes& bytes;

        ~Cleanup() {
            crypto::wipe(bytes.data(), bytes.size());
        }
    } cleanup{owned};

    const auto packet = detail::kbsync::generate_packet(
        dsid, hardware, entropy.empty() ? ByteView(owned) : entropy);
    crypto::require(packet.has_value(), "kbSync entropy exhausted");
    return {packet->bytes.begin(), packet->bytes.end()};
}

namespace {
struct TransportParameters {
    Block key{}, iv{};

    ~TransportParameters() {
        crypto::wipe(key.data(), key.size());
        crypto::wipe(iv.data(), iv.size());
    }
};
} // namespace

struct TestFlightTransport::Impl : TransportParameters {};

struct AppStoreMacTransport::Impl : TransportParameters {};

TestFlightTransport::TestFlightTransport(ByteView hardware, ByteView dp_info)
    : impl_(std::make_unique<Impl>()) {
    crypto::require(hardware.size() == 20 && dp_info.size() == 88,
                    "Transport requires hardware20 and dpInfo88");
    auto parameters = detail::store_transport::derive_parameters(
        std::span<const std::uint8_t, 20>(hardware.data(), 20),
        std::span<const std::uint8_t, 88>(dp_info.data(), 88));
    impl_->key = parameters.key;
    impl_->iv = parameters.iv;
    crypto::wipe(&parameters, sizeof(parameters));
}

TestFlightTransport::~TestFlightTransport() = default;
TestFlightTransport::TestFlightTransport(TestFlightTransport&&) noexcept = default;
TestFlightTransport& TestFlightTransport::operator=(TestFlightTransport&&) noexcept = default;

namespace {
void decrypt_transport_chunk(const TransportParameters* parameters, std::span<std::uint8_t> data) {
    crypto::require(parameters && !data.empty() && data.size() <= 32768, "Invalid transport chunk");
    std::array<std::uint8_t, 7168> packed{};
    std::size_t length = 0;
    for (std::size_t offset = 0; offset < data.size(); offset += 512) {
        const auto count = std::min<std::size_t>(112, data.size() - offset);
        std::copy_n(data.begin() + offset, count, packed.begin() + length);
        length += count;
    }
    const auto complete = length / 16 * 16;
    if (complete) {
        auto plain = crypto::aes_cbc(
            ByteView(packed).first(complete), parameters->key, parameters->iv, true, false);
        std::copy(plain.begin(), plain.end(), packed.begin());
        crypto::wipe(plain.data(), plain.size());
    }
    std::size_t position = 0;
    for (std::size_t offset = 0; offset < data.size(); offset += 512) {
        const auto count = std::min<std::size_t>(112, data.size() - offset);
        std::copy_n(packed.begin() + position, count, data.begin() + offset);
        position += count;
    }
    crypto::wipe(packed.data(), packed.size());
}
} // namespace

void TestFlightTransport::decrypt_chunk(std::span<std::uint8_t> data) const {
    decrypt_transport_chunk(impl_.get(), data);
}

AppStoreMacTransport::AppStoreMacTransport(ByteView hardware, ByteView dp_info)
    : impl_(std::make_unique<Impl>()) {
    crypto::require(hardware.size() == 6 && dp_info.size() == 88,
                    "Mac transport requires hardware6 and dpInfo88");
    crypto::require(dp_info[0] == 0 && dp_info[1] == 0 && dp_info[2] == 0 && dp_info[3] == 3,
                    "Unsupported Mac transport dpInfo version");
    auto parameters = detail::store_transport::derive_mac_store_parameters(
        std::span<const std::uint8_t, 6>(hardware.data(), 6),
        std::span<const std::uint8_t, 88>(dp_info.data(), 88));
    impl_->key = parameters.key;
    impl_->iv = parameters.iv;
    crypto::wipe(&parameters, sizeof(parameters));
}

AppStoreMacTransport::~AppStoreMacTransport() = default;
AppStoreMacTransport::AppStoreMacTransport(AppStoreMacTransport&&) noexcept = default;
AppStoreMacTransport& AppStoreMacTransport::operator=(AppStoreMacTransport&&) noexcept = default;

void AppStoreMacTransport::decrypt_chunk(std::span<std::uint8_t> data) const {
    decrypt_transport_chunk(impl_.get(), data);
}
} // namespace apple_auth
