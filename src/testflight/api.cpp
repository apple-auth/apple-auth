#include "testflight/internal.hpp"

namespace apple_auth {
namespace {
using netdetail::Json;

Json parse_context(ByteView encoded) {
    netdetail::require(!encoded.empty() && encoded.size() <= 1u << 20,
                       "Invalid TestFlight context size");
    return Json::parse(encoded.begin(), encoded.end());
}

Transport selected(Transport transport) {
    return transport ? std::move(transport) : netdetail::make_curl_transport();
}
} // namespace

struct TestFlightClient::Impl {
    netdetail::Json context;
    tfdetail::Engine engine;

    Impl(netdetail::Json saved, Transport transport, TestFlightOptions options)
        : context(std::move(saved)), engine(context, std::move(transport), std::move(options)) {}
};

TestFlightClient::TestFlightClient(ByteView saved, Transport transport)
    : TestFlightClient(saved, std::move(transport), {}) {}

TestFlightClient::TestFlightClient(ByteView saved, Transport transport, TestFlightOptions options)
    : impl_(std::make_unique<Impl>(
          parse_context(saved), selected(std::move(transport)), std::move(options))) {}

TestFlightClient TestFlightClient::from_store_cookies(ByteView saved, Transport transport) {
    return from_store_cookies(saved, std::move(transport), {});
}

TestFlightClient TestFlightClient::from_store_cookies(ByteView saved,
                                                      Transport transport,
                                                      TestFlightOptions options) {
    auto effective = selected(std::move(transport));
    const auto session = tfdetail::create_session(parse_context(saved), effective, options);
    return TestFlightClient(
        netdetail::bytes(session.dump()), std::move(effective), std::move(options));
}

TestFlightClient TestFlightClient::from_store_session(const StoreSession& session,
                                                      ByteView hardware20,
                                                      Headers mac_device_headers,
                                                      Transport transport) {
    return from_store_session(
        session, hardware20, std::move(mac_device_headers), std::move(transport), {});
}

TestFlightClient TestFlightClient::from_store_session(const StoreSession& session,
                                                      ByteView hardware20,
                                                      Headers mac_device_headers,
                                                      Transport transport,
                                                      TestFlightOptions options) {
    return from_store_cookies(session.testflight_context(hardware20, std::move(mac_device_headers)),
                              std::move(transport),
                              std::move(options));
}

TestFlightClient::~TestFlightClient() = default;
TestFlightClient::TestFlightClient(TestFlightClient&&) noexcept = default;
TestFlightClient& TestFlightClient::operator=(TestFlightClient&&) noexcept = default;

Bytes TestFlightClient::serialize(std::optional<ByteView> key) const {
    netdetail::require(bool(impl_), "TestFlight client is closed");
    const auto data = netdetail::bytes(impl_->context.dump(2));
    return key ? encrypt_session(data, *key) : data;
}

TestFlightClient TestFlightClient::deserialize(ByteView data, std::optional<ByteView> key,
                                              Transport transport, TestFlightOptions options) {
    const auto clear = key ? decrypt_session(data, *key) : Bytes(data.begin(), data.end());
    return TestFlightClient(clear, std::move(transport), std::move(options));
}

TestFlightClient TestFlightClient::load(const std::filesystem::path& file, std::optional<ByteView> key,
                                       Transport transport, TestFlightOptions options) {
    return deserialize(netdetail::read_file(file, (1u << 20) + session_encryption_overhead),
                       key, std::move(transport), std::move(options));
}

void TestFlightClient::save(const std::filesystem::path& path, ByteView key) const {
    netdetail::require(impl_ && !std::filesystem::exists(path), "TestFlight session output already exists");
    netdetail::write_private(path, serialize(key));
}

void TestFlightClient::save(const std::filesystem::path& path) const {
    netdetail::require(impl_ && !std::filesystem::exists(path),
                       "TestFlight session output already exists");
    netdetail::write_private(path, netdetail::bytes(impl_->context.dump(2)));
}

Bytes TestFlightClient::catalog() {
    return netdetail::bytes(impl_->engine.catalog().dump(2));
}

Bytes TestFlightClient::install_metadata(const std::string& bundle) {
    return netdetail::bytes(impl_->engine.install_metadata(bundle).dump(2));
}

void TestFlightClient::save_catalog(const std::filesystem::path& path) {
    netdetail::require(!std::filesystem::exists(path), "TestFlight output already exists");
    netdetail::write_private(path, catalog());
}

void TestFlightClient::save_install_metadata(const std::string& bundle,
                                             const std::filesystem::path& path) {
    netdetail::require(!std::filesystem::exists(path), "TestFlight output already exists");
    netdetail::write_private(path, install_metadata(bundle));
}

TestFlightDownload TestFlightClient::download(const std::string& bundle,
                                              const std::filesystem::path& path) {
    return tfdetail::download_testflight_ipa(impl_->engine, bundle, path);
}

std::uint64_t unwrap_testflight_transport(const std::filesystem::path& input,
                                          const std::filesystem::path& output,
                                          ByteView hardware,
                                          ByteView dp_info) {
    return tfdetail::unwrap_transport(input, output, hardware, dp_info);
}

TestFlightArchiveInfo normalize_testflight_ipa(const std::filesystem::path& input,
                                               const std::filesystem::path& output,
                                               const std::string& bundle) {
    auto info = archivedetail::normalize_ipa(input, output, bundle);
    return {std::move(info.bundle), info.members, info.encrypted_images, info.clear_images};
}
} // namespace apple_auth
