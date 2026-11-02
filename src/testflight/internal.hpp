#pragma once
#include "archive/internal.hpp"
#include <apple_auth/testflight.hpp>
#include <set>

namespace apple_auth::tfdetail {
using namespace netdetail;
using archivedetail::normalize_ipa;
using netdetail::bytes;
using netdetail::digest;
using netdetail::Error;
using netdetail::hex;
using netdetail::parse_plist;
using netdetail::random_bytes;
using netdetail::require;
using netdetail::str;
using netdetail::unhex;
using netdetail::write_private;

using archivedetail::read_file;

Json create_session(const Json& context,
                    const Transport& transport,
                    const TestFlightOptions& options = {});

class Engine {
  public:
    Engine(const Json& context, Transport transport, TestFlightOptions options = {});
    Json catalog();
    Json install_metadata(const std::string& bundle);

    const Bytes& hardware() const {
        return hardware_;
    }

  private:
    Json request(unsigned version, const std::string& resource, const Json* body = nullptr);
    std::string find_app(const std::string& bundle);
    std::string latest_build(const std::string& app);
    std::string account_, session_, dsid_;
    std::string device_name_;
    std::uint64_t numeric_dsid_{};
    Bytes hardware_;
    Headers headers_;
    Transport transport_;
};

std::uint64_t
unwrap_transport(const Path& source, const Path& destination, View hardware20, View dp_info88);
TestFlightDownload
download_testflight_ipa(Engine& client, const std::string& bundle, const Path& destination,
                        bool include_sinf);
} // namespace apple_auth::tfdetail
