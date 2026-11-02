#pragma once

#include "client/client_internal.hpp"

namespace apple_auth::archivedetail {
using namespace netdetail;
using netdetail::Error;

struct IpaArchiveInfo {
    std::string bundle;
    std::size_t members{}, encrypted_images{}, clear_images{};
};

inline Bytes read_file(const Path& path, std::size_t limit = 1ull << 31) {
    return netdetail::read_file(path, limit);
}

std::vector<std::uint32_t> encryption_ids(View data);
std::vector<Bytes> sinf_records(const Json& encoded);
IpaArchiveInfo
normalize_ipa(const Path& source, const Path& destination, const std::string& expected_bundle = {},
              const std::vector<Bytes>& sinfs = {});
} // namespace apple_auth::archivedetail
