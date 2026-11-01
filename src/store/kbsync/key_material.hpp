#pragma once
#include "adi/internal.hpp"
#include "key_hash.hpp"
#include "store/data/keys.hpp"

namespace apple_auth::detail::kbsync {

inline AesBlock key_material_from_hash(const Md5Digest& digest) {
    auto block = digest;
    for (std::size_t index = 0; index < block.size(); ++index) {
        block[index] ^= detail::posthash_input_mask[index];
    }
    block = encrypt_aes128_block(block, expand_aes128_key(detail::posthash_key));
    for (std::size_t index = 0; index < block.size(); ++index) {
        block[index] ^= detail::posthash_output_mask[index];
    }
    return block;
}

inline AesBlock key_material_from_body(std::uint64_t dsid,
                                       std::span<const std::uint8_t, 255> body) {
    return key_material_from_hash(key_material_hash(dsid, body));
}

} // namespace apple_auth::detail::kbsync
