#pragma once
#include "entropy.hpp"

namespace apple_auth::detail::kbsync {

using ContextSample = NonzeroSample<12>;

inline std::optional<ContextSample> sample_context(std::span<const std::uint8_t> entropy) {
    return sample_nonzero<12>(entropy);
}

} // namespace apple_auth::detail::kbsync
