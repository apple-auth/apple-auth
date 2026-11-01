#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <type_traits>

namespace apple_auth::detail::data_mask {
// Storage encoding only: values are restored once before use.
class Stream {
  public:
    explicit Stream(std::uint32_t seed) noexcept : state_(seed) {}

    template <class T> void apply(T& value) noexcept {
        static_assert(std::is_unsigned_v<T>);
        value ^= static_cast<T>(next());
    }

    template <class T, std::size_t Size> void apply(std::array<T, Size>& values) noexcept {
        for (auto& value : values) {
            apply(value);
        }
    }

  private:
    std::uint32_t next() noexcept {
        auto value = state_;
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        state_ = value;
        return value;
    }

    // Runtime reads keep optimization, including LTO, from emitting decoded tables.
    volatile std::uint32_t state_;
};

// Traverse integer elements instead of their representation to preserve byte order
// on both little- and big-endian targets, including nested arrays.
template <class T> T decode(T values, std::uint32_t seed) noexcept {
    Stream stream(seed);
    stream.apply(values);
    return values;
}

// Field visitors avoid object padding and preserve mixed-width integer fields.
template <class T, class Visitor> T decode(T values, std::uint32_t seed, Visitor visit) noexcept {
    Stream stream(seed);
    visit(stream, values);
    return values;
}

// For aggregates made exclusively of byte fields, such as byte maps.
template <class T> T decode_bytes(const T& values, std::uint32_t seed) noexcept {
    static_assert(std::has_unique_object_representations_v<T>);
    auto bytes = std::bit_cast<std::array<std::uint8_t, sizeof(T)>>(values);
    return std::bit_cast<T>(decode(bytes, seed));
}
} // namespace apple_auth::detail::data_mask
