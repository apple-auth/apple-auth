#pragma once
#include "archive/internal.hpp"
#include <set>

namespace apple_auth::archivedetail::detail {

inline std::uint64_t zip_number(View bytes, std::uint64_t offset, unsigned size) {
    require(size <= 8 && offset <= bytes.size() && size <= bytes.size() - offset,
            "Truncated ZIP integer");
    std::uint64_t value = 0;
    for (unsigned i = 0; i < size; ++i) {
        value |= std::uint64_t(bytes[static_cast<std::size_t>(offset + i)]) << (8 * i);
    }
    return value;
}

// libzip rejects the Apple method99 layout before it exposes member bytes.
// Change only compression tags in a private parser view. The caller decodes
// marked members with LZFSE and verifies original uncompressed size and CRC.
inline std::set<std::uint64_t> apple_zip_parser_view(Bytes& bytes) {
    require(bytes.size() >= 22, "Truncated ZIP archive");
    const auto minimum = bytes.size() > 65557 ? bytes.size() - 65557 : 0;
    std::size_t end = bytes.size() - 22;
    for (;;) {
        if (zip_number(bytes, end, 4) == 0x06054b50 &&
            zip_number(bytes, end + 20, 2) == bytes.size() - end - 22) {
            break;
        }
        require(end > minimum, "ZIP end record was not found");
        --end;
    }
    require(zip_number(bytes, end + 4, 2) == 0 && zip_number(bytes, end + 6, 2) == 0,
            "Split ZIP archives are unsupported");
    auto count = zip_number(bytes, end + 10, 2);
    auto length = zip_number(bytes, end + 12, 4);
    auto offset = zip_number(bytes, end + 16, 4);
    require(zip_number(bytes, end + 8, 2) == count, "Split ZIP member directory");
    if (count == 65535 || length == 0xffffffff || offset == 0xffffffff) {
        require(end >= 20 && zip_number(bytes, end - 20, 4) == 0x07064b50 &&
                    zip_number(bytes, end - 16, 4) == 0 && zip_number(bytes, end - 4, 4) == 1,
                "Invalid ZIP64 locator");
        const auto position = zip_number(bytes, end - 12, 8);
        require(zip_number(bytes, position, 4) == 0x06064b50 &&
                    zip_number(bytes, position + 4, 8) >= 44 &&
                    zip_number(bytes, position + 16, 4) == 0 &&
                    zip_number(bytes, position + 20, 4) == 0,
                "Invalid ZIP64 end record");
        count = zip_number(bytes, position + 32, 8);
        require(zip_number(bytes, position + 24, 8) == count, "Split ZIP64 member directory");
        length = zip_number(bytes, position + 40, 8);
        offset = zip_number(bytes, position + 48, 8);
    }
    require(count <= 1000000 && offset <= end && length <= end - offset,
            "Invalid ZIP directory bounds");
    const auto directory_end = offset + length;
    std::set<std::uint64_t> apple;
    for (std::uint64_t index = 0; index < count; ++index) {
        require(offset <= directory_end && directory_end - offset >= 46 &&
                    zip_number(bytes, offset, 4) == 0x02014b50,
                "Invalid ZIP directory member");
        const auto name = zip_number(bytes, offset + 28, 2);
        const auto extra = zip_number(bytes, offset + 30, 2);
        const auto comment = zip_number(bytes, offset + 32, 2);
        require(name + extra + comment <= directory_end - offset - 46,
                "Truncated ZIP directory member");
        if (zip_number(bytes, offset + 10, 2) == 99) {
            auto local = zip_number(bytes, offset + 42, 4);
            if (local == 0xffffffff) {
                auto cursor = offset + 46 + name;
                const auto extra_end = cursor + extra;
                bool found = false;
                while (cursor <= extra_end && extra_end - cursor >= 4) {
                    const auto kind = zip_number(bytes, cursor, 2),
                               size = zip_number(bytes, cursor + 2, 2);
                    require(size <= extra_end - cursor - 4, "Invalid ZIP extra field");
                    if (kind == 1) {
                        auto value = cursor + 4;
                        if (zip_number(bytes, offset + 24, 4) == 0xffffffff) {
                            value += 8;
                        }
                        if (zip_number(bytes, offset + 20, 4) == 0xffffffff) {
                            value += 8;
                        }
                        require(value <= cursor + 4 + size && cursor + 4 + size - value >= 8,
                                "Missing ZIP64 member offset");
                        local = zip_number(bytes, value, 8);
                        found = true;
                        break;
                    }
                    cursor += 4 + size;
                }
                require(found, "Missing ZIP64 extra field");
            }
            require(zip_number(bytes, local, 4) == 0x04034b50 &&
                        zip_number(bytes, local + 8, 2) == 99,
                    "Inconsistent Apple ZIP local header");
            bytes[static_cast<std::size_t>(offset + 10)] = 8;
            bytes[static_cast<std::size_t>(offset + 11)] = 0;
            bytes[static_cast<std::size_t>(local + 8)] = 8;
            bytes[static_cast<std::size_t>(local + 9)] = 0;
            apple.insert(index);
        }
        offset += 46 + name + extra + comment;
    }
    return apple;
}

} // namespace apple_auth::archivedetail::detail
