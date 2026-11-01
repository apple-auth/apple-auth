#include "archive/internal.hpp"

namespace apple_auth::archivedetail {
namespace {
std::uint32_t be32(View v, std::size_t p) {
    require(p <= v.size() && v.size() - p >= 4, "Truncated big-endian field");
    return std::uint32_t(v[p]) << 24 | std::uint32_t(v[p + 1]) << 16 |
           std::uint32_t(v[p + 2]) << 8 | v[p + 3];
}

std::uint32_t le32(View v, std::size_t p) {
    require(p <= v.size() && v.size() - p >= 4, "Truncated little-endian field");
    return std::uint32_t(v[p + 3]) << 24 | std::uint32_t(v[p + 2]) << 16 |
           std::uint32_t(v[p + 1]) << 8 | v[p];
}

std::uint64_t be64(View v, std::size_t p) {
    return std::uint64_t(be32(v, p)) << 32 | be32(v, p + 4);
}

View slice(View v, std::size_t p, std::size_t n) {
    require(p <= v.size() && n <= v.size() - p, "Mach-O field exceeds file");
    return v.subspan(p, n);
}

void ids(View data, std::vector<std::uint32_t>& out, unsigned depth) {
    require(depth < 3, "Nested FAT Mach-O is unsupported");
    if (data.size() < 4) {
        return;
    }
    auto magic = be32(data, 0);
    if (magic == 0xcafebabe || magic == 0xcafebabf) {
        auto count = be32(data, 4);
        std::size_t width = magic == 0xcafebabf ? 32 : 20;
        require(count > 0 && count <= 32, "Invalid FAT architecture count");
        slice(data, 8, count * width);
        for (unsigned i = 0; i < count; ++i) {
            auto p = 8 + i * width;
            auto offset = width == 32 ? be64(data, p + 8) : be32(data, p + 8);
            auto size = width == 32 ? be64(data, p + 16) : be32(data, p + 12);
            require(offset >= 8 + count * width, "FAT slice overlaps header");
            ids(slice(data, offset, size), out, depth + 1);
        }
        return;
    }
    auto m = le32(data, 0);
    if (m != 0xfeedfacf && m != 0xfeedface) {
        return;
    }
    auto commands = le32(data, 16);
    std::size_t header = m == 0xfeedfacf ? 32 : 28, end = header + le32(data, 20), pos = header;
    require(end <= data.size() && commands <= 10000, "Invalid Mach-O commands");
    for (unsigned i = 0; i < commands; ++i) {
        require(pos <= end && end - pos >= 8, "Truncated Mach-O command");
        auto cmd = le32(data, pos), size = le32(data, pos + 4);
        require(size >= 8 && size <= end - pos, "Invalid Mach-O command size");
        if (cmd == 0x21 || cmd == 0x2c) {
            require(size >= (cmd == 0x2c ? 24u : 20u), "Truncated encryption command");
            out.push_back(le32(data, pos + 16));
        }
        pos += size;
    }
}
} // namespace

std::vector<std::uint32_t> encryption_ids(View data) {
    std::vector<std::uint32_t> out;
    ids(data, out, 0);
    return out;
}

} // namespace apple_auth::archivedetail
