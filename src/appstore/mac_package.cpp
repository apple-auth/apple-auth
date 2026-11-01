#include "appstore/internal.hpp"
#include "crypto/backend.hpp"
#include <apple_auth/store_core.hpp>
#include <charconv>
#include <fstream>
#include <zlib.h>

namespace apple_auth {
namespace {
using namespace netdetail;

// Bounded XML reader for XAR integrity metadata. Text/attributes are retained
// literally; no DTD, entity expansion, filesystem access or extraction is used.
struct Element {
    std::string name, text;
    std::map<std::string, std::string> attributes;
    std::vector<Element> children;

    const Element& child(const std::string& key) const {
        const Element* result = nullptr;
        for (const auto& value : children) {
            if (value.name == key) {
                require(!result, "Duplicate XAR metadata element");
                result = &value;
            }
        }
        require(result != nullptr, "Missing XAR metadata element");
        return *result;
    }
};

class TocReader {
  public:
    explicit TocReader(std::string_view text) : text_(text) {}

    Element document() {
        misc();
        auto result = element(0);
        misc();
        require(position_ == text_.size(), "Trailing XAR XML data");
        return result;
    }

  private:
    std::string_view text_;
    std::size_t position_ = 0, nodes_ = 0;

    bool at(std::string_view value) const {
        return text_.substr(position_).starts_with(value);
    }

    void take(std::string_view value) {
        require(at(value), "Malformed XAR XML");
        position_ += value.size();
    }

    void space() {
        while (position_ < text_.size() &&
               std::string_view(" \t\r\n").find(text_[position_]) != std::string_view::npos) {
            ++position_;
        }
    }

    void misc() {
        for (;;) {
            space();
            const auto end_marker = at("<?") ? "?>" : at("<!--") ? "-->" : "";
            if (!*end_marker) {
                return;
            }
            const auto end = text_.find(end_marker, position_ + 2);
            require(end != std::string_view::npos, "Unterminated XAR XML comment");
            position_ = end + std::char_traits<char>::length(end_marker);
        }
    }

    std::string name() {
        const auto start = position_;
        while (position_ < text_.size()) {
            const auto c = text_[position_];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '-' || c == ':' || c == '.')) {
                break;
            }
            ++position_;
        }
        require(position_ != start, "Invalid XAR XML name");
        return std::string(text_.substr(start, position_ - start));
    }

    Element element(unsigned depth) {
        require(depth <= 64 && ++nodes_ <= 100000, "XAR XML exceeds limits");
        take("<");
        Element result;
        result.name = name();
        for (;;) {
            space();
            if (at("/>")) {
                take("/>");
                return result;
            }
            if (at(">")) {
                take(">");
                break;
            }
            auto key = name();
            space();
            take("=");
            space();
            require(position_ < text_.size() &&
                        (text_[position_] == '\'' || text_[position_] == '"'),
                    "Invalid XAR XML attribute");
            const auto quote = text_[position_++];
            const auto end = text_.find(quote, position_);
            require(end != std::string_view::npos, "Unterminated XAR XML attribute");
            require(result.attributes.emplace(key, text_.substr(position_, end - position_)).second,
                    "Duplicate XAR XML attribute");
            position_ = end + 1;
        }
        while (!at("</")) {
            require(position_ < text_.size(), "Unterminated XAR XML element");
            if (at("<!--") || at("<?")) {
                misc();
                continue;
            }
            if (at("<")) {
                result.children.push_back(element(depth + 1));
            } else {
                const auto end = text_.find('<', position_);
                require(end != std::string_view::npos, "Unterminated XAR XML text");
                result.text.append(text_.substr(position_, end - position_));
                position_ = end;
            }
        }
        take("</");
        require(name() == result.name, "Mismatched XAR XML element");
        space();
        take(">");
        return result;
    }
};

std::string_view trimmed(std::string_view value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) {
        return {};
    }
    return value.substr(begin, value.find_last_not_of(" \t\r\n") - begin + 1);
}

std::uint64_t number(const Element& parent, const std::string& key) {
    const auto text = trimmed(parent.child(key).text);
    require(!text.empty(), "Empty XAR numeric metadata");
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    require(error == std::errc() && end == text.data() + text.size(),
            "Invalid XAR numeric metadata");
    return value;
}

mbedtls_md_type_t hash_type(const Element& element) {
    const auto found = element.attributes.find("style");
    require(found != element.attributes.end(), "Missing XAR checksum algorithm");
    if (found->second == "sha1") {
        return MBEDTLS_MD_SHA1;
    }
    if (found->second == "md5") {
        return MBEDTLS_MD_MD5;
    }
    if (found->second == "sha256") {
        return MBEDTLS_MD_SHA256;
    }
    throw netdetail::Error("Unsupported XAR checksum algorithm");
}

Bytes range_digest(std::ifstream& input,
                   std::uint64_t offset,
                   std::uint64_t count,
                   mbedtls_md_type_t type) {
    crypto::Context<mbedtls_md_context_t, mbedtls_md_init, mbedtls_md_free> hash;
    const auto* info = mbedtls_md_info_from_type(type);
    require(info != nullptr, "XAR digest unavailable");
    crypto::check(mbedtls_md_setup(hash.get(), info, 0), "XAR digest setup failed");
    crypto::check(mbedtls_md_starts(hash.get()), "XAR digest start failed");
    input.clear();
    input.seekg(static_cast<std::streamoff>(offset));
    require(bool(input), "Cannot seek XAR package");
    std::array<unsigned char, 65536> buffer{};
    while (count) {
        const auto length = static_cast<std::size_t>(std::min<std::uint64_t>(count, buffer.size()));
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(length));
        require(input.gcount() == static_cast<std::streamsize>(length), "Truncated XAR package");
        crypto::check(mbedtls_md_update(hash.get(), buffer.data(), length),
                      "XAR digest update failed");
        count -= length;
    }
    Bytes result(mbedtls_md_get_size(info));
    crypto::check(mbedtls_md_finish(hash.get(), result.data()), "XAR digest finish failed");
    return result;
}

std::uint64_t big_endian(View bytes) {
    std::uint64_t result = 0;
    for (const auto byte : bytes) {
        result = (result << 8) | byte;
    }
    return result;
}
} // namespace

namespace appstoredetail {
AppStoreMacPackageInfo inspect_mac_package(const Path& source) {
    const auto size = std::filesystem::file_size(source);
    require(size >= 28 && size <= (1ull << 34), "Invalid Mac package size");
    std::ifstream input(source, std::ios::binary);
    std::array<std::uint8_t, 28> header{};
    input.read(reinterpret_cast<char*>(header.data()), header.size());
    require(bool(input) && std::equal(header.begin(), header.begin() + 4, "xar!"),
            "Mac transport metadata does not produce XAR");
    const View view(header);
    const auto header_size = big_endian(view.subspan(4, 2));
    const auto compressed_size = big_endian(view.subspan(8, 8));
    const auto clear_size = big_endian(view.subspan(16, 8));
    const auto algorithm = big_endian(view.subspan(24, 4));
    require(header_size >= 28 && header_size <= size && big_endian(view.subspan(6, 2)) == 1 &&
                compressed_size && clear_size && compressed_size <= 16 * 1024 * 1024 &&
                clear_size <= 16 * 1024 * 1024 && compressed_size <= size - header_size,
            "Unsupported XAR header or TOC size");
    const auto heap = header_size + compressed_size;
    input.seekg(static_cast<std::streamoff>(header_size));
    Bytes compressed(static_cast<std::size_t>(compressed_size)),
        clear(static_cast<std::size_t>(clear_size));
    input.read(reinterpret_cast<char*>(compressed.data()),
               static_cast<std::streamsize>(compressed.size()));
    require(bool(input), "Truncated XAR TOC");
    uLongf clear_length = static_cast<uLongf>(clear.size());
    uLong compressed_length = static_cast<uLong>(compressed.size());
    require(uncompress2(clear.data(), &clear_length, compressed.data(), &compressed_length) ==
                    Z_OK &&
                clear_length == clear.size() && compressed_length == compressed.size(),
            "Invalid compressed XAR TOC");
    const auto root = TocReader(str(clear)).document();
    require(root.name == "xar", "Invalid XAR TOC root");
    const auto& toc = root.child("toc");
    const auto& checksum = toc.child("checksum");
    const auto type = hash_type(checksum);
    require((algorithm == 1 && type == MBEDTLS_MD_SHA1) ||
                (algorithm == 2 && type == MBEDTLS_MD_MD5) ||
                (algorithm == 3 && type == MBEDTLS_MD_SHA256),
            "Inconsistent XAR TOC checksum algorithm");
    const auto offset = number(checksum, "offset"), length = number(checksum, "size");
    require(offset <= size - heap && length <= size - heap - offset &&
                length == mbedtls_md_get_size(mbedtls_md_info_from_type(type)),
            "Invalid XAR TOC checksum range");
    Bytes expected(static_cast<std::size_t>(length));
    input.seekg(static_cast<std::streamoff>(heap + offset));
    input.read(reinterpret_cast<char*>(expected.data()), static_cast<std::streamsize>(length));
    require(bool(input) && expected == range_digest(input, header_size, compressed_size, type),
            "XAR TOC checksum mismatch");
    std::uint64_t members = 0;
    bool payload = false, package_info = false;
    const auto visit = [&](const auto& self, const Element& element) -> void {
        if (element.name == "file") {
            for (const auto& data : element.children) {
                if (data.name != "data") {
                    continue;
                }
                const auto start = number(data, "offset"), count = number(data, "length");
                require(start <= size - heap && count <= size - heap - start,
                        "XAR member exceeds package bounds");
                const auto& stored = data.child("archived-checksum");
                require(hex(range_digest(input, heap + start, count, hash_type(stored))) ==
                            trimmed(stored.text),
                        "XAR member checksum mismatch");
                ++members;
                payload |= element.child("name").text == "Payload";
                package_info |= element.child("name").text == "PackageInfo";
            }
        }
        for (const auto& child : element.children) {
            self(self, child);
        }
    };
    visit(visit, toc);
    require(members && payload && package_info, "XAR does not contain a Mac installation package");
    return {size, members, hex(range_digest(input, 0, size, MBEDTLS_MD_SHA256))};
}
} // namespace appstoredetail

AppStoreMacPackageInfo unwrap_appstore_mac_package(const Path& source,
                                                   const Path& destination,
                                                   ByteView hardware,
                                                   ByteView dp_info) {
    require(!destination.empty() && !std::filesystem::exists(destination),
            "Mac package output already exists");
    require(std::filesystem::absolute(source).lexically_normal() !=
                std::filesystem::absolute(destination).lexically_normal(),
            "Mac input and output must differ");
    const AppStoreMacTransport cipher(hardware, dp_info);
    std::ifstream input(source, std::ios::binary);
    require(bool(input), "Cannot open original Mac Store asset");
    if (!destination.parent_path().empty()) {
        std::filesystem::create_directories(destination.parent_path());
    }
    const Path temporary = destination.string() + "." + hex(random_bytes(8)) + ".partial";
    try {
        std::ofstream output(temporary, std::ios::binary);
        require(bool(output), "Cannot create Mac package output");
        std::filesystem::permissions(
            temporary, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        std::array<std::uint8_t, 32768> buffer{};
        while (input.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) ||
               input.gcount()) {
            auto chunk = std::span(buffer).first(static_cast<std::size_t>(input.gcount()));
            cipher.decrypt_chunk(chunk);
            output.write(reinterpret_cast<const char*>(chunk.data()),
                         static_cast<std::streamsize>(chunk.size()));
            require(bool(output), "Cannot write Mac package");
        }
        require(input.eof(), "Cannot finish reading Mac asset");
        output.close();
        require(bool(output), "Cannot finalize Mac package");
        const auto result = appstoredetail::inspect_mac_package(temporary);
        std::filesystem::create_hard_link(temporary, destination);
        std::filesystem::remove(temporary);
        return result;
    } catch (...) {
        std::error_code error;
        std::filesystem::remove(temporary, error);
        throw;
    }
}
} // namespace apple_auth
