#include "archive/internal.hpp"
#include "archive/zip_input.hpp"
#include <algorithm>
#include <lzfse.h>
#include <memory>
#include <set>
#include <zip.h>
#include <zlib.h>

namespace apple_auth::archivedetail {
namespace {
using Archive = std::unique_ptr<zip_t, decltype(&zip_discard)>;

Bytes read(zip_t* archive, zip_uint64_t index, bool apple_lzfse = false) {
    zip_stat_t stat{};
    require(zip_stat_index(archive, index, 0, &stat) == 0, "Cannot inspect ZIP member");
    require(stat.size <= (1ull << 31), "ZIP member exceeds supported size");
    if (apple_lzfse || stat.comp_method == 99) {
        require(stat.comp_size <= (1ull << 31), "Compressed member exceeds limit");
        std::unique_ptr<zip_file_t, decltype(&zip_fclose)> raw(
            zip_fopen_index(archive, index, ZIP_FL_COMPRESSED), zip_fclose);
        require(bool(raw), "Cannot read Apple ZIP member");
        Bytes compressed(std::size_t(stat.comp_size));
        std::size_t done = 0;
        while (done < compressed.size()) {
            auto n = zip_fread(raw.get(), compressed.data() + done, compressed.size() - done);
            require(n > 0, "Truncated Apple ZIP member");
            done += std::size_t(n);
        }
        Bytes out(std::size_t(stat.size));
        auto decoded = lzfse_decode_buffer(
            out.data(), out.size(), compressed.data(), compressed.size(), nullptr);
        require(decoded == out.size() && crc32(0, out.data(), uInt(out.size())) == stat.crc,
                "Apple ZIP member failed size/CRC validation");
        return out;
    }
    std::unique_ptr<zip_file_t, decltype(&zip_fclose)> file(zip_fopen_index(archive, index, 0),
                                                            zip_fclose);
    require(bool(file), "Cannot decompress ZIP member");
    Bytes out(std::size_t(stat.size));
    std::size_t done = 0;
    while (done < out.size()) {
        auto n = zip_fread(file.get(), out.data() + done, out.size() - done);
        require(n > 0, "Truncated or corrupt ZIP member");
        done += std::size_t(n);
    }
    std::uint8_t trailer;
    require(zip_fread(file.get(), &trailer, 1) == 0, "ZIP size/CRC validation failed");
    return out;
}

struct InputArchive {
    Bytes encoded;
    std::set<std::uint64_t> apple;
    Archive archive{nullptr, zip_discard};

    explicit InputArchive(const Path& path)
        : encoded(read_file(path)), apple(detail::apple_zip_parser_view(encoded)) {
        zip_error_t error;
        zip_error_init(&error);
        auto* source = zip_source_buffer_create(encoded.data(), encoded.size(), 0, &error);
        if (!source) {
            zip_error_fini(&error);
            throw Error("Cannot create IPA parser source");
        }
        auto* opened = zip_open_from_source(source, ZIP_RDONLY | ZIP_CHECKCONS, &error);
        if (!opened) {
            zip_source_free(source);
            zip_error_fini(&error);
            throw Error("Cannot open Apple ZIP IPA");
        }
        zip_error_fini(&error);
        archive.reset(opened);
    }

    zip_t* get() const {
        return archive.get();
    }

    Bytes member(zip_uint64_t index) const {
        return read(archive.get(), index, apple.contains(index));
    }
};

} // namespace

std::vector<Bytes> sinf_records(const Json& encoded) {
    if (encoded.is_null()) {
        return {};
    }
    Json records = encoded;
    if (records.is_string()) {
        const auto text = records.get<std::string>();
        require(text.size() <= 24 * 1024 * 1024, "SINF metadata exceeds size limit");
        const auto first = text.find_first_not_of(" \t\r\n");
        require(first != std::string::npos, "Empty SINF metadata");
        records = parse_plist(text[first] == '<' ? bytes(text) : unbase64(text));
    }
    if (records.is_object()) {
        require(records.contains("sinfs"), "SINF metadata lacks records");
        records = Json(records.at("sinfs"));
    }
    require(records.is_array() && records.size() <= 256, "Invalid SINF record list");
    std::vector<Bytes> result;
    std::size_t total = 0;
    for (const auto& record : records) {
        require(record.is_object() && record.contains("sinf") && record.at("sinf").is_binary(),
                "Invalid SINF record");
        const auto& data = record.at("sinf").get_binary();
        total += data.size();
        require(!data.empty() && total <= 16 * 1024 * 1024, "Invalid SINF record size");
        result.emplace_back(data.begin(), data.end());
    }
    return result;
}

IpaArchiveInfo
normalize_ipa(const Path& source, const Path& destination, const std::string& expected_bundle,
              const std::vector<Bytes>& sinfs) {
    require(!std::filesystem::exists(destination), "IPA output already exists");
    require(std::filesystem::absolute(source).lexically_normal() !=
                std::filesystem::absolute(destination).lexically_normal(),
            "IPA input and output must differ");
    int error = 0;
    InputArchive input(source);
    const auto count = zip_get_num_entries(input.get(), 0);
    require(count > 0 && count <= 1000000, "Invalid IPA member count");
    std::map<std::string, zip_uint64_t> names;
    std::vector<std::string> infos;
    for (zip_int64_t index = 0; index < count; ++index) {
        const auto* raw = zip_get_name(input.get(), zip_uint64_t(index), ZIP_FL_ENC_GUESS);
        require(raw, "Invalid IPA member name");
        const std::string name(raw);
        require(!name.empty() && name.front() != '/' &&
                    name.find_first_of("\\:") == std::string::npos,
                "Unsafe IPA member path");
        for (const auto& part : Path(name)) {
            require(part != "..", "Unsafe IPA parent path");
        }
        require(names.emplace(name, zip_uint64_t(index)).second, "Duplicate IPA member");
        if (name.starts_with("Payload/") && name.ends_with(".app/Info.plist") &&
            std::count(name.begin(), name.end(), '/') == 2) {
            infos.push_back(name);
        }
    }
    require(infos.size() == 1, "IPA must contain exactly one main application");
    const auto info = parse_plist(input.member(names.at(infos.front())));
    IpaArchiveInfo result;
    result.bundle = info.at("CFBundleIdentifier").get<std::string>();
    require(!result.bundle.empty() && (expected_bundle.empty() || expected_bundle == result.bundle),
            "IPA bundle differs from the requested application");
    const auto executable = info.at("CFBundleExecutable").get<std::string>();
    require(!executable.empty() && executable.find_first_of("/\\") == std::string::npos &&
                executable != "..",
            "Invalid IPA executable");
    require(names.contains(infos.front().substr(0, infos.front().rfind('/') + 1) + executable),
            "IPA lacks main executable");
    std::map<std::string, Bytes> replacements;
    if (!sinfs.empty()) {
        const auto root = infos.front().substr(0, infos.front().rfind('/') + 1);
        const auto manifest = root + "SC_Info/Manifest.plist";
        std::vector<std::string> paths;
        if (names.contains(manifest)) {
            const auto data = parse_plist(input.member(names.at(manifest)));
            require(data.contains("SinfPaths") && data.at("SinfPaths").is_array(),
                    "IPA manifest lacks SINF paths");
            paths = data.at("SinfPaths").get<std::vector<std::string>>();
        } else {
            require(sinfs.size() == 1, "Multiple SINF records require an IPA manifest");
            paths.push_back("SC_Info/" + executable + ".sinf");
        }
        require(paths.size() == sinfs.size(), "SINF count differs from IPA manifest");
        for (std::size_t i = 0; i < paths.size(); ++i) {
            const auto& path = paths[i];
            require(!path.empty() && path.front() != '/' && path.ends_with(".sinf") &&
                        path.find_first_of("\\:") == std::string::npos &&
                        path.find('\0') == std::string::npos && path.find("//") == std::string::npos,
                    "Unsafe SINF member path");
            bool sc_info = false;
            for (const auto& part : Path(path)) {
                require(part != ".." && part != ".", "Unsafe SINF parent path");
                sc_info = sc_info || part == "SC_Info";
            }
            require(sc_info, "SINF path must be inside SC_Info");
            const auto name = root + path;
            require(!names.contains(name + "/"), "SINF path conflicts with an IPA directory");
            require(replacements.emplace(name, sinfs[i]).second, "Duplicate SINF member path");
        }
    }
    if (!destination.parent_path().empty()) {
        std::filesystem::create_directories(destination.parent_path());
    }
    const Path temporary = destination.string() + "." + hex(random_bytes(8)) + ".partial";
    try {
        Archive output(zip_open(temporary.string().c_str(), ZIP_CREATE | ZIP_EXCL, &error),
                       zip_discard);
        require(bool(output), "Cannot create normalized IPA");
        std::vector<Bytes> buffers;
        buffers.reserve(names.size() + replacements.size());
        for (const auto& [name, index] : names) {
            const auto replacement = replacements.find(name);
            if (replacement == replacements.end()) {
                buffers.push_back(input.member(index));
            } else {
                (void)input.member(index); // Validate the original member's CRC before replacement.
                buffers.push_back(std::move(replacement->second));
                replacements.erase(replacement);
            }
            const auto& data = buffers.back();
            for (const auto id : encryption_ids(data)) {
                if (id) {
                    ++result.encrypted_images;
                } else {
                    ++result.clear_images;
                }
            }
            auto* buffer = zip_source_buffer(output.get(), data.data(), data.size(), 0);
            require(buffer, "Cannot create normalized ZIP source");
            const auto added = zip_file_add(output.get(), name.c_str(), buffer, ZIP_FL_ENC_UTF_8);
            if (added < 0) {
                zip_source_free(buffer);
                throw Error("Cannot add normalized ZIP member");
            }
            zip_stat_t stat{};
            zip_uint8_t os = 0;
            zip_uint32_t attributes = 0;
            require(zip_stat_index(input.get(), index, 0, &stat) == 0 &&
                        zip_file_get_external_attributes(input.get(), index, 0, &os, &attributes) ==
                            0,
                    "Cannot read IPA ZIP metadata");
            require(zip_file_set_external_attributes(
                        output.get(), zip_uint64_t(added), 0, os, attributes) == 0 &&
                        zip_file_set_mtime(output.get(), zip_uint64_t(added), stat.mtime, 0) == 0 &&
                        zip_set_file_compression(
                            output.get(), zip_uint64_t(added), ZIP_CM_DEFLATE, 6) == 0,
                    "Cannot preserve IPA ZIP metadata");
            ++result.members;
        }
        for (auto& [name, data] : replacements) {
            buffers.push_back(std::move(data));
            const auto& member = buffers.back();
            auto* buffer = zip_source_buffer(output.get(), member.data(), member.size(), 0);
            require(buffer, "Cannot create SINF ZIP source");
            const auto added = zip_file_add(output.get(), name.c_str(), buffer, ZIP_FL_ENC_UTF_8);
            if (added < 0) {
                zip_source_free(buffer);
                throw Error("Cannot add SINF ZIP member");
            }
            require(zip_file_set_external_attributes(output.get(), zip_uint64_t(added), 0,
                                                       ZIP_OPSYS_UNIX, 0100644u << 16) == 0 &&
                        zip_set_file_compression(output.get(), zip_uint64_t(added), ZIP_CM_DEFLATE, 6) == 0,
                    "Cannot set SINF ZIP metadata");
            ++result.members;
        }
        require(zip_close(output.get()) == 0, "Cannot finalize normalized IPA");
        output.release();
        std::filesystem::permissions(
            temporary, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        std::filesystem::create_hard_link(temporary, destination);
        std::filesystem::remove(temporary);
    } catch (...) {
        std::error_code code;
        std::filesystem::remove(temporary, code);
        throw;
    }
    return result;
}

} // namespace apple_auth::archivedetail
