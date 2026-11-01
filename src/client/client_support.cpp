#include "client/client_internal.hpp"
#include "crypto/protocol.hpp"
#include <algorithm>
#include <cctype>
#include <climits>
#include <fstream>
#include <memory>
#ifndef __APPLE__
#include <plist/plist.h>
#endif
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <aclapi.h>
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace apple_auth::netdetail {
namespace {
std::string header_key(std::string name) {
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    });
    return name;
}

bool header_value(const std::string& value) {
    return value.size() <= 4096 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return c >= 32 && c <= 126;
           });
}
} // namespace

void validate_device_headers(const ClientOptions& options) {
    for (const auto* value : {&options.user_agent, &options.client_info}) {
        if (!header_value(*value)) {
            throw apple_auth::Error(ErrorCode::invalid_argument, "Invalid device header override");
        }
    }
    std::vector<std::string> names;
    std::size_t total = 0;
    for (const auto& [name, value] : options.headers) {
        const auto key = header_key(name);
        total += name.size() + value.size();
        if (name.empty() || name.size() > 256 || !header_value(value) ||
            !std::all_of(name.begin(),
                         name.end(),
                         [](unsigned char c) {
                             return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                    (c >= '0' && c <= '9') ||
                                    std::string_view("!#$%&'*+-.^_`|~").find(c) !=
                                        std::string_view::npos;
                         }) ||
            std::find(names.begin(), names.end(), key) != names.end() || names.size() >= 128 ||
            total > 65536) {
            throw apple_auth::Error(ErrorCode::invalid_argument, "Invalid custom HTTP headers");
        }
        names.push_back(key);
    }
}

void merge_headers(Headers& headers, const Headers& overrides) {
    for (const auto& [name, value] : overrides) {
        auto canonical = name;
        const auto key = header_key(name);
        bool found = false;
        for (auto it = headers.begin(); it != headers.end();) {
            if (header_key(it->first) == key) {
                if (!found) {
                    canonical = it->first;
                    found = true;
                }
                it = headers.erase(it);
            } else {
                ++it;
            }
        }
        headers[canonical] = value;
    }
}

void apply_device_headers(Headers& headers, const ClientOptions& options) {
    if (!options.user_agent.empty()) {
        merge_headers(headers, {{"User-Agent", options.user_agent}});
    }
    if (!options.client_info.empty()) {
        merge_headers(headers, {{"X-MMe-Client-Info", options.client_info}});
    }
    merge_headers(headers, options.headers);
}

Transport configured_transport(const ClientOptions& options) {
    validate_device_headers(options);
    auto transport = options.transport ? options.transport : make_curl_transport();
    Headers overrides;
    apply_device_headers(overrides, options);
    if (overrides.empty()) {
        return transport;
    }
    return [transport = std::move(transport),
            overrides = std::move(overrides)](const HttpRequest& request) {
        auto configured = request;
        merge_headers(configured.headers, overrides);
        return transport(configured);
    };
}

void apply_xcode_headers(Headers& headers) {
    // Callers can override this through ClientOptions::headers in every binding.
    // https://developer.apple.com/news/releases/?id=10292026a
    headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth";
    headers["User-Agent"] = "Xcode";
    const auto version = std::find_if(headers.begin(), headers.end(), [](const auto& field) {
        return header_key(field.first) == "x-xcode-version";
    });
    if (version == headers.end()) {
        headers["X-Xcode-Version"] = "27.2 (27B52)";
    }
}

void check_apple_endpoint(const std::string& url) {
    require(url.starts_with("https://"), "Apple endpoint must use HTTPS");
    const auto end = url.find('/', 8);
    const auto authority = url.substr(8, end == std::string::npos ? std::string::npos : end - 8);
    require(authority.ends_with(".apple.com") &&
                authority.find_first_of("@:?#\\\r\n") == std::string::npos,
            "Lookup returned an invalid Apple endpoint");
}

Json lookup_grandslam_urls(const Headers& headers, const Transport& transport) {
    const auto response = transport(
        HttpRequest{"https://gsa.apple.com/grandslam/GsService2/lookup", "GET", headers, {}});
    require(response.status == 200, "GrandSlam lookup HTTP " + std::to_string(response.status));
    const auto lookup = parse_plist(response.body);
    require(lookup.contains("urls") && lookup.at("urls").is_object(), "Invalid GrandSlam lookup");
    return lookup.at("urls");
}

std::string grandslam_url(const Json& urls, const char* name) {
    require(urls.contains(name) && urls.at(name).is_string(),
            std::string("GrandSlam lookup missing endpoint: ") + name);
    auto url = urls.at(name).get<std::string>();
    check_apple_endpoint(url);
    return url;
}

Bytes random_bytes(std::size_t size) {
    return crypto::random_bytes(size);
}

Bytes unhex(const std::string& value) {
    return crypto::unhex(value);
}

std::string hex(View value) {
    return crypto::hex(value);
}

Bytes digest(const std::string& name, View value) {
    return crypto::digest(name, value);
}

Bytes hmac_sha256(View key, View value) {
    return crypto::hmac_sha256(key, value);
}

Bytes aes_cbc(View input, View key, View iv, bool decrypt, bool padding) {
    return crypto::aes_cbc(input, key, iv, decrypt, padding);
}

Bytes password_key(const std::string& password, View salt, int iterations, bool hex_password) {
    return crypto::password_key(password, salt, iterations, hex_password);
}

Bytes unbase64(const std::string& input) {
    std::string v;
    for (unsigned char c : input) {
        if (!std::isspace(c)) {
            v += char(c);
        }
    }
    require(v.size() % 4 == 0 && v.size() <= INT_MAX, "Invalid base64 length");
    if (v.empty()) {
        return {};
    }
    std::size_t padding = v.back() == '=' ? 1 : 0;
    if (v.size() > 1 && v[v.size() - 2] == '=') {
        ++padding;
    }
    for (std::size_t i = 0; i < v.size() - padding; ++i) {
        require(std::isalnum(static_cast<unsigned char>(v[i])) || v[i] == '+' || v[i] == '/',
                "Invalid base64 data");
    }
    Bytes out(v.size() / 4 * 3);
    std::size_t size = 0;
    require(mbedtls_base64_decode(out.data(),
                                  out.size(),
                                  &size,
                                  reinterpret_cast<const unsigned char*>(v.data()),
                                  v.size()) == 0,
            "Invalid base64 data");
    out.resize(size);
    return out;
}

#ifndef __APPLE__

namespace {
Json plist_json(plist_t node, unsigned depth) {
    require(node && depth < 64, "Invalid plist nesting");
    switch (plist_get_node_type(node)) {
    case PLIST_DICT: {
        Json out = Json::object();
        plist_dict_iter it = nullptr;
        plist_dict_new_iter(node, &it);
        const std::unique_ptr<void, decltype(&free)> iterator(it, free);
        for (;;) {
            char* key = nullptr;
            plist_t child = nullptr;
            plist_dict_next_item(node, it, &key, &child);
            if (!child) {
                break;
            }
            std::unique_ptr<char, decltype(&free)> owned(key, free);
            out[key] = plist_json(child, depth + 1);
        }
        return out;
    }
    case PLIST_ARRAY: {
        Json out = Json::array();
        for (std::uint32_t i = 0; i < plist_array_get_size(node); ++i) {
            out.push_back(plist_json(plist_array_get_item(node, i), depth + 1));
        }
        return out;
    }
    case PLIST_DATA: {
        char* p = nullptr;
        std::uint64_t n = 0;
        plist_get_data_val(node, &p, &n);
        std::unique_ptr<char, decltype(&free)> owned(p, free);
        require(p != nullptr || n == 0, "Invalid plist data field");
        return Json::binary(n == 0 ? Bytes{} : Bytes(p, p + n));
    }
    case PLIST_STRING:
    case PLIST_KEY: {
        char* p = nullptr;
        plist_get_string_val(node, &p);
        std::unique_ptr<char, decltype(&free)> owned(p, free);
        return p ? Json(p) : Json("");
    }
    case PLIST_BOOLEAN: {
        std::uint8_t b = 0;
        plist_get_bool_val(node, &b);
        return b != 0;
    }
    case PLIST_UINT: {
        std::uint64_t n = 0;
        plist_get_uint_val(node, &n);
        return n;
    }
    case PLIST_REAL: {
        double n = 0;
        plist_get_real_val(node, &n);
        return n;
    }
    case PLIST_DATE: {
#ifdef APPLE_AUTH_PLIST_UNIX_DATE
        std::int64_t seconds = 0;
        plist_get_unix_date_val(node, &seconds);
        return Json{{"seconds", seconds - 978307200}, {"microseconds", 0}};
#else
        std::int32_t s = 0, u = 0;
        plist_get_date_val(node, &s, &u);
        return Json{{"seconds", s}, {"microseconds", u}};
#endif
    }
    default:
        throw Error("Unsupported plist value");
    }
}

plist_t json_plist(const Json& v) {
    if (v.is_object()) {
        auto p = plist_new_dict();
        try {
            for (auto it = v.begin(); it != v.end(); ++it) {
                plist_dict_set_item(p, it.key().c_str(), json_plist(it.value()));
            }
        } catch (...) {
            plist_free(p);
            throw;
        }
        return p;
    }
    if (v.is_array()) {
        auto p = plist_new_array();
        try {
            for (const auto& x : v) {
                plist_array_append_item(p, json_plist(x));
            }
        } catch (...) {
            plist_free(p);
            throw;
        }
        return p;
    }
    if (v.is_binary()) {
        const auto& b = v.get_binary();
        return plist_new_data(reinterpret_cast<const char*>(b.data()), b.size());
    }
    if (v.is_string()) {
        return plist_new_string(v.get_ref<const std::string&>().c_str());
    }
    if (v.is_boolean()) {
        return plist_new_bool(v.get<bool>() ? 1 : 0);
    }
    if (v.is_number_integer()) {
        return plist_new_uint(v.get<std::uint64_t>());
    }
    if (v.is_number_float()) {
        return plist_new_real(v.get<double>());
    }
    throw Error("Unsupported JSON value in plist");
}
} // namespace

Json parse_plist(View input) {
    require(!input.empty() && input.size() <= 16 * 1024 * 1024, "Invalid plist size");
    require(str(input).find("<!ENTITY") == std::string::npos, "Plist entities are unsupported");
    plist_t node = nullptr;
    plist_format_t format{};
    const auto result = plist_from_memory(
        reinterpret_cast<const char*>(input.data()), std::uint32_t(input.size()), &node, &format);
    require(result == PLIST_ERR_SUCCESS && node, "Invalid plist");
    std::unique_ptr<void, decltype(&plist_free)> owned(node, plist_free);
    return plist_json(node, 0);
}

Bytes encode_plist(const Json& value) {
    std::unique_ptr<void, decltype(&plist_free)> node(json_plist(value), plist_free);
    char* p = nullptr;
    std::uint32_t size = 0;
    plist_to_xml(node.get(), &p, &size);
    std::unique_ptr<char, decltype(&free)> owned(p, free);
    require(p, "Cannot encode plist");
    return Bytes(p, p + size);
}

#endif

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw Error(message);
    }
}

Bytes bytes(const std::string& value) {
    return {value.begin(), value.end()};
}

std::string str(View value) {
    return {value.begin(), value.end()};
}

Bytes read_file(const Path& path, std::size_t limit) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    require(bool(file), "Cannot open file: " + path.filename().string());
    auto size = file.tellg();
    require(size >= 0 && static_cast<std::uint64_t>(size) <= limit, "File size exceeds limit");
    Bytes out(static_cast<std::size_t>(size));
    file.seekg(0);
    require(bool(file.read(reinterpret_cast<char*>(out.data()),
                           static_cast<std::streamsize>(out.size()))),
            "Cannot read complete file");
    return out;
}

void write_private(const Path& path, View data) {
    if (!path.parent_path().empty()) {
        if (std::filesystem::create_directories(path.parent_path())) {
            std::filesystem::permissions(path.parent_path(), std::filesystem::perms::owner_all);
        }
    }
    auto temp = path;
    temp += "." + hex(random_bytes(12)) + ".tmp";
    bool created = false;
    try {
#ifdef _WIN32
        struct Handle {
            HANDLE value = INVALID_HANDLE_VALUE;

            ~Handle() {
                if (value != INVALID_HANDLE_VALUE && value != nullptr) {
                    CloseHandle(value);
                }
            }
        } token;

        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) != 0,
                "Cannot inspect file owner");
        DWORD required = 0;
        GetTokenInformation(token.value, TokenUser, nullptr, 0, &required);
        require(required != 0, "Cannot determine file owner");
        Bytes info(required);
        require(GetTokenInformation(token.value, TokenUser, info.data(), required, &required) != 0,
                "Cannot read file owner");
        EXPLICIT_ACCESSW access{};
        access.grfAccessPermissions = GENERIC_ALL;
        access.grfAccessMode = SET_ACCESS;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;
        access.Trustee.ptstrName =
            static_cast<LPWSTR>(reinterpret_cast<TOKEN_USER*>(info.data())->User.Sid);
        PACL raw_acl = nullptr;
        require(SetEntriesInAclW(1, &access, nullptr, &raw_acl) == ERROR_SUCCESS,
                "Cannot create private file permissions");
        const std::unique_ptr<void, decltype(&LocalFree)> acl(raw_acl, LocalFree);
        SECURITY_DESCRIPTOR descriptor{};
        require(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) != 0 &&
                    SetSecurityDescriptorDacl(&descriptor, TRUE, raw_acl, FALSE) != 0 &&
                    SetSecurityDescriptorControl(
                        &descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0,
                "Cannot initialize private file permissions");
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), &descriptor, FALSE};
        {
            Handle file{CreateFileW(temp.c_str(),
                                    GENERIC_WRITE,
                                    0,
                                    &attributes,
                                    CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr)};
            require(file.value != INVALID_HANDLE_VALUE, "Cannot create private file");
            created = true;
            std::size_t offset = 0;
            while (offset < data.size()) {
                const auto chunk =
                    static_cast<DWORD>(std::min<std::size_t>(data.size() - offset, MAXDWORD));
                DWORD written = 0;
                require(WriteFile(file.value, data.data() + offset, chunk, &written, nullptr) !=
                                0 &&
                            written != 0,
                        "Cannot write private file");
                offset += written;
            }
            require(FlushFileBuffers(file.value) != 0, "Cannot flush private file");
        }
        require(MoveFileExW(temp.c_str(),
                            path.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0,
                "Cannot publish private file");
#else
        {
            struct File {
                int descriptor;

                ~File() {
                    if (descriptor >= 0) {
                        ::close(descriptor);
                    }
                }
            } file{::open(temp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600)};

            require(file.descriptor >= 0, "Cannot create private file");
            created = true;
            std::size_t offset = 0;
            while (offset < data.size()) {
                const auto written =
                    ::write(file.descriptor, data.data() + offset, data.size() - offset);
                if (written < 0 && errno == EINTR) {
                    continue;
                }
                require(written > 0, "Cannot write private file");
                offset += static_cast<std::size_t>(written);
            }
            require(::fsync(file.descriptor) == 0, "Cannot flush private file");
        }
        std::filesystem::rename(temp, path);
#endif
    } catch (...) {
        std::error_code ec;
        if (created) {
            std::filesystem::remove(temp, ec);
        }
        throw;
    }
}

} // namespace apple_auth::netdetail
