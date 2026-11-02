#include "testflight/data/protocol.hpp"
#include "testflight/internal.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace apple_auth::tfdetail {
namespace {

std::string text(const Json& object, const char* key) {
    if (!object.is_object() || !object.contains(key)) {
        return {};
    }
    const auto& value = object.at(key);
    if (value.is_string()) {
        return value.get<std::string>();
    }
    if (value.is_number_integer()) {
        return value.dump();
    }
    return {};
}

std::string escape(const std::string& value) {
    const char* digits = "0123456789ABCDEF";
    std::string result;
    for (const auto character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
            byte == '~') {
            result += character;
        } else {
            result += '%';
            result += digits[byte >> 4];
            result += digits[byte & 15];
        }
    }
    return result;
}

std::string request_id() {
    auto id = random_bytes(16);
    id[6] = (id[6] & 15) | 0x40;
    id[8] = (id[8] & 63) | 0x80;
    auto encoded = hex(id);
    std::transform(encoded.begin(), encoded.end(), encoded.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return encoded.substr(0, 8) + "-" + encoded.substr(8, 4) + "-" + encoded.substr(12, 4) + "-" +
           encoded.substr(16, 4) + "-" + encoded.substr(20);
}

void visit(const Json& value,
           const std::function<void(const Json&)>& callback,
           unsigned depth = 0) {
    require(depth < 64, "TestFlight response is too deeply nested");
    if (value.is_object()) {
        callback(value);
        for (const auto& child : value) {
            if (child.is_structured()) {
                visit(child, callback, depth + 1);
            }
        }
    } else if (value.is_array()) {
        for (const auto& child : value) {
            if (child.is_structured()) {
                visit(child, callback, depth + 1);
            }
        }
    }
}

bool flag(const Json& value, const char* key) {
    return value.contains(key) && value.at(key).is_boolean() && value.at(key).get<bool>();
}

bool expired(const std::string& value) {
    if (value.size() < 20 || value.back() != 'Z') {
        return false;
    }
    std::tm date{};
    std::istringstream input(value.substr(0, 19));
    input >> std::get_time(&date, "%Y-%m-%dT%H:%M:%S");
    if (input.fail()) {
        return false;
    }
#ifdef _WIN32
    const auto expiry = _mkgmtime(&date);
#else
    const auto expiry = timegm(&date);
#endif
    return expiry >= 0 &&
           expiry <= std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}

} // namespace

namespace {
void validate_options(const TestFlightOptions& options) {
    ClientOptions headers;
    headers.headers = options.headers;
    headers.client_info = options.device_model;
    validate_device_headers(headers);
    require(options.device_model.size() <= 128 && options.device_name.size() <= 256 &&
                std::all_of(options.device_name.begin(),
                            options.device_name.end(),
                            [](unsigned char c) {
                                return c >= 32 && c != 127;
                            }),
            "Invalid TestFlight device options");
}
} // namespace

Json create_session(const Json& context,
                    const Transport& transport,
                    const TestFlightOptions& options) {
    validate_options(options);
    const auto dsid = text(context, "dsid");
    std::uint64_t number = 0;
    const auto parsed = std::from_chars(dsid.data(), dsid.data() + dsid.size(), number);
    require(parsed.ec == std::errc{} && parsed.ptr == dsid.data() + dsid.size() && number,
            "Store context requires a valid DSID");
    const auto hardware = unhex(text(context, "udid"));
    require(hardware.size() == 20, "Store context requires hardware20");
    require(context.contains("storeCookies") && context.at("storeCookies").is_structured() &&
                !context.at("storeCookies").empty(),
            "Saved Store cookies are missing");
    require(context.contains("headers") && context.at("headers").is_object(),
            "Store context requires macOS TestFlight headers");
    Headers headers;
    for (const auto* key : {"User-Agent",
                            "X-Apple-AMD-M",
                            "X-Apple-Store-Front",
                            "X-Apple-Device-Model",
                            "X-Apple-TA-Device",
                            "X-Apple-TestFlight-iOS",
                            "X-Apple-Rosetta-Available"}) {
        headers[key] = text(context.at("headers"), key);
    }
    require(!headers["User-Agent"].empty() && !headers["X-Apple-AMD-M"].empty() &&
                !headers["X-Apple-Store-Front"].empty() && headers["X-Apple-TestFlight-iOS"] == "0",
            "Incomplete macOS TestFlight context");
    headers["Accept"] = "application/json";
    headers["Content-Type"] = "application/json";
    headers["Accept-Language"] = "en-US";
    merge_headers(headers, options.headers);
    const auto vendor = request_id();
    const auto storefront = headers["X-Apple-Store-Front"];
    const Json body{{"deviceModel", headers["X-Apple-Device-Model"]},
                    {"deviceName",
                     options.device_name.empty() ? context.value("deviceName", "TestFlight")
                                                 : options.device_name},
                    {"dsId", number},
                    {"deviceVendorId", vendor},
                    {"storeFrontIdentifier", storefront.substr(0, storefront.find(','))},
                    {"storeCookies", context.at("storeCookies")}};
    const auto response = transport({"https://testflight.apple.com/v1/session/authenticate",
                                     "POST",
                                     headers,
                                     bytes(body.dump())});
    require(response.status >= 200 && response.status < 300,
            "TestFlight session creation rejected (HTTP " + std::to_string(response.status) + ")");
    auto payload = Json::parse(response.body.begin(), response.body.end());
    if (payload.is_object() && payload.contains("data")) {
        payload = payload.at("data");
    }
    const auto account = text(payload, "accountId"), session = text(payload, "sessionId");
    require(!account.empty() && !session.empty(), "TestFlight did not return a session");
    return Json{
        {"accountId", account},
        {"sessionId", session},
        {"dsid", dsid},
        {"udid", hex(hardware)},
        {"deviceVendorId", vendor},
        {"deviceName",
         options.device_name.empty() ? context.value("deviceName", "TestFlight")
                                     : options.device_name},
        {"deviceModel",
         options.device_model.empty() ? context.value("deviceModel", "iPhone12,1")
                                      : options.device_model},
        {"headers",
         Json{{"X-Apple-AMD-M", headers["X-Apple-AMD-M"]}, {"X-Apple-Store-Front", storefront}}}};
}

Engine::Engine(const Json& context, Transport transport, TestFlightOptions options)
    : transport_(std::move(transport)) {
    validate_options(options);
    device_name_ = options.device_name.empty() ? context.value("deviceName", "TestFlight")
                                               : options.device_name;
    account_ = text(context, "accountId");
    session_ = text(context, "sessionId");
    dsid_ = text(context, "dsid");
    require(!account_.empty() && !session_.empty() && !dsid_.empty(),
            "Incomplete saved TestFlight session");
    require(account_.size() <= 256 && session_.size() <= 4096, "Invalid saved TestFlight session");
    const auto parsed = std::from_chars(dsid_.data(), dsid_.data() + dsid_.size(), numeric_dsid_);
    require(parsed.ec == std::errc{} && parsed.ptr == dsid_.data() + dsid_.size() &&
                numeric_dsid_ != 0,
            "Invalid TestFlight DSID");
    hardware_ = unhex(text(context, "udid"));
    require(hardware_.size() == 20, "TestFlight session requires hardware20");
    require(context.contains("headers") && context.at("headers").is_object(),
            "TestFlight session headers are missing");
    headers_["X-Apple-AMD-M"] = "";
    headers_["X-Apple-Store-Front"] = "";
    headers_["Accept"] = "application/json";
    headers_["Content-Type"] = "application/json";
    headers_["Accept-Language"] = "en-US";
    headers_["X-Apple-Device-Model"] = context.value("deviceModel", "iPhone12,1");
    headers_["X-Apple-TA-Device"] = headers_["X-Apple-Device-Model"];
    headers_["User-Agent"] = testflight_agent;
    ClientOptions saved;
    saved.headers = context.at("headers").get<Headers>();
    validate_device_headers(saved);
    merge_headers(headers_, saved.headers);
    if (!options.device_model.empty()) {
        merge_headers(headers_,
                      {{"X-Apple-Device-Model", options.device_model},
                       {"X-Apple-TA-Device", options.device_model}});
    }
    merge_headers(headers_, options.headers);
    require(!headers_.at("X-Apple-AMD-M").empty() && !headers_.at("X-Apple-Store-Front").empty(),
            "TestFlight device headers are missing");
    saved.headers = headers_;
    validate_device_headers(saved);
    TestFlightOptions resolved;
    resolved.device_name = device_name_;
    resolved.device_model = headers_.at("X-Apple-Device-Model");
    validate_options(resolved);
}

Json Engine::request(unsigned version, const std::string& resource, const Json* body) {

    auto headers = headers_;
    const auto id = request_id();
    merge_headers(headers,
                  {{"X-Session-Id", session_},
                   {"X-Request-Id", id},
                   {"X-Session-Digest",
                    hex(digest("SHA1", bytes(session_ + id + dsid_ + session_digest_salt)))}});
    const auto response = transport_({"https://testflight.apple.com/v" + std::to_string(version) +
                                          "/accounts/" + escape(account_) + "/" + resource,
                                      body ? "POST" : "GET",
                                      headers,
                                      body ? bytes(body->dump()) : Bytes{}});
    require(response.status >= 200 && response.status < 300,
            "TestFlight request rejected (HTTP " + std::to_string(response.status) + ")");
    if (response.body.empty()) {
        return Json::object();
    }
    auto payload = Json::parse(response.body.begin(), response.body.end());
    if (payload.is_object()) {
        require(!payload.contains("error") || payload.at("error").is_null() ||
                    payload.at("error") == false,
                "TestFlight reported an API error");
        if (payload.contains("messages") && payload.at("messages").is_array()) {
            for (const auto& message : payload.at("messages")) {
                auto kind = text(message, "messageType");
                if (kind.empty()) {
                    kind = text(message, "type");
                }
                std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                require(kind != "error", "TestFlight reported an API error");
            }
        }
        if (payload.contains("data")) {
            return payload.at("data");
        }
    }
    return payload;
}

Json Engine::catalog() {
    return request(4, "apps?allDetailsCount=10000");
}

std::string Engine::find_app(const std::string& bundle) {
    auto data = catalog();
    std::string result;
    const auto match = [&](const Json& app) {
        auto name = text(app, "bundleId");
        if (name.empty()) {
            name = text(app, "bundleIdentifier");
        }
        if (name != bundle) {
            return;
        }
        for (const auto* key : {"appAdamId", "adamId", "appId"}) {
            auto candidate = text(app, key);
            if (!candidate.empty()) {
                result = candidate;
                break;
            }
        }
    };
    visit(data, match);
    if (!result.empty()) {
        return result;
    }
    std::map<std::string, Json> outlines;
    visit(data, [&](const Json& item) {
        if (item.contains("appId")) {
            outlines.try_emplace(text(item, "appId"), item.at("appId"));
        }
    });
    Json apps = Json::array();
    for (const auto& [key, value] : outlines) {
        if (key.empty()) {
            continue;
        }
        apps.push_back(Json{{"appId", value}});
        if (apps.size() == 25) {
            const Json body{{"apps", apps}};
            visit(request(4, "appDetails", &body), match);
            if (!result.empty()) {
                return result;
            }
            apps.clear();
        }
    }
    if (!apps.empty()) {
        const Json body{{"apps", apps}};
        visit(request(4, "appDetails", &body), match);
    }
    require(!result.empty(), "Application is absent from the iOS TestFlight catalog");
    return result;
}

std::string Engine::latest_build(const std::string& app) {
    const auto details = request(3, "apps/" + escape(app));
    std::uint64_t latest = 0;
    std::string result;
    visit(details, [&](const Json& item) {
        auto id = text(item, "buildId");
        if (id.empty()) {
            id = text(item, "buildID");
        }
        if (id.empty() && (item.contains("buildVersion") || item.contains("cfBundleVersion") ||
                           item.contains("cfBundleShortVersion"))) {
            id = text(item, "id");
        }
        auto platform = text(item, "platform");
        std::transform(platform.begin(), platform.end(), platform.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (id.empty() ||
            (!platform.empty() && platform != "ios" && platform != "iphoneos" && platform != "1")) {
            return;
        }
        if (flag(item, "expired") || flag(item, "isExpired") || flag(item, "launchProhibited") ||
            (item.contains("manuallyExpiredDate") && !item.at("manuallyExpiredDate").is_null() &&
             !item.at("manuallyExpiredDate").empty()) ||
            expired(text(item, "expiration"))) {
            return;
        }
        std::uint64_t number = 0;
        const auto parsed = std::from_chars(id.data(), id.data() + id.size(), number);
        if (parsed.ec == std::errc{} && parsed.ptr == id.data() + id.size() && number > latest) {
            latest = number;
            result = id;
        }
    });
    require(!result.empty(), "TestFlight returned no available iOS build");
    return result;
}

Json Engine::install_metadata(const std::string& bundle) {
    require(!bundle.empty(), "Application bundle identifier is required");
    const auto app = find_app(bundle);
    const auto build = latest_build(app);
    const auto packet = generate_kbsync(numeric_dsid_, hardware_);
    auto storefront = headers_.at("X-Apple-Store-Front");
    storefront = storefront.substr(0, storefront.find(','));
    const Json body{{"kbSync", base64(packet)},
                    {"udid", hex(hardware_)},
                    {"deviceName", device_name_},
                    {"storefrontId", storefront},
                    {"isFromAutoUpdate", false}};
    auto data = request(2, "apps/" + escape(app) + "/builds/" + escape(build) + "/install", &body);
    require(data.is_object() && !text(data, "url").empty() && !text(data, "dpInfo").empty(),
            "TestFlight returned incomplete install metadata");
    return data;
}

TestFlightDownload
download_testflight_ipa(Engine& client, const std::string& bundle, const Path& destination,
                        bool include_sinf) {
    require(!std::filesystem::exists(destination), "IPA output already exists");
    auto parent = destination.parent_path();
    if (parent.empty()) {
        parent = ".";
    }
    const auto work = parent / (".testflight-download-" + hex(random_bytes(8)));
    require(std::filesystem::create_directories(work), "Cannot create download artifact directory");
    std::filesystem::permissions(work, std::filesystem::perms::owner_all);
    const auto metadata = client.install_metadata(bundle);
    const auto sinfs = include_sinf
                           ? archivedetail::sinf_records(metadata.value("sinf", Json()))
                           : std::vector<Bytes>{};
    write_private(work / "install-metadata.json", bytes(metadata.dump(2)));
    const auto length = download_file(text(metadata, "url"), work / "transport.bin");
    unwrap_transport(work / "transport.bin",
                     work / "applezip.ipa",
                     client.hardware(),
                     unbase64(text(metadata, "dpInfo")));
    auto archive = normalize_ipa(work / "applezip.ipa", destination, bundle, sinfs);
    return {{std::move(archive.bundle),
             archive.members,
             archive.encrypted_images,
             archive.clear_images},
            length,
            work};
}

} // namespace apple_auth::tfdetail
