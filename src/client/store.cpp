#include "client/data/store.hpp"
#include "client/client_internal.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace apple_auth {
namespace {
using namespace netdetail;

const char* protocol_name(StoreProtocol protocol) {
    switch (protocol) {
    case StoreProtocol::android_music:
        return "android-music";
    case StoreProtocol::macos_accounts:
        return "macos-accounts";
    case StoreProtocol::configurator:
        return "configurator";
    }
    throw netdetail::Error("Unknown Store protocol");
}

Json decode_store(ByteView data) {
    require(!data.empty() && data.size() <= (16u << 20), "Invalid Store response size");
    const auto first = std::find_if(data.begin(), data.end(), [](unsigned char c) {
        return !std::isspace(c);
    });
    require(first != data.end(), "Empty Store response");
    if (*first == '{' || *first == '[') {
        return Json::parse(data.begin(), data.end());
    }
    if (*first == '<') {
        const auto xml = str(data);
        const auto begin = xml.find("<plist"), end = xml.find("</plist>");
        if (begin != std::string::npos && end != std::string::npos && end > begin) {
            return parse_plist(bytes(xml.substr(begin, end + 8 - begin)));
        }
    }
    return parse_plist(data);
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return char(std::tolower(c));
    });
    return value;
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}

void safe_header(const std::string& value) {
    require(value.size() <= 32 * 1024 && std::none_of(value.begin(),
                                                      value.end(),
                                                      [](unsigned char c) {
                                                          return c < 32 || c == 127;
                                                      }),
            "Invalid Store header value");
}

struct Url {
    std::string host, path;
};

Url apple_url(const std::string& url, bool store_only = false, bool certificate = false) {
    require(url.starts_with("https://") && url.size() <= 8192 &&
                url.find_first_of("\r\n\t\\#") == std::string::npos,
            "Store endpoint must be an Apple HTTPS URL");
    const auto end = url.find_first_of("/?", 8);
    auto host = lower(url.substr(8, end == std::string::npos ? end : end - 8));
    require(
        host.find_first_of("@: %") == std::string::npos &&
            (host.ends_with(".apple.com") || (certificate && host.ends_with(".mzstatic.com"))) &&
            (!store_only || host == "itunes.apple.com" || host.ends_with(".itunes.apple.com")),
        "Invalid Apple Store endpoint host");
    auto path = end != std::string::npos && url[end] == '/' ? url.substr(end) : "/";
    path = path.substr(0, path.find('?'));
    return {std::move(host), std::move(path)};
}

bool domain_matches(const std::string& host, const std::string& domain) {
    return host == domain || (host.size() > domain.size() && host.ends_with("." + domain));
}

std::string header(const HttpResponse& response, const std::string& name) {
    std::string result;
    for (const auto& [key, value] : response.headers) {
        if (lower(key) == name) {
            result = value;
        }
    }
    return result;
}

Bytes binary(const Json& object, const char* field) {
    require(object.contains(field), "Missing Store binary field");
    const auto& value = object.at(field);
    if (value.is_binary()) {
        return value.get_binary();
    }
    require(value.is_string(), "Invalid Store binary field");
    return unbase64(value.get<std::string>());
}

std::string scalar(const Json& value) {
    if (value.is_string()) {
        return value.get<std::string>();
    }
    require(value.is_number_integer(), "Invalid Store identifier");
    return value.dump();
}

void cookies_update(Json& cookies,
                    const std::string& url,
                    const HttpResponse& response,
                    std::int64_t now) {
    const auto target = apple_url(url);
    for (const auto& [key, line] : response.headers) {
        if (lower(key) != "set-cookie" || line.size() > 16 * 1024) {
            continue;
        }
        std::istringstream input(line);
        std::string part;
        std::getline(input, part, ';');
        const auto equal = part.find('=');
        if (equal == std::string::npos || equal == 0) {
            continue;
        }
        const auto name = trim(part.substr(0, equal)), value = trim(part.substr(equal + 1));
        if (name.find_first_of(" \t\r\n,;") != std::string::npos ||
            value.find_first_of("\r\n;") != std::string::npos) {
            continue;
        }
        safe_header(name);
        safe_header(value);
        auto domain = target.host;
        auto path = target.path.substr(0, target.path.find_last_of('/') + 1);
        bool host_only = true;
        std::int64_t expires = 0;
        std::optional<std::int64_t> max_age;
        while (std::getline(input, part, ';')) {
            const auto separator = part.find('=');
            const auto attribute = lower(trim(part.substr(0, separator)));
            auto setting = separator == std::string::npos ? "" : trim(part.substr(separator + 1));
            if (attribute == "domain") {
                domain = lower(setting);
                while (domain.starts_with('.')) {
                    domain.erase(domain.begin());
                }
                host_only = false;
            } else if (attribute == "path" && setting.starts_with('/')) {
                path = setting;
            } else if (attribute == "expires") {
                const auto date = netdetail::http_date(setting);
                if (date >= 0) {
                    expires = static_cast<std::int64_t>(date);
                }
            } else if (attribute == "max-age") {
                try {
                    std::size_t used = 0;
                    const auto seconds = std::stoll(setting, &used);
                    if (used == setting.size()) {
                        max_age = seconds;
                    }
                } catch (const std::exception&) { /* Ignore an invalid attribute. */
                }
            }
        }
        if ((domain != "apple.com" && !domain.ends_with(".apple.com")) ||
            !domain_matches(target.host, domain)) {
            continue;
        }
        if (max_age) {
            expires =
                *max_age <= 0 ? 1 : now + std::min<std::int64_t>(*max_age, 10LL * 366 * 86400);
        }
        auto same = [&](const Json& cookie) {
            return cookie.at("name") == name && cookie.at("domain") == domain &&
                   cookie.at("path") == path;
        };
        cookies.erase(std::remove_if(cookies.begin(), cookies.end(), same), cookies.end());
        if (expires && expires <= now) {
            continue;
        }
        require(cookies.size() < 256, "Too many Store cookies");
        cookies.push_back({{"name", name},
                           {"value", value},
                           {"domain", domain},
                           {"path", path},
                           {"host_only", host_only},
                           {"expires", expires}});
    }
}

std::string cookie_header(const Json& cookies, const std::string& url, std::int64_t now) {
    const auto target = apple_url(url, true);
    std::vector<const Json*> matching;
    for (const auto& cookie : cookies) {
        const auto& domain = cookie.at("domain").get_ref<const std::string&>();
        const auto& path = cookie.at("path").get_ref<const std::string&>();
        const auto expires = cookie.at("expires").get<std::int64_t>();
        if ((cookie.at("host_only").get<bool>() ? target.host == domain
                                                : domain_matches(target.host, domain)) &&
            target.path.starts_with(path) &&
            (target.path.size() == path.size() || path.ends_with('/') ||
             target.path[path.size()] == '/') &&
            (!expires || expires > now)) {
            matching.push_back(&cookie);
        }
    }
    std::stable_sort(matching.begin(), matching.end(), [](const auto* a, const auto* b) {
        return a->at("path").template get_ref<const std::string&>().size() >
               b->at("path").template get_ref<const std::string&>().size();
    });
    std::string result;
    for (const auto* cookie : matching) {
        if (!result.empty()) {
            result += "; ";
        }
        result +=
            cookie->at("name").get<std::string>() + "=" + cookie->at("value").get<std::string>();
    }
    return result;
}

std::string utc_time(std::int64_t seconds) {
    const auto time = static_cast<std::time_t>(seconds);
    std::tm calendar{};
#ifdef _WIN32
    require(gmtime_s(&calendar, &time) == 0, "Invalid Store clock");
#else
    require(gmtime_r(&time, &calendar) != nullptr, "Invalid Store clock");
#endif
    std::ostringstream output;
    output << std::put_time(&calendar, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}
} // namespace

struct StoreSession::Impl {
    Json state;
};

StoreSession::StoreSession(std::unique_ptr<Impl> value) : impl_(std::move(value)) {}

StoreSession::~StoreSession() = default;
StoreSession::StoreSession(StoreSession&&) noexcept = default;
StoreSession& StoreSession::operator=(StoreSession&&) noexcept = default;

StoreSession StoreSession::from_plist(ByteView data) {
    auto result = std::make_unique<Impl>();
    result->state = parse_plist(data);
    const auto& state = result->state;
    const auto kind = state.value("kind", "");
    require(kind == "apple-auth-store" && state.value("version", 0) == 1,
            "Unsupported Store session format");
    const auto id = scalar(state.at("account").at("dsPersonId"));
    require(!id.empty() && id.size() <= 32 &&
                std::all_of(id.begin(),
                            id.end(),
                            [](unsigned char c) {
                                return c >= '0' && c <= '9';
                            }),
            "Invalid Store account ID");
    for (const auto& value : {state.at("account").at("passwordToken").get<std::string>(),
                              state.at("storefront").get<std::string>(),
                              state.at("guid").get<std::string>()}) {
        require(!value.empty(), "Incomplete Store session");
        safe_header(value);
    }
    const auto& cookies = state.at("cookies");
    if (state.contains("user_agent")) {
        safe_header(state.at("user_agent").get<std::string>());
    }
    require(cookies.is_array() && cookies.size() <= 256, "Invalid Store cookies");
    for (const auto& cookie : cookies) {
        for (const auto* name : {"name", "value", "domain", "path"}) {
            safe_header(cookie.at(name).get<std::string>());
        }
        require(!cookie.at("name").get_ref<const std::string&>().empty() &&
                    cookie.at("name").get_ref<const std::string&>().find_first_of("=; ,") ==
                        std::string::npos &&
                    cookie.at("value").get_ref<const std::string&>().find(';') ==
                        std::string::npos &&
                    (cookie.at("domain") == "apple.com" ||
                     cookie.at("domain").get_ref<const std::string&>().ends_with(".apple.com")) &&
                    cookie.at("path").get_ref<const std::string&>().starts_with('/') &&
                    cookie.at("expires").is_number_integer() && cookie.at("host_only").is_boolean(),
                "Invalid saved Store cookie");
    }
    return StoreSession(std::move(result));
}

StoreSession StoreSession::load(const std::filesystem::path& path) {
    return from_plist(read_file(path, 1024 * 1024));
}

std::string StoreSession::account_id() const {
    require(bool(impl_), "Store session was moved");
    return scalar(impl_->state.at("account").at("dsPersonId"));
}

std::string StoreSession::storefront() const {
    require(bool(impl_), "Store session was moved");
    return impl_->state.at("storefront").get<std::string>();
}

StoreProtocol StoreSession::protocol() const {
    require(bool(impl_), "Store session was moved");
    const auto name = impl_->state.value("protocol", "android-music");
    for (const auto value : {StoreProtocol::android_music,
                             StoreProtocol::macos_accounts,
                             StoreProtocol::configurator}) {
        if (name == protocol_name(value)) {
            return value;
        }
    }
    throw netdetail::Error("Unknown saved Store protocol");
}

Headers StoreSession::headers(const std::string& url) const {
    require(bool(impl_), "Store session was moved");
    apple_url(url, true);
    Headers result{{"User-Agent", impl_->state.value("user_agent", std::string(store_agent))},
                   {"X-Dsid", account_id()},
                   {"X-Token", impl_->state.at("account").at("passwordToken").get<std::string>()},
                   {"X-Apple-Store-Front", storefront()}};
    const auto cookies = cookie_header(
        impl_->state.at("cookies"), url, static_cast<std::int64_t>(std::time(nullptr)));
    if (!cookies.empty()) {
        result["Cookie"] = cookies;
    }
    return result;
}

Bytes StoreSession::plist() const {
    require(bool(impl_), "Store session was moved");
    return encode_plist(impl_->state);
}

void StoreSession::save(const std::filesystem::path& path) const {
    write_private(path, plist());
}

namespace {
Json root_cookies(const Json& state) {
    Json result = Json::object();
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    for (const auto& cookie : state.at("cookies")) {
        if (cookie.at("domain") == "apple.com" && cookie.at("path") == "/" &&
            !cookie.at("host_only").get<bool>() &&
            (!cookie.at("expires").get<std::int64_t>() ||
             cookie.at("expires").get<std::int64_t>() > now)) {
            result[cookie.at("name").get<std::string>()] = cookie.at("value");
        }
    }
    require(!result.empty(), "Store session has no unexpired root Apple cookies");
    return result;
}
} // namespace

Bytes StoreSession::ios_context(const std::string& country) const {
    require(protocol() == StoreProtocol::configurator,
            "iOS context requires a Configurator session");
    require(country.size() == 2 && std::all_of(country.begin(),
                                               country.end(),
                                               [](char c) {
                                                   return c >= 'a' && c <= 'z';
                                               }),
            "Country must be a two-letter lowercase code");
    Json context{{"dsid", account_id()},
                 {"guid", impl_->state.at("guid")},
                 {"country", country},
                 {"storefront", storefront()},
                 {"storeCookies", root_cookies(impl_->state)},
                 {"passwordToken", impl_->state.at("account").at("passwordToken")}};
    if (impl_->state.contains("purchase_url")) {
        context["purchaseUrl"] = impl_->state.at("purchase_url");
    }
    return bytes(context.dump(2));
}

Bytes StoreSession::testflight_context(ByteView hardware20, Headers device_headers) const {
    require(protocol() == StoreProtocol::macos_accounts && hardware20.size() == 20,
            "TestFlight context requires a Mac Store session and hardware20");
    require(impl_->state.contains("machine_id"), "Store session lacks its AMD machine ID");
    device_headers["X-Apple-AMD-M"] = impl_->state.at("machine_id").get<std::string>();
    device_headers["X-Apple-Store-Front"] = storefront();
    for (const auto& [key, value] : device_headers) {
        safe_header(key);
        safe_header(value);
    }
    return bytes(Json{{"dsid", account_id()},
                      {"udid", hex(hardware20)},
                      {"storeCookies", root_cookies(impl_->state)},
                      {"headers", device_headers}}
                     .dump(2));
}

void StoreSession::save_ios_context(const Path& path, const std::string& country) const {
    require(!std::filesystem::exists(path), "Store context output already exists");
    write_private(path, ios_context(country));
}

void StoreSession::save_testflight_context(const Path& path,
                                           ByteView hardware20,
                                           Headers device_headers) const {
    require(!std::filesystem::exists(path), "Store context output already exists");
    write_private(path, testflight_context(hardware20, std::move(device_headers)));
}

struct StoreClient::Impl {
    Path directory;
    ClientOptions options;
    StoreProtocol protocol;
    Json identity, bag;
    HardwareId hardware{};
    std::optional<Profile> profile;
    std::optional<SapSession> sap;

    Impl(Path path, ClientOptions config, StoreProtocol selected)
        : directory(std::move(path)), options(std::move(config)), protocol(selected) {
        (void)protocol_name(protocol);
        options.transport = configured_transport(options);
        if (!options.clock) {
            options.clock = [] {
                return static_cast<std::int64_t>(std::time(nullptr));
            };
        }
        if (std::filesystem::exists(directory / "identity.json")) {
            identity = Json::parse(read_file(directory / "identity.json"));
        } else {
            require(!std::filesystem::exists(directory / "adi.pb"),
                    "Store identity is missing beside its profile");
            auto guid = hex(random_bytes(6));
            std::transform(guid.begin(), guid.end(), guid.begin(), [](unsigned char c) {
                return char(std::toupper(c));
            });
            auto identifier = hex(random_bytes(16));
            identifier.insert(8, "-");
            identifier.insert(13, "-");
            identifier.insert(18, "-");
            identifier.insert(23, "-");
            identity = {{"version", 1},
                        {"guid", guid},
                        {"device_id", identifier},
                        {"hardware_hash", hex(random_bytes(20))}};
            write_private(directory / "identity.json", bytes(identity.dump(2)));
        }
        require(identity.value("version", 0) == 1 &&
                    identity.at("guid").get_ref<const std::string&>().size() == 12 &&
                    identity.at("device_id").get_ref<const std::string&>().size() == 36,
                "Invalid Store identity");
        require(unhex(identity.at("guid").get<std::string>()).size() == 6, "Invalid Store GUID");
        const auto binding = unhex(identity.at("hardware_hash").get<std::string>());
        require(binding.size() == 20, "Invalid Store hardware binding");
        std::copy(binding.begin(), binding.end(), hardware.begin());
        if (protocol != StoreProtocol::configurator &&
            std::filesystem::exists(directory / "adi.pb")) {
            profile = Profile::import_file(read_file(directory / "adi.pb"), hardware, "adi.pb");
            require(profile->kind() == ProfileKind::store, "Wrong Store profile kind");
        }
    }

    Headers common() const {
        Headers headers;
        if (protocol == StoreProtocol::macos_accounts) {
            headers = {{"User-Agent", mac_agent},
                       {"Content-Type", "application/x-apple-plist"},
                       {"X-Apple-Client-Application", "com.apple.TestFlight"},
                       {"Accept-Language", "en-US"}};
        } else if (protocol == StoreProtocol::configurator) {
            headers = {{"User-Agent", configurator_agent},
                       {"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"},
                       {"X-Apple-Client-Application", "me.majd.ipatool"},
                       {"Accept-Language", "en"}};
        } else {
            headers = {{"User-Agent", store_agent},
                       {"Content-Type", "application/x-apple-plist"},
                       {"Accept-Language", "en-US"}};
        }
        apply_device_headers(headers, options);
        return headers;
    }

    HttpResponse send(const std::string& url, const Json* body, Headers headers) const {
        apple_url(url);
        return options.transport(
            {url, body ? "POST" : "GET", std::move(headers), body ? encode_plist(*body) : Bytes{}});
    }

    Json checked(const std::string& url, const Json* body, Headers headers) const {
        const auto response = send(url, body, std::move(headers));
        if (response.status != 200) {
            throw apple_auth::Error(ErrorCode::network,
                                    "Store HTTP " + std::to_string(response.status));
        }
        return decode_store(response.body);
    }

    void load_bag() {
        if (!bag.empty()) {
            return;
        }
        const auto url =
            protocol == StoreProtocol::macos_accounts
                ? "https://bag.itunes.apple.com/"
                  "bag.xml?os=OS%20X&osVersion=13.1&deviceClass=Macintosh&product=TestFlight&"
                  "productVersion=4.4.0&profile=Accounts&profileVersion=1&format=json"
            : protocol == StoreProtocol::configurator
                ? "https://init.itunes.apple.com/bag.xml?guid=" +
                      identity.at("guid").get<std::string>()
                : "https://init.itunes.apple.com/bag.xml?ix=6";
        auto loaded = checked(url, nullptr, common());
        if (loaded.contains("urlBag")) {
            loaded = loaded.at("urlBag");
        }
        if (protocol == StoreProtocol::configurator) {
            loaded["sign-sap-setup"] = "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy";
            auto& endpoint = loaded.at("authenticateAccount").get_ref<std::string&>();
            if (!endpoint.ends_with('/')) {
                endpoint += '/';
            }
        }
        for (const char* field : {"authenticateAccount",
                                  "amd-finish-provisioning",
                                  "sign-sap-setup-cert",
                                  "sign-sap-setup"}) {
            if (std::string_view(field) == "amd-finish-provisioning" &&
                protocol != StoreProtocol::android_music) {
                continue;
            }
            require(loaded.contains(field) && loaded.at(field).is_string(),
                    "Incomplete Store URL bag");
            const bool certificate = std::string_view(field) == "sign-sap-setup-cert";
            apple_url(loaded.at(field).get<std::string>(), !certificate, certificate);
        }
        require(protocol != StoreProtocol::android_music || loaded.contains("storeFrontId"),
                "Missing Store storefront");
        bag = std::move(loaded);
    }

    std::string default_storefront() {
        // Saved Mac sessions already carry the account storefront. Generating
        // local AMD headers must not fetch an authentication bag again.
        if (protocol == StoreProtocol::macos_accounts && bag.empty()) {
            return "143441-1,29";
        }
        load_bag();
        if (protocol == StoreProtocol::configurator) {
            return "143478-2,13";
        }
        if (!bag.contains("storeFrontId")) {
            return "143441-1,29";
        }
        return scalar(bag.at("storeFrontId")) +
               bag.value("storefront-header-suffix", std::string());
    }

    void provision() {
        if (protocol == StoreProtocol::configurator) {
            return;
        }
        if (profile) {
            return;
        }
        load_bag();
        Headers adi_headers{{"User-Agent", store_agent},
                            {"Content-Type", "application/x-apple-plist"},
                            {"Accept-Language", "en-US"}};
        if (protocol == StoreProtocol::android_music) {
            apply_device_headers(adi_headers, options);
        }
        auto provisioning_bag =
            protocol == StoreProtocol::android_music
                ? bag
                : checked("https://init.itunes.apple.com/bag.xml?ix=6", nullptr, adi_headers);
        const auto now = options.clock();
        require(now >= 0 && static_cast<std::uint64_t>(now) <= UINT32_MAX,
                "Store provisioning clock exceeds range");
        const auto id = identity.at("device_id").get<std::string>();
        Headers control{
            {"User-Agent", "akd/1.0"},
            {"Content-Type", "application/x-www-form-urlencoded"},
            {"X-Mme-Device-Id", id},
            {"X-Apple-I-MD-LU", base64(bytes(id))},
            {"X-Apple-Client-App-Name", "akd"},
            {"X-Apple-I-Client-Time", utc_time(now)},
            {"X-Apple-I-TimeZone", "UTC"},
            {"X-Apple-Locale", "en_US"},
            {"X-MMe-Client-Info",
             "<MacBookPro18,3> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"}};
        const auto lookup =
            checked("https://gsa.apple.com/grandslam/GsService2/lookup", nullptr, control);
        const Json empty{{"Header", Json::object()}, {"Request", Json::object()}};
        const auto started =
            checked(
                lookup.at("urls").at("midStartProvisioning").get<std::string>(), &empty, control)
                .at("Response");
        require(started.at("Status").value("ec", -1) == 0, "Store start provisioning rejected");
        ProvisioningSession pending(
            binary(started, "spim"), hardware, static_cast<std::uint32_t>(now), ProfileKind::store);
        const Json finish{{"clientData", base64(pending.request())}, {"guid", identity.at("guid")}};
        const auto finished =
            checked(provisioning_bag.at("amd-finish-provisioning").get<std::string>(),
                    &finish,
                    adi_headers);
        const auto trust = binary(finished, "transportKey");
        require(trust.size() == 16, "Invalid Store trust key");
        Block key{};
        std::copy(trust.begin(), trust.end(), key.begin());
        auto completed = pending.finish(binary(finished, "settingInfo"), key);
        write_private(directory / "adi.pb", completed.export_file(hardware, "adi.pb"));
        profile = std::move(completed);
    }

    Headers headers() {
        provision();
        auto result = common();
        result["X-Apple-Store-Front"] = default_storefront();
        if (protocol == StoreProtocol::configurator) {
            result["X-Apple-Tz"] = "0";
            apply_device_headers(result, options);
            return result;
        }
        result["X-Apple-AMD-M"] = profile->machine_id_header();
        result["X-Apple-AMD"] = profile->otp_header(time_counter(options.clock()));
        apply_device_headers(result, options);
        return result;
    }

    void prepare_sap() {
        if (sap && sap->ready()) {
            return;
        }
        load_bag();
        const auto url = bag.at("sign-sap-setup-cert").get<std::string>();
        apple_url(url, false, true);
        const auto response = options.transport({url, "GET", common(), {}});
        if (response.status != 200) {
            throw apple_auth::Error(ErrorCode::network,
                                    "SAP certificate HTTP " + std::to_string(response.status));
        }
        const auto certificate = decode_store(response.body);
        SapSession pending(binary(certificate, "sign-sap-setup-cert"),
                           protocol == StoreProtocol::android_music ? SapPlatform::android
                                                                    : SapPlatform::macos,
                           options.sap_entropy ? options.sap_entropy() : SapEntropy::random());
        const Json body{{"sign-sap-setup-buffer",
                         Json::binary(Bytes(pending.request().begin(), pending.request().end()))}};
        auto setup_headers = common();
        if (protocol != StoreProtocol::android_music) {
            setup_headers["Content-Type"] = "application/x-plist";
        }
        const auto reply =
            checked(bag.at("sign-sap-setup").get<std::string>(), &body, std::move(setup_headers));
        pending.finish(binary(reply, "sign-sap-setup-buffer"));
        sap = std::move(pending);
    }
};

StoreClient::StoreClient(Path directory, ClientOptions options)
    : StoreClient(std::move(directory), StoreProtocol::android_music, std::move(options)) {}

StoreClient::StoreClient(Path directory, StoreProtocol protocol, ClientOptions options)
    : impl_(std::make_unique<Impl>(std::move(directory), std::move(options), protocol)) {}

StoreClient::~StoreClient() = default;
StoreClient::StoreClient(StoreClient&&) noexcept = default;
StoreClient& StoreClient::operator=(StoreClient&&) noexcept = default;

void StoreClient::provision() {
    impl_->provision();
}

Headers StoreClient::headers() {
    return impl_->headers();
}

StoreSession StoreClient::login_with_pet(const std::string& email,
                                         const AccountSession& account,
                                         const std::function<Headers()>& device_headers) {
    require(impl_->protocol == StoreProtocol::macos_accounts && !email.empty() &&
                bool(device_headers),
            "Mac Store login requires email, PET and fresh Mac device headers");
    const auto authenticated = parse_plist(account.plist);
    require(authenticated.at("adsid") == account.account_id &&
                authenticated.at("t").at("com.apple.gs.idms.pet").at("token") == account.pet &&
                !account.pet.empty(),
            "PET does not match its GSA session");
    const auto dsid = scalar(authenticated.at("DsPrsId"));
    require(!dsid.empty() && dsid.find_first_not_of("0123456789") == std::string::npos,
            "Invalid Store DSID");
    const auto expiry =
        authenticated.at("t").at("com.apple.gs.idms.pet").at("expiry").get<std::int64_t>();
    const auto valid_pet = [&] {
        require(expiry / 1000 > impl_->options.clock() + 5, "Mac PET has expired");
    };
    valid_pet();
    impl_->provision();
    impl_->prepare_sap();
    auto url = impl_->bag.at("authenticateAccount").get<std::string>();
    const Json payload{{"createSession", true},
                       {"credentialSource", 5},
                       {"guid", impl_->identity.at("guid")},
                       {"isSilentAuthentication", false},
                       {"password", account.pet},
                       {"rmp", "0"},
                       {"passwordSettings", {{"free", "always"}, {"paid", "always"}}},
                       {"appleId", email},
                       {"deviceOffersCheck", "true"}};
    const auto body = encode_plist(payload);
    Json cookies = Json::array();
    for (unsigned redirects = 0; redirects <= 3; ++redirects) {
        valid_pet();
        auto headers = impl_->common();
        const auto fresh = device_headers(), store = impl_->headers();
        for (const auto* name : {"X-Apple-I-MD",
                                 "X-Apple-I-MD-M",
                                 "X-Apple-I-MD-RINFO",
                                 "X-Apple-I-MD-LU",
                                 "X-Apple-I-Client-Time",
                                 "X-Apple-I-TimeZone",
                                 "X-Apple-Locale"}) {
            require(fresh.contains(name), "Missing Mac anisette header");
            safe_header(fresh.at(name));
            headers[name] = fresh.at(name);
        }
        headers["X-Apple-AMD"] = store.at("X-Apple-AMD");
        headers["X-Apple-AMD-M"] = store.at("X-Apple-AMD-M");
        headers["X-DSID"] = dsid;
        headers["X-Apple-Tz"] = "0";
        headers["Accept"] = "*/*";
        headers["X-Apple-ActionSignature"] = base64(impl_->sap->sign(body));
        const auto cookie = cookie_header(cookies, url, impl_->options.clock());
        if (!cookie.empty()) {
            headers["Cookie"] = cookie;
        }
        const auto response = impl_->options.transport({url, "POST", std::move(headers), body});
        cookies_update(cookies, url, response, impl_->options.clock());
        if (response.status == 302 || response.status == 307) {
            auto next = header(response, "location");
            require(redirects < 3 && !next.empty(), "Invalid Mac Store redirect");
            if (next.starts_with('/') && !next.starts_with("//")) {
                next = "https://" + apple_url(url, true).host + next;
            }
            apple_url(next, true);
            url = std::move(next);
            continue;
        }
        if (response.status != 200) {
            throw apple_auth::Error(ErrorCode::authentication,
                                    "Mac Store authentication HTTP " +
                                        std::to_string(response.status));
        }
        const auto result = decode_store(response.body);
        require(result.value("status", Json()) == 0 && result.contains("dsPersonId") &&
                    scalar(result.at("dsPersonId")) == dsid && result.contains("passwordToken"),
                "Mac Store authentication rejected");
        auto storefront = header(response, "x-set-apple-store-front");
        if (storefront.empty()) {
            storefront = header(response, "x-apple-store-front");
        }
        if (storefront.empty()) {
            storefront = impl_->default_storefront();
        }
        return StoreSession::from_plist(
            encode_plist({{"kind", "apple-auth-store"},
                          {"version", 1},
                          {"protocol", protocol_name(impl_->protocol)},
                          {"guid", impl_->identity.at("guid")},
                          {"user_agent", impl_->common().at("User-Agent")},
                          {"machine_id", store.at("X-Apple-AMD-M")},
                          {"storefront", storefront},
                          {"cookies", cookies},
                          {"account", result}}));
    }
    throw netdetail::Error("Mac Store redirect limit exceeded");
}

StoreSession StoreClient::login(const std::string& email,
                                const std::string& password,
                                const TwoFactor& two_factor) {
    require(!email.empty() && !password.empty(), "Store login requires email and password");
    require(impl_->protocol != StoreProtocol::macos_accounts,
            "Mac Store login requires an existing PET session");
    impl_->provision();
    impl_->prepare_sap();
    auto url = impl_->bag.at("authenticateAccount").get<std::string>();
    Json cookies = Json::array();
    std::string code;
    bool retried = false;
    unsigned redirects = 0;
    for (;;) {
        Json payload{{"attempt", code.empty() && !retried ? "1" : "2"},
                     {"appleId", email},
                     {"password", password + code},
                     {"rmp", "0"},
                     {"createSession", "true"},
                     {"why", "signIn"},
                     {"guid", impl_->identity.at("guid")}};
        if (impl_->protocol == StoreProtocol::configurator) {
            payload["createSession"] = true;
            payload["credentialSource"] = 0;
            payload["deviceOffersCheck"] = "true";
            payload["isSilentAuthentication"] = false;
            payload["passwordSettings"] = {{"free", "always"}, {"paid", "always"}};
        }
        auto request_headers = impl_->headers();
        const auto cookie = cookie_header(cookies, url, impl_->options.clock());
        if (!cookie.empty()) {
            request_headers["Cookie"] = cookie;
        }
        const auto body = encode_plist(payload);
        request_headers["X-Apple-ActionSignature"] = base64(impl_->sap->sign(body));
        const auto response =
            impl_->options.transport({url, "POST", std::move(request_headers), body});
        cookies_update(cookies, url, response, impl_->options.clock());
        if (response.status == 302 || response.status == 307) {
            auto next = header(response, "location");
            require(++redirects <= 3 && !next.empty(), "Invalid Store authentication redirect");
            if (next.starts_with('/') && !next.starts_with("//")) {
                const auto slash = url.find('/', 8);
                next = url.substr(0, slash) + next;
            }
            apple_url(next, true);
            url = std::move(next);
            continue;
        }
        if (response.status != 200) {
            throw apple_auth::Error(ErrorCode::authentication,
                                    "Store authentication HTTP " + std::to_string(response.status));
        }
        const auto result = decode_store(response.body);
        const bool accepted_status =
            (impl_->protocol == StoreProtocol::configurator &&
             result.value("status", Json()) == 0) ||
            (result.value("m-allowed", false) &&
             result.value("action", Json::object()).value("kind", "") == "SetUserAndReset");
        if (accepted_status && result.contains("dsPersonId") && result.contains("passwordToken")) {
            auto storefront = header(response, "x-set-apple-store-front");
            if (storefront.empty()) {
                storefront = impl_->default_storefront();
            }
            return StoreSession::from_plist(
                encode_plist({{"kind", "apple-auth-store"},
                              {"version", 1},
                              {"guid", impl_->identity.at("guid")},
                              {"protocol", protocol_name(impl_->protocol)},
                              {"user_agent", impl_->common().at("User-Agent")},
                              {"purchase_url",
                               "https://" + apple_url(url, true).host +
                                   "/WebObjects/MZFinance.woa/wa/buyProduct"},
                              {"storefront", storefront},
                              {"cookies", cookies},
                              {"account", result}}));
        }
        const auto failure = result.value("failureType", std::string());
        const auto error_code =
            result.contains("errorCode") ? scalar(result.at("errorCode")) : std::string();
        const bool verification_required =
            error_code == "-22947" ||
            (failure.empty() &&
             result.value("customerMessage", "") == "MZFinance.BadLogin.Configurator_message");
        if (verification_required) {
            if (!code.empty() || !two_factor) {
                throw apple_auth::Error(ErrorCode::authentication,
                                        "Store login requires a fresh two-factor code");
            }
            code = two_factor();
            require(code.size() == 6 && std::all_of(code.begin(),
                                                    code.end(),
                                                    [](unsigned char c) {
                                                        return c >= '0' && c <= '9';
                                                    }),
                    "Store two-factor code must contain six digits");
            continue;
        }
        if (impl_->protocol == StoreProtocol::android_music && failure == "-5000" && !retried &&
            code.empty()) {
            retried = true;
            continue;
        }
        throw apple_auth::Error(ErrorCode::authentication, "Store authentication rejected");
    }
}

HttpResponse StoreClient::request(StoreSession& session, HttpRequest request) {
    require((request.method == "GET" || request.method == "HEAD" || request.method == "POST" ||
             request.method == "PUT" || request.method == "PATCH" || request.method == "DELETE") &&
                request.body.size() <= 1024 * 1024 &&
                ((request.method != "GET" && request.method != "HEAD") || request.body.empty()),
            "Unsupported Store HTTP method or body");
    if (request.url.find("://") == std::string::npos) {
        impl_->load_bag();
        require(impl_->bag.contains(request.url) && impl_->bag.at(request.url).is_string(),
                "Unknown Store URL bag endpoint");
        request.url = impl_->bag.at(request.url).get<std::string>();
    }
    apple_url(request.url, true);
    require(session.protocol() == impl_->protocol,
            "Store request protocol differs from its saved session");
    require(session.impl_ && session.impl_->state.at("guid") == impl_->identity.at("guid"),
            "Store session belongs to another device");
    for (auto it = request.headers.begin(); it != request.headers.end();) {
        const auto name = lower(it->first);
        if (name == "x-token" || name == "x-dsid" || name == "cookie" ||
            name == "x-apple-actionsignature" || name == "x-apple-amd" || name == "x-apple-amd-m") {
            it = request.headers.erase(it);
        } else {
            ++it;
        }
    }
    impl_->prepare_sap();
    const auto custom_headers = request.headers;
    for (unsigned redirects = 0;; ++redirects) {
        auto headers = impl_->headers();
        for (const auto& [key, value] : custom_headers) {
            headers[key] = value;
        }
        for (const auto& [key, value] : session.headers(request.url)) {
            headers[key] = value;
        }
        headers.erase("Cookie");
        const auto cookie =
            cookie_header(session.impl_->state.at("cookies"), request.url, impl_->options.clock());
        if (!cookie.empty()) {
            headers["Cookie"] = cookie;
        }
        headers["X-Apple-ActionSignature"] = base64(impl_->sap->sign(request.body));
        request.headers = std::move(headers);
        const auto response = impl_->options.transport(request);
        cookies_update(
            session.impl_->state["cookies"], request.url, response, impl_->options.clock());
        const bool redirect =
            response.status == 307 || response.status == 308 ||
            ((request.method == "GET" || request.method == "HEAD") &&
             (response.status == 301 || response.status == 302 || response.status == 303));
        if (!redirect) {
            return response;
        }
        auto next = header(response, "location");
        require(redirects < 3 && !next.empty(), "Invalid Store request redirect");
        if (next.starts_with('/') && !next.starts_with("//")) {
            next = request.url.substr(0, request.url.find('/', 8)) + next;
        }
        apple_url(next, true);
        request.url = std::move(next);
    }
}
} // namespace apple_auth
