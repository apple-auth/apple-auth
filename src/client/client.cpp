#include "client/client_internal.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <regex>

namespace apple_auth {
namespace {
using namespace netdetail;

struct DeviceDescription {
    DevicePlatform platform;
    const char* name;
    const char* client_info;
    const char* user_agent;
    const char* application;
};

constexpr DeviceDescription device_descriptions[] = {
    {DevicePlatform::windows,
     "windows",
     "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 (com.apple.iCloud/1)>",
     "iCloud/7.4",
     "Setup"},
    {DevicePlatform::mac,
     "mac",
     "<MacBookPro18,3> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
     "akd/1.0",
     "akd"},
    {DevicePlatform::iphone,
     "iphone",
     "<iPhone15,2> <iPhone OS;17.4;21E219> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
     "akd/1.0",
     "akd"},
    {DevicePlatform::android,
     "android",
     "<Pixel 8> <Android;14;UQ1A.240205.004> "
     "<com.apple.AuthKit/1 (com.apple.android.music/4.9.6)>",
     "AppleMusic/4.9.6",
     "Music"}};

const DeviceDescription& describe_device(DevicePlatform platform) {
    for (const auto& description : device_descriptions) {
        if (description.platform == platform) {
            return description;
        }
    }
    throw apple_auth::Error(ErrorCode::invalid_argument, "Unsupported device platform");
}

const DeviceDescription& describe_device(const std::string& name) {
    for (const auto& description : device_descriptions) {
        if (name == description.name) {
            return description;
        }
    }
    throw apple_auth::Error(ErrorCode::invalid_data, "Invalid saved device platform");
}

bool has_mac_options(const MacDevice& device) {
    return !device.model.empty() || !device.macos_version.empty() || !device.macos_build.empty();
}

bool has_iphone_options(const IPhoneDevice& device) {
    return !device.model.empty() || !device.ios_version.empty() || !device.ios_build.empty();
}

void validate_iphone_device(const IPhoneDevice& device) {
    static const std::regex model("iPhone[0-9]+,[0-9]+");
    static const std::regex version("[0-9]{1,2}\\.[0-9]{1,2}(\\.[0-9]{1,2})?");
    static const std::regex build("[0-9]{2}[A-Z][0-9]{1,5}[a-z]?");
    require(device.model.size() <= 64 && std::regex_match(device.model, model),
            "Invalid iPhone model identifier; expected e.g. iPhone19,4");
    require(device.ios_version.size() <= 8 && std::regex_match(device.ios_version, version),
            "Invalid iOS version; expected e.g. 27.2");
    require(device.ios_build.size() <= 9 && std::regex_match(device.ios_build, build),
            "Invalid iOS build; expected e.g. 24B91020");
}

IPhoneDevice resolve_iphone_device(const IPhoneDevice& requested, IPhoneDevice saved) {
    if ((!requested.ios_version.empty() && requested.ios_version != saved.ios_version) ||
        (!requested.model.empty() && requested.model != saved.model)) {
        saved.ios_build.clear();
    }
    if (!requested.model.empty()) {
        saved.model = requested.model;
    }
    if (!requested.ios_version.empty()) {
        saved.ios_version = requested.ios_version;
    }
    if (!requested.ios_build.empty()) {
        saved.ios_build = requested.ios_build;
    }
    require(!saved.ios_build.empty(), "Provide an explicit iOS build for custom iPhone metadata");
    validate_iphone_device(saved);
    return saved;
}

std::string known_macos_build(const std::string& version) {
    constexpr std::pair<const char*, const char*> releases[] = {{"13.1", "22C65"},
                                                                {"14.4.1", "23E224"},
                                                                {"15.0", "24A335"},
                                                                {"26.2", "25C56"},
                                                                {"27.0.1", "26A434"},
                                                                {"27.2", "26B123"}};
    for (const auto& [release, build] : releases) {
        if (version == release) {
            return build;
        }
    }
    return {};
}

void validate_mac_device(const MacDevice& device) {
    static const std::regex model("Mac[A-Za-z]*[0-9]+,[0-9]+");
    static const std::regex version("[0-9]{1,2}\\.[0-9]{1,2}(\\.[0-9]{1,2})?");
    static const std::regex build("[0-9]{2}[A-Z][0-9]{1,5}[a-z]?");
    require(device.model.size() <= 64 && std::regex_match(device.model, model),
            "Invalid Mac model identifier; expected e.g. MacBookPro18,3 or Mac14,2");
    require(device.macos_version.size() <= 8 && std::regex_match(device.macos_version, version),
            "Invalid macOS version; expected e.g. 14.4.1");
    require(device.macos_build.size() <= 9 && std::regex_match(device.macos_build, build),
            "Invalid macOS build; expected e.g. 23E224");
}

MacDevice resolve_mac_device(const MacDevice& requested, MacDevice saved) {
    if (!requested.model.empty()) {
        saved.model = requested.model;
    }
    if (!requested.macos_version.empty() && requested.macos_version != saved.macos_version) {
        saved.macos_version = requested.macos_version;
        saved.macos_build = known_macos_build(saved.macos_version);
    }
    if (!requested.macos_build.empty()) {
        saved.macos_build = requested.macos_build;
    }
    require(!saved.macos_build.empty(),
            "Unknown macOS release; provide its macOS build explicitly");
    validate_mac_device(saved);
    return saved;
}

Json mac_device_json(const MacDevice& device) {
    return {{"model", device.model},
            {"macos_version", device.macos_version},
            {"macos_build", device.macos_build}};
}

std::string uppercase(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return text;
}

std::string normalize_serial(const std::string& serial) {
    if (serial.empty() || serial == "0") {
        return {};
    }
    require(serial.size() <= 32 && std::all_of(serial.begin(),
                                               serial.end(),
                                               [](unsigned char c) {
                                                   return (c >= 'a' && c <= 'z') ||
                                                          (c >= 'A' && c <= 'Z') ||
                                                          (c >= '0' && c <= '9') || c == '-';
                                               }),
            "Invalid serial number; expected up to 32 ASCII letters, digits or hyphens");
    return serial;
}

std::string device_uuid() {
    auto data = random_bytes(16);
    data[6] = (data[6] & 15) | 64;
    data[8] = (data[8] & 63) | 128;
    const auto value = uppercase(hex(data));
    return value.substr(0, 8) + "-" + value.substr(8, 4) + "-" + value.substr(12, 4) + "-" +
           value.substr(16, 4) + "-" + value.substr(20);
}

std::string utc_time(std::int64_t seconds) {
    const auto timestamp = static_cast<std::time_t>(seconds);
    std::tm value{};
#ifdef _WIN32
    gmtime_s(&value, &timestamp);
#else
    gmtime_r(&timestamp, &value);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &value);
    return buffer;
}

Bytes binary_field(const Json& response, const char* key) {
    require(response.contains(key), "Missing provisioning field: " + std::string(key));
    const auto& value = response.at(key);
    if (value.is_binary()) {
        return value.get_binary();
    }
    require(value.is_string(), "Invalid provisioning field type");
    return unbase64(value.get<std::string>());
}

void check_status(const Json& response) {
    const auto status = response.value("Status", Json::object());
    require(status.is_object() && status.contains("ec") && status.at("ec").is_number_integer(),
            "Missing provisioning result code");
    const auto code = status.at("ec").get<std::int64_t>();
    if (code != 0) {
        throw apple_auth::Error(ErrorCode::authentication,
                                "Device provisioning rejected (code " + std::to_string(code) + ")");
    }
}

std::filesystem::path saved_profile_path(const std::filesystem::path& directory) {
    const auto canonical = directory / "adi.pb";
    if (std::filesystem::exists(canonical) || !std::filesystem::is_directory(directory)) {
        return canonical;
    }
    std::optional<std::filesystem::path> legacy;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const auto name = entry.path().filename().u8string();
        if (!entry.is_regular_file() || name.size() != 15 || !name.starts_with(u8"adi-") ||
            !name.ends_with(u8".pb") ||
            std::u8string_view(name).substr(4, 8).find_first_not_of(u8"0123456789abcdefABCDEF") !=
                std::u8string_view::npos) {
            continue;
        }
        require(!legacy, "Multiple legacy ADI profiles; use a separate device directory");
        legacy = entry.path();
    }
    return legacy.value_or(canonical);
}

Profile load_grandslam_profile(const std::filesystem::path& path,
                               const HardwareId& hardware,
                               ProfilePlatform platform) {
    auto profile = Profile::import_file(read_file(path), hardware, path.filename().string());
    require(profile.kind() == ProfileKind::grandslam, "State file has an unsupported profile");
    require(profile.platform() == platform, "State profile differs from the selected ADI platform");
    const auto canonical = path.parent_path() / profile.filename();
    if (path != canonical) {
        // Filenames bind the file key; authenticate the re-encrypted copy before removal.
        write_private(canonical, profile.export_file(hardware, profile.filename()));
        try {
            (void)Profile::import_file(read_file(canonical), hardware, profile.filename());
        } catch (...) {
            std::error_code ignored;
            std::filesystem::remove(canonical, ignored);
            throw;
        }
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
    return profile;
}
} // namespace

struct Client::Impl {
    std::filesystem::path directory;
    ClientOptions options;
    netdetail::Json identity;
    const DeviceDescription* description = nullptr;
    MacDevice mac_device;
    IPhoneDevice iphone_device;
    std::string serial_number;
    HardwareId hardware{};
    std::optional<Profile> profile;
    std::unique_ptr<StoreClient> store;
    std::unique_ptr<StoreClient> mac_store;

    StoreClient& store_client(StoreProtocol protocol = StoreProtocol::android_music) {
        netdetail::require(protocol != StoreProtocol::configurator,
                           "Use an explicit Configurator StoreClient");
        auto& selected = protocol == StoreProtocol::macos_accounts ? mac_store : store;
        if (!selected) {
            selected = std::make_unique<StoreClient>(directory / "store", protocol, options);
        }
        return *selected;
    }

    Impl(std::filesystem::path path, ClientOptions config)
        : directory(std::move(path)), options(std::move(config)) {
        options.transport = netdetail::configured_transport(options);
        if (!options.clock) {
            options.clock = [] {
                return static_cast<std::int64_t>(std::time(nullptr));
            };
        }
        const auto identity_path = directory / "identity.json";
        const auto profile_path = saved_profile_path(directory);
        const bool new_identity = !std::filesystem::exists(identity_path);
        bool identity_upgraded = false;
        const auto* requested = options.device_platform == DevicePlatform::automatic
                                    ? nullptr
                                    : &describe_device(options.device_platform);
        if (!new_identity) {
            identity = netdetail::Json::parse(netdetail::read_file(identity_path));
            const auto version = identity.value("version", 0);
            netdetail::require(version == 1 || version == 2 || version == 3 || version == 4,
                               "Unsupported device identity version");
            description = version == 1
                              ? &describe_device(DevicePlatform::windows)
                              : &describe_device(identity.at("platform").get<std::string>());
            netdetail::require(
                requested == nullptr || requested == description,
                "Device platform differs from saved identity; use a new state directory");
            netdetail::require(
                provisioning_platform() != ProfilePlatform::mac || version == 3,
                std::string("Legacy ") +
                    (description->platform == DevicePlatform::mac ? "Mac" : "iPhone") +
                    " identity uses Windows ADI; use a new state directory");
            netdetail::require(version != 4 || description->platform == DevicePlatform::android,
                               "Invalid Android device identity");
            if (provisioning_platform() == ProfilePlatform::android && version != 4) {
                netdetail::require(
                    !std::filesystem::exists(profile_path),
                    "Legacy Android identity uses Windows ADI; use a new state directory");
                identity["version"] = 4;
                identity_upgraded = true;
            }
        } else {
            netdetail::require(!std::filesystem::exists(profile_path),
                               "Device identity is missing beside an existing profile");
            description = requested ? requested : &describe_device(DevicePlatform::windows);
            identity = {
                {"version",
                 provisioning_platform() == ProfilePlatform::mac       ? 3
                 : provisioning_platform() == ProfilePlatform::android ? 4
                                                                       : 2},
                {"platform", description->name},
                {"device_id", device_uuid()},
                {"local_user_hash",
                 uppercase(
                     netdetail::hex(netdetail::digest("SHA256", netdetail::random_bytes(32))))},
                {"hardware_hash", netdetail::hex(netdetail::random_bytes(hardware.size()))}};
            if (provisioning_platform() == ProfilePlatform::mac) {
                identity["local_user_hash"] =
                    base64(netdetail::bytes(identity.at("device_id").get<std::string>()));
            }
        }
        const bool mac = description->platform == DevicePlatform::mac;
        netdetail::require(mac || !has_mac_options(options.mac_device),
                           "Mac model and macOS options require the Mac device platform");
        if (mac) {
            MacDevice saved{"MacBookPro18,3", "13.1", "22C65"};
            if (!new_identity && identity.contains("mac_device")) {
                const auto& data = identity.at("mac_device");
                saved = {data.at("model").get<std::string>(),
                         data.at("macos_version").get<std::string>(),
                         data.at("macos_build").get<std::string>()};
            }
            validate_mac_device(saved);
            mac_device = resolve_mac_device(options.mac_device, saved);
            netdetail::require(
                new_identity || mac_device == saved,
                "Mac model or macOS differs from saved identity; use a new state directory");
            if (new_identity) {
                identity["mac_device"] = mac_device_json(mac_device);
            }
        }
        const bool iphone = description->platform == DevicePlatform::iphone;
        netdetail::require(iphone || !has_iphone_options(options.iphone_device),
                           "iPhone model and iOS options require the iPhone device platform");
        if (iphone) {
            IPhoneDevice saved{"iPhone15,2", "17.4", "21E219"};
            if (!new_identity && identity.contains("iphone_device")) {
                const auto& data = identity.at("iphone_device");
                saved = {data.at("model").get<std::string>(),
                         data.at("ios_version").get<std::string>(),
                         data.at("ios_build").get<std::string>()};
            }
            validate_iphone_device(saved);
            iphone_device = resolve_iphone_device(options.iphone_device, saved);
            netdetail::require(
                new_identity || iphone_device == saved,
                "iPhone model or iOS differs from saved identity; use a new state directory");
            if (new_identity) {
                identity["iphone_device"] = {{"model", iphone_device.model},
                                             {"ios_version", iphone_device.ios_version},
                                             {"ios_build", iphone_device.ios_build}};
            }
        }
        const auto& local_user = identity.at("local_user_hash").get_ref<const std::string&>();
        const auto saved_serial = normalize_serial(identity.value("serial_number", std::string()));
        serial_number = normalize_serial(options.serial_number.value_or(saved_serial));
        netdetail::require(new_identity || uppercase(serial_number) == uppercase(saved_serial),
                           "Serial number differs from saved identity; use a new state directory");
        if (!new_identity) {
            serial_number = saved_serial;
        }
        if (new_identity && !serial_number.empty()) {
            identity["serial_number"] = serial_number;
        }
        netdetail::require(
            identity.value("device_id", std::string()).size() == 36 &&
                (provisioning_platform() == ProfilePlatform::mac
                     ? local_user ==
                           base64(netdetail::bytes(identity.at("device_id").get<std::string>()))
                     : local_user.size() == 64),
            "Invalid device identity");
        const auto decoded = netdetail::unhex(identity.at("hardware_hash").get<std::string>());
        netdetail::require(decoded.size() == hardware.size(), "Invalid hardware binding");
        std::copy(decoded.begin(), decoded.end(), hardware.begin());
        if (std::filesystem::exists(profile_path)) {
            netdetail::require(
                identity.contains("routing_info") && identity.at("routing_info").is_string() &&
                    !identity.at("routing_info").get_ref<const std::string&>().empty(),
                "Provisioning metadata is incomplete");
            profile = load_grandslam_profile(profile_path, hardware, provisioning_platform());
        }
        if (new_identity || identity_upgraded) {
            save_identity();
        }
    }

    void save_identity() const {
        netdetail::write_private(directory / "identity.json", netdetail::bytes(identity.dump(2)));
    }

    ProfilePlatform provisioning_platform() const noexcept {
        switch (description->platform) {
        case DevicePlatform::mac:
        case DevicePlatform::iphone:
            return ProfilePlatform::mac;
        case DevicePlatform::android:
            return ProfilePlatform::android;
        default:
            return ProfilePlatform::windows;
        }
    }

    Headers device_headers(const DeviceDescription& environment) const {
        auto info = std::string(environment.client_info);
        if (environment.platform == DevicePlatform::mac &&
            description->platform == DevicePlatform::mac) {
            info = "<" + mac_device.model + "> <macOS;" + mac_device.macos_version + ";" +
                   mac_device.macos_build + "> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
        } else if (environment.platform == DevicePlatform::iphone) {
            info = "<" + iphone_device.model + "> <iPhone OS;" + iphone_device.ios_version + ";" +
                   iphone_device.ios_build + "> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
        }
        Headers headers{{"User-Agent", environment.user_agent},
                        {"Content-Type", "application/x-www-form-urlencoded"},
                        {"X-Mme-Device-Id", identity.at("device_id").get<std::string>()},
                        {"X-Apple-I-MD-LU", identity.at("local_user_hash").get<std::string>()},
                        {"X-MMe-Client-Info", info},
                        {"X-Apple-Client-App-Name", environment.application},
                        {"X-Apple-I-Client-Time", utc_time(options.clock())},
                        {"X-Apple-I-TimeZone", "UTC"},
                        {"X-Apple-Locale", "en_US"}};
        if (!serial_number.empty()) {
            headers["X-Apple-I-SRL-NO"] = serial_number;
        }
        netdetail::apply_device_headers(headers, options);
        return headers;
    }

    netdetail::Json request(const std::string& url, const netdetail::Json* body = nullptr) const {
        check_apple_endpoint(url);
        const auto response = options.transport(HttpRequest{
            url,
            body ? "POST" : "GET",
            device_headers(describe_device(provisioning_platform() == ProfilePlatform::mac
                                               ? DevicePlatform::mac
                                               : description->platform)),
            body ? netdetail::encode_plist(*body) : Bytes{}});
        if (response.status != 200) {
            throw apple_auth::Error(ErrorCode::network,
                                    "Provisioning HTTP " + std::to_string(response.status));
        }
        return netdetail::parse_plist(response.body);
    }

    void provision() {
        if (profile) {
            return;
        }
        const auto seconds = options.clock();
        netdetail::require(seconds >= 0 && static_cast<std::uint64_t>(seconds) <= UINT32_MAX,
                           "Provisioning clock exceeds protocol range");
        const auto lookup = request("https://gsa.apple.com/grandslam/GsService2/lookup");
        netdetail::require(lookup.contains("urls") && lookup.at("urls").is_object(),
                           "Invalid provisioning lookup");
        const auto& urls = lookup.at("urls");
        const netdetail::Json empty = {{"Header", netdetail::Json::object()},
                                       {"Request", netdetail::Json::object()}};
        const auto started =
            request(urls.at("midStartProvisioning").get<std::string>(), &empty).at("Response");
        check_status(started);
        const auto challenge = binary_field(started, "spim");
        ProvisioningSession session(
            challenge, hardware, static_cast<std::uint32_t>(seconds), provisioning_platform());
        const netdetail::Json finish = {{"Header", netdetail::Json::object()},
                                        {"Request", {{"cpim", base64(session.request())}}}};
        const auto finished =
            request(urls.at("midFinishProvisioning").get<std::string>(), &finish).at("Response");
        check_status(finished);
        const auto trust = binary_field(finished, "tk");
        netdetail::require(trust.size() == 16, "Invalid trust-key length");
        Block trust_key{};
        std::copy(trust.begin(), trust.end(), trust_key.begin());
        auto completed = session.finish(binary_field(finished, "ptm"), trust_key);
        const auto encoded = completed.export_file(hardware, completed.filename());
        netdetail::require(
            finished.contains("X-Apple-I-MD-RINFO") &&
                finished.at("X-Apple-I-MD-RINFO").is_string() &&
                !finished.at("X-Apple-I-MD-RINFO").get_ref<const std::string&>().empty(),
            "Missing routing information");
        identity["routing_info"] = finished.at("X-Apple-I-MD-RINFO");
        save_identity();
        netdetail::write_private(directory / completed.filename(), encoded);
        profile = std::move(completed);
    }

    Headers headers() {
        provision();
        auto result = device_headers(*description);
        result["X-Apple-I-MD"] = profile->otp_header(time_counter(options.clock()));
        result["X-Apple-I-MD-M"] = profile->machine_id_header();
        result["X-Apple-I-MD-RINFO"] = identity.at("routing_info").get<std::string>();
        netdetail::apply_device_headers(result, options);
        return result;
    }
};

Client::Client(std::filesystem::path directory, ClientOptions options)
    : impl_(std::make_unique<Impl>(std::move(directory), std::move(options))) {}

Client::~Client() = default;
Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

void Client::provision() {
    impl_->provision();
}

Headers Client::headers() {
    return impl_->headers();
}

void Client::provision_store() {
    impl_->store_client().provision();
}

Headers Client::store_headers() {
    return impl_->store_client().headers();
}

StoreSession Client::login_store(const std::string& email,
                                 const std::string& password,
                                 const TwoFactor& two_factor) {
    return impl_->store_client().login(email, password, two_factor);
}

HttpResponse Client::store_request(StoreSession& session, HttpRequest request) {
    return impl_->store_client(session.protocol()).request(session, std::move(request));
}

StoreSession Client::login_store_with_pet(const std::string& email, const AccountSession& account) {
    netdetail::require(device_platform() == DevicePlatform::mac,
                       "Mac Store PET login requires a Mac Client");
    return impl_->store_client(StoreProtocol::macos_accounts).login_with_pet(email, account, [&] {
        return headers();
    });
}

DevicePlatform Client::device_platform() const noexcept {
    return impl_->description->platform;
}

MacDevice Client::mac_device() const {
    return impl_->mac_device;
}

IPhoneDevice Client::iphone_device() const {
    return impl_->iphone_device;
}

std::string Client::serial_number() const {
    return impl_->serial_number;
}

AccountSession
Client::login(const std::string& email, const std::string& password, const TwoFactor& two_factor) {
    const auto session = netdetail::grandslam_login(
        email,
        password,
        [&] {
            return headers();
        },
        two_factor,
        impl_->options.transport,
        impl_->options.clock);
    netdetail::require(session.contains("adsid") && session.at("adsid").is_string(),
                       "Account session has no account ID");
    return {session.at("adsid").get<std::string>(),
            session.at("t").at("com.apple.gs.idms.pet").at("token").get<std::string>(),
            netdetail::encode_plist(session)};
}

void AccountSession::save(const std::filesystem::path& file) const {
    netdetail::write_private(file, plist);
}

AccountSession AccountSession::from_plist(ByteView data) {
    const auto session = netdetail::parse_plist(data);
    netdetail::require(netdetail::grandslam_account_state(netdetail::Json::object(), session) ==
                           netdetail::AccountState::authenticated,
                       "Account session has not completed authentication");
    const auto id = session.at("adsid").get<std::string>();
    const auto pet = session.at("t").at("com.apple.gs.idms.pet").at("token").get<std::string>();
    netdetail::require(!id.empty() && !pet.empty(), "Incomplete saved account session");
    return {id, pet, Bytes(data.begin(), data.end())};
}

AccountSession AccountSession::load(const std::filesystem::path& file) {
    return from_plist(netdetail::read_file(file, 1u << 20));
}

AccountSession Client::login_with_options(const std::string& email,
                                          const std::string& password,
                                          const VerificationOptions& verification) {
    const auto session = netdetail::grandslam_login(
        email,
        password,
        [&] {
            return headers();
        },
        verification.code,
        impl_->options.transport,
        impl_->options.clock,
        &verification);
    return {session.at("adsid").get<std::string>(),
            session.at("t").at("com.apple.gs.idms.pet").at("token").get<std::string>(),
            netdetail::encode_plist(session)};
}

DeveloperSession Client::developer_session(const AccountSession& account) {
    return netdetail::exchange_developer_session(
        account,
        [&] {
            return headers();
        },
        impl_->options.transport,
        impl_->options.clock);
}

Headers Client::developer_headers(const DeveloperSession& session) {
    // GrandSlam ADSID is opaque; Apple also issues non-numeric identifiers.
    const auto visible_ascii = [](const std::string& value) {
        return std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return c >= 33 && c <= 126;
        });
    };
    netdetail::require(!session.account_id.empty() && session.account_id.size() <= 4096 &&
                           visible_ascii(session.account_id) &&
                           !session.token.empty() && session.token.size() <= 32 * 1024 &&
                           visible_ascii(session.token),
                       "Invalid Developer Session");
    netdetail::require(!session.expires_at_ms ||
                           impl_->options.clock() < session.expires_at_ms / 1000,
                       "Developer Session has expired; exchange a fresh session");
    auto result = headers();
    result["X-Apple-GS-Token"] = session.token;
    result["X-Apple-I-Identity-Id"] = session.account_id;
    result["X-Apple-App-Info"] = "com.apple.gs.xcode.auth";
    result["User-Agent"] = "Xcode";
    netdetail::apply_device_headers(result, impl_->options);
    return result;
}
} // namespace apple_auth
