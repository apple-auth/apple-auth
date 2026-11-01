#include "appstore/data/protocol.hpp"
#include "appstore/internal.hpp"
#include "client/data/store.hpp"
#include "crypto/backend.hpp"
#include <algorithm>
#include <apple_auth/appstore.hpp>
#include <apple_auth/store_core.hpp>
#include <cctype>
#include <fstream>
#include <memory>
#include <set>
#include <zip.h>

namespace apple_auth {
namespace {
using namespace netdetail;

Transport ios_transport(Transport transport, Headers headers) {
    ClientOptions options;
    options.transport = std::move(transport);
    options.headers = std::move(headers);
    return configured_transport(options);
}

std::string scalar(const Json& value) {
    require(value.is_string() || value.is_number_unsigned() || value.is_number_integer(),
            "Invalid App Store identifier");
    return value.is_string() ? value.get<std::string>() : value.dump();
}

bool decimal(const std::string& value) {
    return !value.empty() && value.size() <= 20 &&
           std::all_of(value.begin(), value.end(), [](char c) {
               return c >= '0' && c <= '9';
           });
}

void safe_header(const std::string& value) {
    require(!value.empty() && value.size() <= 65536 &&
                std::all_of(value.begin(),
                            value.end(),
                            [](unsigned char c) {
                                return c >= 32 && c != 127;
                            }),
            "Invalid App Store header");
}

std::string checked_asset_url(const std::string& url) {
    require(url.starts_with("https://") && url.size() <= 16384 &&
                url.find_first_of("\r\n\t\\#") == std::string::npos,
            "Invalid App Store asset URL");
    const auto end = url.find_first_of("/?", 8);
    const auto host = url.substr(8, end == std::string::npos ? end : end - 8);
    require(host.find_first_of("@: %") == std::string::npos &&
                (host.ends_with(".apple.com") || host.ends_with(".cdn-apple.com") ||
                 host.ends_with(".mzstatic.com")),
            "Invalid App Store asset host");
    return url;
}

std::string file_digest(const Path& path, mbedtls_md_type_t type) {
    crypto::Context<mbedtls_md_context_t, mbedtls_md_init, mbedtls_md_free> hash;
    const auto* info = mbedtls_md_info_from_type(type);
    require(info, "Digest unavailable");
    crypto::check(mbedtls_md_setup(hash.get(), info, 0), "Digest setup failed");
    crypto::check(mbedtls_md_starts(hash.get()), "Digest start failed");
    std::ifstream input(path, std::ios::binary);
    require(bool(input), "Cannot read downloaded IPA");
    std::array<unsigned char, 65536> buffer{};
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const auto count = input.gcount();
        if (count) {
            crypto::check(mbedtls_md_update(hash.get(), buffer.data(), std::size_t(count)),
                          "Digest update failed");
        }
    }
    require(input.eof(), "Cannot finish reading downloaded IPA");
    Bytes output(mbedtls_md_get_size(info));
    crypto::check(mbedtls_md_finish(hash.get(), output.data()), "Digest finish failed");
    return hex(output);
}

void validate_ipa(const Path& file, AppStoreIosDownload& result) {
    int error = 0;
    std::unique_ptr<zip_t, decltype(&zip_discard)> archive(
        zip_open(file.string().c_str(), ZIP_RDONLY | ZIP_CHECKCONS, &error), zip_discard);
    require(bool(archive), "Cannot open App Store IPA");
    const auto count = zip_get_num_entries(archive.get(), 0);
    require(count > 0 && count <= 1000000, "Invalid IPA record count");
    std::set<std::string> names;
    std::map<std::string, zip_uint64_t> entries;
    std::string main_info;
    auto member = [&](zip_uint64_t index, bool keep) {
        zip_stat_t stat{};
        require(zip_stat_index(archive.get(), index, 0, &stat) == 0 && stat.size <= (1ull << 31) &&
                    (stat.comp_method == 0 || stat.comp_method == 8),
                "Unsupported App Store ZIP member");
        require(!keep || stat.size <= (128ull << 20), "IPA metadata/executable is too large");
        std::unique_ptr<zip_file_t, decltype(&zip_fclose)> stream(
            zip_fopen_index(archive.get(), index, 0), zip_fclose);
        require(bool(stream), "Cannot open IPA ZIP member");
        Bytes data;
        if (keep) {
            data.reserve(std::size_t(stat.size));
        }
        std::array<std::uint8_t, 65536> buffer{};
        std::uint64_t consumed = 0;
        for (;;) {
            const auto n = zip_fread(stream.get(), buffer.data(), buffer.size());
            require(n >= 0, "IPA member failed CRC validation");
            if (!n) {
                break;
            }
            require(std::uint64_t(n) <= stat.size - consumed,
                    "IPA member exceeds its declared size");
            consumed += std::uint64_t(n);
            if (keep) {
                data.insert(data.end(), buffer.begin(), buffer.begin() + std::size_t(n));
            }
        }
        require(consumed == stat.size, "Truncated IPA member");
        return data;
    };
    for (zip_int64_t i = 0; i < count; ++i) {
        const auto* raw = zip_get_name(archive.get(), zip_uint64_t(i), ZIP_FL_ENC_GUESS);
        require(raw, "Invalid IPA path");
        const std::string name(raw);
        require(!name.empty() && name.front() != '/' &&
                    name.find_first_of("\\:") == std::string::npos,
                "Unsafe IPA path");
        for (const auto& part : Path(name)) {
            require(part != "..", "Unsafe IPA parent path");
        }
        require(names.insert(name).second, "Duplicate IPA member");
        entries.emplace(name, zip_uint64_t(i));
        if (name.starts_with("Payload/") && name.ends_with(".app/Info.plist") &&
            std::count(name.begin(), name.end(), '/') == 2) {
            require(main_info.empty(), "Multiple main applications in IPA");
            main_info = name;
        }
        (void)member(zip_uint64_t(i), false);
    }
    require(!main_info.empty(), "IPA lacks main Info.plist");
    const auto info = parse_plist(member(entries.at(main_info), true));
    require(info.at("CFBundleIdentifier") == result.offer.bundle &&
                info.at("CFBundleShortVersionString") == result.offer.version &&
                info.contains("CFBundleSupportedPlatforms") &&
                std::find(info.at("CFBundleSupportedPlatforms").begin(),
                          info.at("CFBundleSupportedPlatforms").end(),
                          "iPhoneOS") != info.at("CFBundleSupportedPlatforms").end(),
            "IPA does not match selected iOS app/version");
    const auto executable = info.at("CFBundleExecutable").get<std::string>();
    require(!executable.empty() && executable.find_first_of("/\\:") == std::string::npos &&
                executable != "..",
            "Invalid main executable path");
    const auto main_path = main_info.substr(0, main_info.rfind('/') + 1) + executable;
    require(entries.contains(main_path), "IPA lacks main executable");
    result.main_cryptids = archivedetail::encryption_ids(member(entries.at(main_path), true));
    result.members = std::uint64_t(count);
}
} // namespace

struct AppStoreIosClient::Impl {
    Json context;
    Transport transport;
    std::uint64_t dsid = 0;
    Bytes hardware;
    Headers headers;

    Impl(ByteView encoded, Transport custom, Headers overrides)
        : context(Json::parse(encoded.begin(), encoded.end())),
          transport(ios_transport(std::move(custom), std::move(overrides))) {
        const auto id = scalar(context.at("dsid"));
        require(decimal(id), "Invalid App Store DSID");
        dsid = std::stoull(id);
        require(dsid != 0, "App Store DSID must be nonzero");
        hardware = unhex(context.at("guid").get<std::string>());
        require(hardware.size() == 6, "App Store requires original hardware6 GUID");
        const auto country = context.at("country").get<std::string>();
        require(country.size() == 2 && std::all_of(country.begin(),
                                                   country.end(),
                                                   [](char c) {
                                                       return c >= 'a' && c <= 'z';
                                                   }),
                "Invalid App Store country");
        const auto storefront = context.at("storefront").get<std::string>();
        require(!storefront.empty() && storefront.size() <= 40 &&
                    storefront.find_first_not_of("0123456789-,") == std::string::npos,
                "Invalid App Store storefront");
        const auto& cookies = context.at("storeCookies");
        require(cookies.is_object() && !cookies.empty() && cookies.size() <= 256,
                "Saved iOS Store cookies are required");
        std::string cookie;
        for (auto it = cookies.begin(); it != cookies.end(); ++it) {
            const auto value = it.value().get<std::string>();
            safe_header(it.key());
            require(it.key().find_first_of("=; ,") == std::string::npos,
                    "Invalid Store cookie name");
            if (!value.empty()) {
                safe_header(value);
            }
            require(value.find(';') == std::string::npos, "Invalid Store cookie value");
            if (!cookie.empty()) {
                cookie += "; ";
            }
            cookie += it.key() + "=" + value;
        }
        safe_header(cookie);
        headers = {{"User-Agent", configurator_agent},
                   {"Accept", "*/*"},
                   {"Accept-Language", "en-US"},
                   {"X-Dsid", id},
                   {"iCloud-DSID", id},
                   {"X-Apple-Store-Front", storefront},
                   {"Cookie", cookie}};
    }

    Json catalog(std::uint64_t id) {
        require(id != 0, "App Store app ID must be nonzero");
        const Headers public_headers{{"User-Agent", configurator_agent},
                                     {"Accept", "application/json"}};
        for (const auto* platform : {"enterprisestore", "iphone", "ipad"}) {
            const auto url = "https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/"
                             "wa/lookup?version=2&id=" +
                             std::to_string(id) + "&p=mdm-lockup&caller=MDM&platform=" + platform +
                             "&cc=" + context.at("country").get<std::string>() + "&l=en";
            const auto response = transport({url, "GET", public_headers, {}});
            require(response.status == 200, "Public iOS catalog request failed");
            const auto result = Json::parse(response.body.begin(), response.body.end());
            if (!result.contains("results") || !result.at("results").contains(std::to_string(id))) {
                continue;
            }
            const auto& entry = result.at("results").at(std::to_string(id));
            if (!entry.contains("offers") || entry.at("offers").empty()) {
                continue;
            }
            require(entry.contains("bundleId") && !entry.at("bundleId").get<std::string>().empty(),
                    "Invalid iOS catalog bundle");
            return result;
        }
        throw netdetail::Error("No iOS App Store offer in the account country");
    }

    AppStoreIosOffer offer(std::uint64_t id, const Json& catalog) {
        const auto& entry = catalog.at("results").at(std::to_string(id));
        const auto& version = entry.at("offers").at(0).at("version");
        const auto external = scalar(version.at("externalId"));
        require(decimal(external) && external != "0", "Invalid iOS offer identifier");
        return {id,
                entry.at("bundleId").get<std::string>(),
                version.at("display").get<std::string>(),
                external};
    }

    std::pair<AppStoreIosOffer, Json> metadata(std::uint64_t id) {
        const auto selected = offer(id, catalog(id));
        auto request_headers = headers;
        request_headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
        Bytes serial(appstoredetail::serial_prefix.begin(), appstoredetail::serial_prefix.end());
        serial.insert(serial.end(), hardware.begin() + 2, hardware.end());
        const Json body{{"creditDisplay", ""},
                        {"guid", context.at("guid")},
                        {"salableAdamId", std::to_string(id)},
                        {"externalVersionId", selected.external_version_id},
                        {"serialNumber", base64(serial)},
                        {"kbsync", base64(generate_kbsync(dsid, hardware))}};
        const auto response = transport({"https://downloaddispatch.itunes.apple.com/WebObjects/"
                                         "DownloadDispatch.woa/wa/ent/download?guid=" +
                                             context.at("guid").get<std::string>(),
                                         "POST",
                                         request_headers,
                                         encode_plist(body)});
        require(response.status == 200, "Saved iOS App Store session rejected");
        const auto result = parse_plist(response.body);
        if (result.contains("failureType") && !scalar(result.at("failureType")).empty()) {
            const auto failure = scalar(result.at("failureType"));
            throw netdetail::Error(failure == "9610" ? "An App Store license is required"
                                                     : "App Store download authorization rejected");
        }
        require(result.value("status", -1) == 0 && result.contains("songList") &&
                    result.at("songList").size() == 1,
                "App Store did not return exactly one download item");
        require(result.contains("dsPersonId") &&
                    scalar(result.at("dsPersonId")) == scalar(context.at("dsid")),
                "App Store returned another account");
        const auto& item = result.at("songList").at(0);
        const auto& meta = item.at("metadata");
        require(scalar(meta.at("itemId")) == std::to_string(id) &&
                    meta.at("softwareVersionBundleId") == selected.bundle &&
                    scalar(meta.at("softwareVersionExternalIdentifier")) ==
                        selected.external_version_id &&
                    meta.at("bundleShortVersionString") == selected.version &&
                    meta.at("software-platform") == "ios",
                "App Store returned a different app, version or platform");
        checked_asset_url(item.at("URL").get<std::string>());
        return {selected, result};
    }
};

AppStoreIosClient::AppStoreIosClient(ByteView context, Transport transport)
    : AppStoreIosClient(context, std::move(transport), {}) {}

AppStoreIosClient::AppStoreIosClient(ByteView context, Transport transport, Headers headers)
    : impl_(std::make_unique<Impl>(context, std::move(transport), std::move(headers))) {}

AppStoreIosClient::AppStoreIosClient(const StoreSession& session,
                                     const std::string& country,
                                     Transport transport)
    : AppStoreIosClient(session.ios_context(country), std::move(transport)) {}

AppStoreIosClient::AppStoreIosClient(const StoreSession& session,
                                     const std::string& country,
                                     Transport transport,
                                     Headers headers)
    : AppStoreIosClient(session.ios_context(country), std::move(transport), std::move(headers)) {}

AppStoreIosClient::~AppStoreIosClient() = default;
AppStoreIosClient::AppStoreIosClient(AppStoreIosClient&&) noexcept = default;
AppStoreIosClient& AppStoreIosClient::operator=(AppStoreIosClient&&) noexcept = default;

Bytes AppStoreIosClient::catalog(std::uint64_t app_id) {
    require(bool(impl_), "App Store client was moved");
    return bytes(impl_->catalog(app_id).dump(2));
}

AppStoreIosOffer AppStoreIosClient::offer(std::uint64_t app_id) {
    require(bool(impl_), "App Store client was moved");
    return impl_->offer(app_id, impl_->catalog(app_id));
}

Bytes AppStoreIosClient::metadata(std::uint64_t app_id) {
    require(bool(impl_), "App Store client was moved");
    return encode_plist(impl_->metadata(app_id).second);
}

Bytes AppStoreIosClient::acquire_free(std::uint64_t app_id) {
    require(bool(impl_) && app_id != 0, "Invalid free-app acquisition");
    const auto& context = impl_->context;
    const auto token = context.at("passwordToken").get<std::string>();
    safe_header(token);
    const auto url = context.at("purchaseUrl").get<std::string>();
    const auto end = url.find('/', 8);
    const auto host = url.substr(8, end == std::string::npos ? end : end - 8);
    require(url.starts_with("https://") && end != std::string::npos &&
                host.ends_with("-buy.itunes.apple.com") &&
                host.find_first_of("@: %?#\\\r\n") == std::string::npos &&
                url.substr(end) == "/WebObjects/MZFinance.woa/wa/buyProduct",
            "Invalid App Store purchase endpoint");
    const Headers public_headers{{"User-Agent", configurator_agent},
                                 {"Accept", "application/json"}};
    const auto price =
        impl_->transport({"https://itunes.apple.com/lookup?id=" + std::to_string(app_id) +
                              "&country=" + context.at("country").get<std::string>(),
                          "GET",
                          public_headers,
                          {}});
    require(price.status == 200, "Cannot verify the current app price");
    const auto found = Json::parse(price.body.begin(), price.body.end()).at("results");
    require(found.is_array() && found.size() == 1 && found[0].at("trackId") == app_id &&
                found[0].at("price").is_number() && found[0].at("price").get<double>() == 0.0,
            "App is not currently free");
    auto serial = unhex("54c8b0a988");
    serial.insert(serial.end(), impl_->hardware.begin() + 2, impl_->hardware.end());
    const Json payload{{"appExtVrsId", "0"},
                       {"hasAskedToFulfillPreorder", "true"},
                       {"buyWithoutAuthorization", "true"},
                       {"hasDoneAgeCheck", "true"},
                       {"guid", context.at("guid")},
                       {"needDiv", "0"},
                       {"origPage", "Software-" + std::to_string(app_id)},
                       {"origPageLocation", "Buy"},
                       {"price", "0"},
                       {"pricingParameters", "STDQ"},
                       {"productType", "C"},
                       {"salableAdamId", app_id},
                       {"kbsync", base64(generate_kbsync(impl_->dsid, impl_->hardware))},
                       {"serialNumber", base64(serial)}};
    auto headers = impl_->headers;
    headers["X-Token"] = token;
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    headers["X-Apple-Client-Application"] = "me.majd.ipatool";
    headers["X-Apple-Tz"] = "0";
    headers["Accept-Language"] = "en";
    const auto response =
        impl_->transport({url, "POST", std::move(headers), encode_plist(payload)});
    require(response.status == 200, "Free-app acquisition rejected");
    const auto result = parse_plist(response.body);
    require(result.value("jingleDocType", "") == "purchaseSuccess" &&
                scalar(result.at("status")) == "0" &&
                scalar(result.at("dsPersonId")) == scalar(context.at("dsid")),
            "Free-app acquisition was not confirmed");
    return response.body;
}

AppStoreIosDownload AppStoreIosClient::download(std::uint64_t app_id, const Path& destination) {
    require(bool(impl_) && !destination.empty() && !std::filesystem::exists(destination),
            "App Store output already exists or is invalid");
    const auto [selected, metadata] = impl_->metadata(app_id);
    AppStoreIosDownload result;
    result.offer = selected;
    result.path = destination;
    result.material_directory = destination.string() + ".appstore-" + hex(random_bytes(8));
    std::filesystem::create_directories(result.material_directory);
    std::filesystem::permissions(result.material_directory, std::filesystem::perms::owner_all);
    write_private(result.material_directory / "download-metadata.plist", encode_plist(metadata));
    const auto& item = metadata.at("songList").at(0);
    const auto source = result.material_directory / "original-CDN-encrypted.ipa";
    result.bytes = download_file(item.at("URL").get<std::string>(), source);
    require(item.contains("asset-info") &&
                result.bytes == item.at("asset-info").at("file-size").get<std::uint64_t>(),
            "IPA size differs from Store metadata");
    require(file_digest(source, MBEDTLS_MD_MD5) == item.at("md5").get<std::string>(),
            "IPA digest differs from Store metadata");
    validate_ipa(source, result);
    result.sha256 = file_digest(source, MBEDTLS_MD_SHA256);
    for (const auto& value :
         item.at("metadata").value("softwareVersionExternalIdentifiers", Json::array())) {
        const auto id = scalar(value);
        require(decimal(id), "Invalid App Store version history identifier");
        result.version_ids.push_back(id);
    }
    std::filesystem::create_hard_link(source, destination);
    return result;
}

namespace {
Path existing_mac_store(const Path& directory) {
    require(std::filesystem::is_regular_file(directory / "identity.json") &&
                std::filesystem::is_regular_file(directory / "adi.pb"),
            "Mac downloads require existing Store identity and ADI; automatic provisioning is "
            "disabled");
    return directory;
}
} // namespace

struct AppStoreMacClient::Impl {
    StoreSession session;
    StoreClient store;
    Transport transport;
    Json state;
    std::string country, guid;
    Bytes hardware;
    std::uint64_t dsid;

    AppStoreMacDownload download(std::uint64_t id, const Path& destination, bool package);

    Impl(const StoreSession& saved,
         Path directory,
         std::string selected_country,
         ClientOptions options)
        : session(StoreSession::from_plist(saved.plist())),
          store(existing_mac_store(directory), StoreProtocol::macos_accounts, options),
          transport(configured_transport(options)), state(parse_plist(saved.plist())),
          country(std::move(selected_country)), guid(state.at("guid").get<std::string>()),
          hardware(unhex(guid)), dsid(0) {
        require(session.protocol() == StoreProtocol::macos_accounts,
                "Mac download requires a Mac Accounts session");
        require(country.size() == 2 && std::all_of(country.begin(),
                                                   country.end(),
                                                   [](char c) {
                                                       return c >= 'a' && c <= 'z';
                                                   }),
                "Invalid Mac App Store country");
        require(hardware.size() == 6, "Mac download requires the original hardware6 GUID");
        const auto id = session.account_id();
        require(decimal(id), "Invalid Mac Store DSID");
        dsid = std::stoull(id);
        require(dsid != 0, "Mac Store DSID must be nonzero");
        const auto identity = Json::parse(netdetail::read_file(directory / "identity.json"));
        require(unhex(identity.at("guid").get<std::string>()) == hardware,
                "Mac Store session belongs to another Store identity");
    }

    Json catalog(std::uint64_t id) {
        require(id != 0, "Mac app ID must be nonzero");
        const Headers public_headers{{"User-Agent", mac_agent}, {"Accept", "application/json"}};
        const auto response = transport({"https://apps.apple.com/api/apps/v1/catalog/" + country +
                                             "/apps/" + std::to_string(id) + "?platform=mac",
                                         "GET",
                                         public_headers,
                                         {}});
        require(response.status == 200, "Public Mac catalog request failed");
        const auto result = Json::parse(response.body.begin(), response.body.end());
        require(result.contains("data") && result.at("data").is_array() &&
                    result.at("data").size() == 1,
                "Mac catalog did not return exactly one application");
        const auto& app = result.at("data").at(0);
        require(scalar(app.at("id")) == std::to_string(id),
                "Mac catalog returned a different application");
        const auto& platform = app.at("attributes").at("platformAttributes").at("osx");
        require(platform.contains("bundleId") &&
                    !platform.at("bundleId").get<std::string>().empty() &&
                    platform.contains("offers") && platform.at("offers").is_array() &&
                    !platform.at("offers").empty(),
                "No Mac App Store offer in the account country");
        return result;
    }

    AppStoreMacOffer offer(std::uint64_t id, const Json& catalog) {
        const auto& platform =
            catalog.at("data").at(0).at("attributes").at("platformAttributes").at("osx");
        const auto external = scalar(platform.at("externalVersionId"));
        require(decimal(external) && external != "0", "Invalid Mac catalog offer identifier");
        return {id, platform.at("bundleId").get<std::string>(), external};
    }

    std::pair<AppStoreMacOffer, Json> metadata(std::uint64_t id) {
        const auto selected = offer(id, catalog(id));
        const std::string url =
            "https://downloaddispatch.itunes.apple.com/ent/download?guid=" + guid;
        auto headers = session.headers(url);
        const auto anisette = store.headers();
        headers["User-Agent"] = mac_agent;
        headers["Accept"] = "*/*";
        headers["Accept-Language"] = "en-US";
        headers["Content-Type"] = "application/x-apple-plist";
        headers["X-Apple-Client-Application"] = "com.apple.TestFlight";
        headers["X-Apple-Tz"] = "0";
        headers["X-Guid"] = guid;
        headers["iCloud-DSID"] = session.account_id();
        headers["X-Apple-AMD"] = anisette.at("X-Apple-AMD");
        headers["X-Apple-AMD-M"] = anisette.at("X-Apple-AMD-M");
        if (state.at("account").contains("altDsid")) {
            const auto value = scalar(state.at("account").at("altDsid"));
            safe_header(value);
            headers["X-Apple-ADSID"] = value;
        }
        require(headers.contains("Cookie"),
                "Saved Mac session has no cookies for the download endpoint");
        // The saved positive differential confirms AMD + cookies suffice; no new
        // SAP setup/signature or GSA/PET exchange is performed for downloads.
        const Json payload{{"creditDisplay", ""},
                           {"guid", guid},
                           {"salableAdamId", std::to_string(id)},
                           {"externalVersionId", selected.external_version_id},
                           {"serialNumber", "0"},
                           {"kbsync", base64(generate_kbsync(dsid, hardware))}};
        const auto response = transport({url, "POST", std::move(headers), encode_plist(payload)});
        require(response.status == 200, "Saved Mac Store download session rejected");
        const auto result = parse_plist(response.body);
        if (result.contains("failureType") && !scalar(result.at("failureType")).empty()) {
            throw netdetail::Error(scalar(result.at("failureType")) == "9610"
                                       ? "A Mac App Store license is required"
                                       : "Mac Store download authorization rejected");
        }
        require(result.value("status", -1) == 0 && result.contains("songList") &&
                    result.at("songList").is_array() && result.at("songList").size() == 1 &&
                    scalar(result.at("dsPersonId")) == session.account_id(),
                "Mac Store did not return one download for the same account");
        const auto& item = result.at("songList").at(0);
        const auto& meta = item.at("metadata");
        require(scalar(meta.at("itemId")) == std::to_string(id) &&
                    meta.at("softwareVersionBundleId") == selected.bundle &&
                    meta.at("software-platform") == "macos" &&
                    scalar(meta.at("softwareVersionExternalIdentifier")) ==
                        selected.external_version_id,
                "Mac Store returned a different app, offer or platform");
        require(item.at("asset-info").at("file-size").is_number_unsigned() ||
                    item.at("asset-info").at("file-size").is_number_integer(),
                "Missing Mac asset size");
        const auto size = item.at("asset-info").at("file-size").get<std::int64_t>();
        require(size > 0 && size <= (1ll << 34), "Mac asset size exceeds the supported range");
        const auto md5 = item.at("md5").get<std::string>();
        require(md5.size() == 32 &&
                    md5.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos,
                "Invalid Mac asset digest");
        checked_asset_url(item.at("URL").get<std::string>());
        return {selected, result};
    }
};

AppStoreMacClient::AppStoreMacClient(const StoreSession& session,
                                     Path directory,
                                     std::string country,
                                     ClientOptions options)
    : impl_(std::make_unique<Impl>(
          session, std::move(directory), std::move(country), std::move(options))) {}

AppStoreMacClient::~AppStoreMacClient() = default;
AppStoreMacClient::AppStoreMacClient(AppStoreMacClient&&) noexcept = default;
AppStoreMacClient& AppStoreMacClient::operator=(AppStoreMacClient&&) noexcept = default;

Bytes AppStoreMacClient::catalog(std::uint64_t id) {
    require(bool(impl_), "Mac App Store client was moved");
    return bytes(impl_->catalog(id).dump(2));
}

AppStoreMacOffer AppStoreMacClient::offer(std::uint64_t id) {
    require(bool(impl_), "Mac App Store client was moved");
    return impl_->offer(id, impl_->catalog(id));
}

Bytes AppStoreMacClient::metadata(std::uint64_t id) {
    require(bool(impl_), "Mac App Store client was moved");
    return encode_plist(impl_->metadata(id).second);
}

AppStoreMacDownload AppStoreMacClient::download(std::uint64_t id, const Path& destination) {
    require(bool(impl_), "Mac App Store client was moved");
    return impl_->download(id, destination, false);
}

AppStoreMacDownload AppStoreMacClient::download_package(std::uint64_t id, const Path& destination) {
    require(bool(impl_), "Mac App Store client was moved");
    return impl_->download(id, destination, true);
}

AppStoreMacDownload
AppStoreMacClient::Impl::download(std::uint64_t id, const Path& destination, bool package) {
    require(!destination.empty() && !std::filesystem::exists(destination),
            "Mac asset output already exists or is invalid");
    const auto [selected, response] = metadata(id);
    const auto& item = response.at("songList").at(0);
    AppStoreMacDownload result;
    result.offer = selected;
    result.path = destination;
    result.version = item.at("metadata").value("bundleShortVersionString", std::string());
    result.material_directory = destination.string() + ".appstore-" + hex(random_bytes(8));
    std::filesystem::create_directories(result.material_directory);
    std::filesystem::permissions(result.material_directory, std::filesystem::perms::owner_all);
    write_private(result.material_directory / "download-metadata.plist", encode_plist(response));
    const auto source = result.material_directory / "original-CDN-Mac.asset";
    result.original_path = source;
    result.bytes = download_file(item.at("URL").get<std::string>(), source);
    require(result.bytes == item.at("asset-info").at("file-size").get<std::uint64_t>(),
            "Mac asset size differs from Store metadata");
    auto expected_md5 = item.at("md5").get<std::string>();
    std::transform(
        expected_md5.begin(), expected_md5.end(), expected_md5.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    require(file_digest(source, MBEDTLS_MD_MD5) == expected_md5,
            "Mac asset digest differs from Store metadata");
    result.sha256 = file_digest(source, MBEDTLS_MD_SHA256);
    Bytes dp_info;
    for (const auto& row : item.value("sinfs", Json::array())) {
        if (row.contains("dpInfo") && row.at("dpInfo").is_binary() &&
            !row.at("dpInfo").get_binary().empty()) {
            result.transport_wrapped = true;
            if (package) {
                require(dp_info.empty(), "Multiple Mac transport records are unsupported");
                const auto& binary = row.at("dpInfo").get_binary();
                dp_info.assign(binary.begin(), binary.end());
            }
        }
    }
    for (const auto& value :
         item.at("metadata").value("softwareVersionExternalIdentifiers", Json::array())) {
        const auto version = scalar(value);
        require(decimal(version), "Invalid Mac version history identifier");
        result.version_ids.push_back(version);
    }
    if (package) {
        const auto checked =
            dp_info.empty() ? appstoredetail::inspect_mac_package(source)
                            : unwrap_appstore_mac_package(source, destination, hardware, dp_info);
        if (dp_info.empty()) {
            std::filesystem::create_hard_link(source, destination);
        }
        result.bytes = checked.bytes;
        result.members = checked.members;
        result.sha256 = checked.sha256;
        result.transport_wrapped = false;
        result.package_validated = true;
    } else {
        std::filesystem::create_hard_link(source, destination);
    }
    return result;
}
} // namespace apple_auth
