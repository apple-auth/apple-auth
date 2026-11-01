#include "client/client_internal.hpp"

#include <array>
#include <curl/curl.h>
#include <fstream>
#include <memory>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <wincrypt.h>
#include <windows.h>
#endif
namespace apple_auth::netdetail {
std::int64_t http_date(const std::string& value) {
    return static_cast<std::int64_t>(curl_getdate(value.c_str(), nullptr));
}

namespace {
struct CertificateFile {
    Path path;
    CertificateFile() = default;
    CertificateFile(const CertificateFile&) = delete;
    CertificateFile& operator=(const CertificateFile&) = delete;

    ~CertificateFile() {
        std::error_code ignored;
        if (!path.empty()) {
            std::filesystem::remove(path, ignored);
        }
    }
};

constexpr char apple_root_hex[] =
    "308204bb308203a3a003020102020102300d06092a864886f70d01010505003062310b300906035504061302555331"
    "133011060355040a130a4170706c6520496e632e31263024060355040b131d4170706c652043657274696669636174"
    "696f6e20417574686f72697479311630140603550403130d4170706c6520526f6f74204341301e170d303630343235"
    "3231343033365a170d3335303230393231343033365a3062310b300906035504061302555331133011060355040a13"
    "0a4170706c6520496e632e31263024060355040b131d4170706c652043657274696669636174696f6e20417574686f"
    "72697479311630140603550403130d4170706c6520526f6f7420434130820122300d06092a864886f70d0101010500"
    "0382010f003082010a0282010100e491a9091f91db1e4750eb05ed5e79842deb36a2574c55ec8b1989def94b6cf507"
    "ab223002e8183ef85009d37f41a898f9d1ca669c246b11d0a3bbe41b2ac31f959e7a0ca4478b5bd4163733cbc40f4d"
    "ce1469d1c91972f55d0ed57f5f9bf22503ba558f4d5d0df1643523154b15591db394f7f69c9ecf50bac15850678f08"
    "b420f7cbac2c206f70b63f01308cb743cf0f9d3df32b49281ac8feceb5b90ed95e1cd6cb3db53aadf40f0e00920bb1"
    "21162e74d53c0ddb6216aba37192475355c1af2f41b3f8fbe370cde6a34c457e1f4c6b50964189c474620b10834187"
    "338a81b13058ec5a04328c68b38f1dde6573ff675e65bc49d8769f331465a17794c92d0203010001a382017a308201"
    "76300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e041604142bd0"
    "6947947609fef46b8d2e40a6f7474d7f085e301f0603551d230418301680142bd06947947609fef46b8d2e40a6f747"
    "4d7f085e308201110603551d2004820108308201043082010006092a864886f7636405013081f2302a06082b060105"
    "05070201161e68747470733a2f2f7777772e6170706c652e636f6d2f6170706c6563612f3081c306082b0601050507"
    "02023081b61a81b352656c69616e6365206f6e207468697320636572746966696361746520627920616e7920706172"
    "747920617373756d657320616363657074616e6365206f6620746865207468656e206170706c696361626c65207374"
    "616e64617264207465726d7320616e6420636f6e646974696f6e73206f66207573652c206365727469666963617465"
    "20706f6c69637920616e642063657274696669636174696f6e2070726163746963652073746174656d656e74732e30"
    "0d06092a864886f70d010105050003820101005c36994c2d78b7ed8c9bdcf3779bf276d277304fc11f8583851b993d"
    "4737f2a99b408e2cd4b19012d8bef4739beed2640fcb794f34d8a23ef978ff6bc807ec7d39838b5320d338c4b1bf9a"
    "4f0a6bff2bfc59a705097c174056111e74d3b78b233b47a3d56f24e2ebd1b770df0f45e127caf16d78ede7b51717a8"
    "dc7e2235ca25d5d90fd66bd4a2242311f7a1ac8f738160c61b5b092f92b2f84448f060389e15f53d2667208a336af7"
    "0d82cfdeeba32ff9536a5b64c0633377f73a072c56ebda0f210edaba73194fb5d9367fc18755d9a799b93242fbd8d5"
    "719e7ea152b71bbd934224122ac70f1db64d9c5e63c84b801750aa8ad5dae4fcd0090737b0757521";

// https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
// Android MidService provisioning uses this Apple Root CA G3 chain.
constexpr char apple_root_g3_hex[] =
    "30820243308201c9a00302010202082dc5fc88d2c54b95300a06082a8648ce3d0403033067311b3019060355"
    "04030c124170706c6520526f6f74204341202d20473331263024060355040b0c1d4170706c65204365727469"
    "6669636174696f6e20417574686f7269747931133011060355040a0c0a4170706c6520496e632e310b300906"
    "0355040613025553301e170d3134303433303138313930365a170d3339303433303138313930365a3067311b"
    "301906035504030c124170706c6520526f6f74204341202d20473331263024060355040b0c1d4170706c6520"
    "43657274696669636174696f6e20417574686f7269747931133011060355040a0c0a4170706c6520496e632e"
    "310b30090603550406130255533076301006072a8648ce3d020106052b810400220362000498e92f3d4072a4"
    "ed93227281131cdd1095f1c5a34e71dc1416d90ee5a6052a77647b5f4e38d3bb1c44b57ff51fb632625dc9e9"
    "845b4f304f115a00fd58580ca5f50f2c4d07471375da9797976f315ced2b9d7b203bd8b954d95e99a43a510a"
    "31a3423040301d0603551d0e04160414bbb0dea15833889aa48a99debebdebafdacb24ab300f0603551d1301"
    "01ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d04030303680030650231"
    "0083e9c1c4165e1a5d3418d9edeff46c0e00464bb8dfb24611c50ffde67a8ca1a66bcec203d49cf593c674b8"
    "6adfaa231502306d668a10cad40dd44fcd8d433eb48a63a5336ee36dda17b7641fc85326f9886274390b175b"
    "cb51a80ce81803e7a2b228";

void append_certificate(std::string& bundle, ByteView der) {
    const auto encoded = base64(der);
    bundle += "-----BEGIN CERTIFICATE-----\n";
    for (std::size_t offset = 0; offset < encoded.size(); offset += 64) {
        bundle += encoded.substr(offset, 64) + "\n";
    }
    bundle += "-----END CERTIFICATE-----\n";
}

std::string trust_bundle(CURL* handle) {
    std::string bundle;
    append_certificate(bundle, unhex(apple_root_hex));
    append_certificate(bundle, unhex(apple_root_g3_hex));
    // Preserve curl's configured system roots alongside Apple's private CA.
    char* path = nullptr;
    if (curl_easy_getinfo(handle, CURLINFO_CAINFO, &path) == CURLE_OK && path) {
        std::ifstream input(path, std::ios::binary);
        bundle.append(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }
#ifdef _WIN32
    // An explicit CA bundle replaces Schannel's default store. Include the OS
    // roots as well so Store endpoints using public CAs keep their normal trust.
    const auto store = CertOpenSystemStoreW(0, L"ROOT");
    require(store != nullptr, "Cannot open Windows root certificate store");

    struct StoreOwner {
        HCERTSTORE value;
        PCCERT_CONTEXT current = nullptr;

        ~StoreOwner() {
            if (current) {
                CertFreeCertificateContext(current);
            }
            CertCloseStore(value, 0);
        }
    } owner{store};

    while ((owner.current = CertEnumCertificatesInStore(store, owner.current)) != nullptr) {
        append_certificate(bundle,
                           ByteView(owner.current->pbCertEncoded, owner.current->cbCertEncoded));
    }
#endif
    return bundle;
}

} // namespace

HttpResponse curl_transport(const HttpRequest& request) {
    const auto& url = request.url;
    const auto& body = request.body;
    const auto& headers = request.headers;
    const auto& method = request.method;
    require(url.starts_with("https://"), "Only HTTPS is supported");
    static const int initialized = []() {
        require(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "Cannot initialize HTTP");
        return 1;
    }();
    (void)initialized;
    std::array<char, CURL_ERROR_SIZE> error_buffer{};
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
    require(bool(handle), "Cannot create HTTP request");
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> list(nullptr, curl_slist_free_all);
    for (const auto& [k, v] : headers) {
        require(k.find_first_of("\r\n:") == std::string::npos &&
                    v.find_first_of("\r\n") == std::string::npos,
                "Invalid HTTP header");
        auto* updated = curl_slist_append(list.get(), (k + ": " + v).c_str());
        require(updated != nullptr, "Cannot allocate HTTP headers");
        (void)list.release();
        list.reset(updated);
    }
    HttpResponse response;
    curl_easy_setopt(handle.get(), CURLOPT_ERRORBUFFER, error_buffer.data());
    curl_easy_setopt(handle.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle.get(), CURLOPT_HTTPHEADER, list.get());
    curl_easy_setopt(handle.get(), CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(handle.get(), CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT, 90L);
    curl_easy_setopt(handle.get(), CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(handle.get(), CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(handle.get(), CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(handle.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(handle.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    auto certificates = trust_bundle(handle.get());
    curl_blob bundle{certificates.data(), certificates.size(), CURL_BLOB_NOCOPY};
    std::optional<CertificateFile> certificate_file;
    const auto certificate_status = curl_easy_setopt(handle.get(), CURLOPT_CAINFO_BLOB, &bundle);
    if (certificate_status == CURLE_NOT_BUILT_IN || certificate_status == CURLE_UNKNOWN_OPTION) {
        // Older GnuTLS-backed curl releases support CAINFO but not CAINFO_BLOB.
        // Keep this private file alive through the request, including error paths.
        certificate_file.emplace();
        certificate_file->path = std::filesystem::temp_directory_path() /
                                 ("apple-auth-ca-" + hex(random_bytes(16)) + ".pem");
        write_private(certificate_file->path, bytes(certificates));
        const auto path = certificate_file->path.u8string();
        require(curl_easy_setopt(handle.get(),
                                 CURLOPT_CAINFO,
                                 reinterpret_cast<const char*>(path.c_str())) == CURLE_OK,
                "Cannot configure HTTPS trust roots");
    } else {
        require(certificate_status == CURLE_OK, "Cannot configure HTTPS trust roots");
    }
    // Schannel uses the Windows root store by default. Other backends may opt
    // into the host store in addition to the supplied Apple CA bundle.
    curl_easy_setopt(handle.get(), CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
    if (method != "GET") {
        curl_easy_setopt(handle.get(),
                         CURLOPT_POSTFIELDS,
                         body.empty() ? "" : reinterpret_cast<const char*>(body.data()));
        curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDSIZE_LARGE, curl_off_t(body.size()));
    }
    curl_easy_setopt(
        handle.get(),
        CURLOPT_WRITEFUNCTION,
        +[](char* p, std::size_t n, std::size_t m, void* context) -> std::size_t {
            auto& out = *static_cast<Bytes*>(context);
            if (n && m > SIZE_MAX / n) {
                return 0;
            }
            auto size = n * m;
            if (size > 16 * 1024 * 1024 - out.size()) {
                return 0;
            }
            try {
                out.insert(out.end(), p, p + size);
            } catch (...) {
                return 0;
            }
            return size;
        });
    curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &response.body);
    std::size_t header_bytes = 0;
    const auto header_context = std::pair{&response.headers, &header_bytes};
    curl_easy_setopt(
        handle.get(),
        CURLOPT_HEADERFUNCTION,
        +[](char* data, std::size_t size, std::size_t count, void* opaque) -> std::size_t {
            auto& state = *static_cast<const decltype(header_context)*>(opaque);
            if (size && count > SIZE_MAX / size) {
                return 0;
            }
            const auto length = size * count;
            if (length > 64 * 1024 - *state.second) {
                return 0;
            }
            *state.second += length;
            try {
                std::string line(data, length);
                if (line.starts_with("HTTP/")) {
                    state.first->clear();
                }
                const auto colon = line.find(':');
                if (colon != std::string::npos) {
                    auto value = line.substr(colon + 1);
                    const auto begin = value.find_first_not_of(" \t");
                    value = begin == std::string::npos ? "" : value.substr(begin);
                    const auto end = value.find_last_not_of(" \t\r\n");
                    value = end == std::string::npos ? "" : value.substr(0, end + 1);
                    state.first->emplace_back(line.substr(0, colon), std::move(value));
                }
                return length;
            } catch (...) {
                return 0;
            }
        });
    curl_easy_setopt(handle.get(), CURLOPT_HEADERDATA, &header_context);
    const auto status = curl_easy_perform(handle.get());
    if (status != CURLE_OK) {
        const std::string detail =
            error_buffer[0] ? error_buffer.data() : curl_easy_strerror(status);
        throw apple_auth::Error(ErrorCode::network,
                                "HTTPS request failed (curl " + std::to_string(status) +
                                    "): " + detail);
    }
    curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &response.status);
    return response;
}
} // namespace apple_auth::netdetail
