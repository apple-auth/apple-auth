#include "client/client_internal.hpp"
#include <curl/curl.h>
#include <fstream>
#include <memory>

namespace apple_auth::netdetail {
namespace {
void initialize_download_http() {
    static const int initialized = [] {
        require(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK,
                "Cannot initialize download HTTP");
        return 1;
    }();
    (void)initialized;
}
} // namespace

std::uint64_t download_file(const std::string& url, const Path& destination) {
    require(url.starts_with("https://"), "Only HTTPS downloads are supported");
    require(!std::filesystem::exists(destination), "Download output already exists");
    initialize_download_http();
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
    require(bool(handle), "Cannot create download request");
    if (!destination.parent_path().empty()) {
        std::filesystem::create_directories(destination.parent_path());
    }
    const Path temporary = destination.string() + "." + hex(random_bytes(8)) + ".partial";
    std::uint64_t bytes_written = 0;
    try {
        std::ofstream output(temporary, std::ios::binary);
        require(bool(output), "Cannot create download output");
        std::filesystem::permissions(
            temporary, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

        struct Writer {
            std::ofstream* stream;
            std::uint64_t* count;
        } writer{&output, &bytes_written};

        curl_easy_setopt(handle.get(), CURLOPT_URL, url.c_str());
        curl_easy_setopt(handle.get(), CURLOPT_CONNECTTIMEOUT, 15L);
        curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT, 600L);
        curl_easy_setopt(handle.get(), CURLOPT_PROTOCOLS_STR, "https");
        curl_easy_setopt(handle.get(), CURLOPT_REDIR_PROTOCOLS_STR, "https");
        curl_easy_setopt(handle.get(), CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(handle.get(), CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(handle.get(), CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(handle.get(), CURLOPT_SSL_VERIFYHOST, 2L);
#ifdef _WIN32
        curl_easy_setopt(
            handle.get(), CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif
        // The signed CDN URL is fetched without TF session headers or cookies.
        curl_easy_setopt(
            handle.get(),
            CURLOPT_WRITEFUNCTION,
            +[](char* data, std::size_t n, std::size_t m, void* context) -> std::size_t {
                if (n && m > SIZE_MAX / n) {
                    return 0;
                }
                const auto count = n * m;
                auto& writer = *static_cast<Writer*>(context);
                if (count > (1ull << 34) - *writer.count) {
                    return 0;
                }
                writer.stream->write(data, static_cast<std::streamsize>(count));
                if (!*writer.stream) {
                    return 0;
                }
                *writer.count += count;
                return count;
            });
        curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &writer);
        const auto result = curl_easy_perform(handle.get());
        require(result == CURLE_OK,
                "IPA download failed: " + std::string(curl_easy_strerror(result)));
        long status = 0;
        curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &status);
        require(status == 200, "IPA download rejected (HTTP " + std::to_string(status) + ")");
        curl_off_t length = -1;
        curl_easy_getinfo(handle.get(), CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &length);
        require(bytes_written &&
                    (length < 0 || static_cast<std::uint64_t>(length) == bytes_written),
                "IPA download size differs from the response");
        output.close();
        require(bool(output), "Cannot finalize IPA download");
        std::filesystem::create_hard_link(temporary, destination);
        std::filesystem::remove(temporary);
    } catch (...) {
        std::error_code error;
        std::filesystem::remove(temporary, error);
        throw;
    }
    return bytes_written;
}
} // namespace apple_auth::netdetail
