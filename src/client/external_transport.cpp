#include "client/client_internal.hpp"
#include <ctime>
#include <iomanip>
#include <locale>
#include <sstream>

namespace apple_auth::netdetail {
std::int64_t http_date(const std::string& value) {
    if (value.size() > 128) return -1;
    for (const char* format : {"%a, %d %b %Y %H:%M:%S GMT", "%A, %d-%b-%y %H:%M:%S GMT",
                               "%a %b %d %H:%M:%S %Y"}) {
        std::tm date{};
        std::istringstream input(value);
        input.imbue(std::locale::classic());
        if (!(input >> std::get_time(&date, format))) continue;
        input >> std::ws;
        if (!input.eof()) continue;
#ifdef _WIN32
        const auto seconds = _mkgmtime(&date);
#else
        const auto seconds = timegm(&date);
#endif
        if (seconds >= 0) return static_cast<std::int64_t>(seconds);
    }
    return -1;
}

HttpResponse curl_transport(const HttpRequest&) {
    throw apple_auth::Error(ErrorCode::unsupported,
                            "This build requires a custom HTTP transport; use the Swift AppleAuth package on Apple platforms");
}
} // namespace apple_auth::netdetail
