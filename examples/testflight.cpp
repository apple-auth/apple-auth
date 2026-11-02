#include <apple_auth/testflight.hpp>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

namespace {
using namespace apple_auth;
using Path = std::filesystem::path;
using Json = nlohmann::json;

void require(bool valid, const char* message) {
    if (!valid) {
        throw Error(ErrorCode::invalid_argument, message);
    }
}

Bytes read(const Path& path, std::size_t limit = 1u << 20) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    require(bool(file), "Cannot open input file");
    const auto size = file.tellg();
    require(size >= 0 && static_cast<std::uint64_t>(size) <= limit, "Invalid input size");
    Bytes data(static_cast<std::size_t>(size));
    file.seekg(0);
    require(bool(file.read(reinterpret_cast<char*>(data.data()),
                           static_cast<std::streamsize>(data.size()))),
            "Cannot read input");
    return data;
}

Bytes unhex(const std::string& text) {
    require(text.size() % 2 == 0, "Invalid hexadecimal input");
    Bytes result;
    const auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    };
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const auto a = digit(text[i]), b = digit(text[i + 1]);
        require(a >= 0 && b >= 0, "Invalid hexadecimal input");
        result.push_back(static_cast<std::uint8_t>(a * 16 + b));
    }
    return result;
}

Bytes unbase64(const std::string& text) {
    // dpInfo88 has a fixed 120-character base64 encoding, with two '=' bytes.
    require(text.size() == 120 && text.ends_with("=="), "Invalid dpInfo base64");
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Bytes result;
    unsigned state = 0, bits = 0;
    for (const char c : text) {
        if (c == '=') {
            break;
        }
        const auto value = alphabet.find(c);
        require(value != std::string::npos, "Invalid dpInfo base64");
        state = (state << 6) | static_cast<unsigned>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<std::uint8_t>(state >> bits));
        }
    }
    require(result.size() == 88, "Invalid dpInfo length");
    return result;
}

void save_packet(const Path& path, ByteView data) {
    require(!std::filesystem::exists(path), "kbSync output already exists");
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }
    auto temp = path;
    temp += ".";
    for (auto byte : FileEncoding::random().iv) {
        constexpr char digits[] = "0123456789abcdef";
        temp += digits[byte >> 4];
        temp += digits[byte & 15];
    }
    temp += ".partial";
    try {
        {
            std::ofstream file(temp, std::ios::binary);
            require(bool(file), "Cannot create kbSync file");
            std::filesystem::permissions(
                temp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
            file.write(reinterpret_cast<const char*>(data.data()),
                       static_cast<std::streamsize>(data.size()));
            file.close();
            require(bool(file), "Cannot write kbSync");
        }
        std::filesystem::create_hard_link(temp, path);
        std::filesystem::remove(temp);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temp, ignored);
        throw;
    }
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 1 || (argc == 2 && std::string(argv[1]) == "--help")) {
            std::cout << "apple-auth TestFlight: SDK MbedTLS + curl, no OpenSSL dependency\n"
                         "--tf-session-from-cookies CONTEXT --output SESSION\n"
                         "--tf-catalog --tf-session SESSION --output CATALOG\n"
                         "--tf-install BUNDLE --tf-session SESSION --output METADATA\n"
                         "--tf-download BUNDLE --tf-session SESSION --output IPA [--no-sinf]\n"
                         "--unwrap-transport INPUT --material IDENTITY --install-metadata METADATA "
                         "--output APPLEZIP\n"
                         "--normalize-ipa APPLEZIP --output IPA\n"
                         "--kbsync --material IDENTITY --output PACKET\n";
            return 0;
        }
        std::map<std::string, std::string> options;
        std::string mode, argument;
        bool include_sinf = true;
        for (int i = 1; i < argc; ++i) {
            const std::string key = argv[i];
            const bool operation = key == "--tf-session-from-cookies" || key == "--tf-catalog" ||
                                   key == "--tf-install" || key == "--tf-download" ||
                                   key == "--unwrap-transport" || key == "--normalize-ipa" ||
                                   key == "--kbsync";
            if (key == "--no-sinf") {
                require(include_sinf, "Duplicate --no-sinf option");
                include_sinf = false;
            } else if (operation) {
                require(mode.empty(), "Choose one operation");
                mode = key;
                if (key != "--tf-catalog" && key != "--kbsync") {
                    require(i + 1 < argc, "Missing operation argument");
                    argument = argv[++i];
                }
            } else {
                require(key == "--output" || key == "--tf-session" || key == "--material" ||
                            key == "--install-metadata",
                        "Unknown option");
                require(i + 1 < argc && !options.contains(key), "Missing or duplicate option");
                options[key] = argv[++i];
            }
        }
        require(!mode.empty() && options.contains("--output"),
                "Operation and --output are required");
        require(include_sinf || mode == "--tf-download", "--no-sinf requires --tf-download");
        const Path output = options.at("--output");
        require(!std::filesystem::exists(output), "Output already exists");
        if (mode == "--tf-session-from-cookies") {
            require(options.size() == 1, "Unexpected session option");
            auto client = TestFlightClient::from_store_cookies(read(argument));
            client.save(output);
        } else if (mode == "--normalize-ipa") {
            require(options.size() == 1, "Unexpected normalization option");
            (void)normalize_testflight_ipa(argument, output);
        } else if (mode == "--kbsync") {
            require(options.size() == 2 && options.contains("--material"),
                    "kbSync requires --material");
            const auto identity = Json::parse(read(options.at("--material")));
            const auto& raw = identity.at("dsid");
            const auto id =
                raw.is_string() ? std::stoull(raw.get<std::string>()) : raw.get<std::uint64_t>();
            save_packet(output, generate_kbsync(id, unhex(identity.at("udid").get<std::string>())));
        } else if (mode == "--unwrap-transport") {
            require(options.size() == 3 && options.contains("--material") &&
                        options.contains("--install-metadata"),
                    "Transport requires identity and metadata");
            const auto identity = Json::parse(read(options.at("--material")));
            auto metadata = Json::parse(read(options.at("--install-metadata")));
            if (metadata.contains("data")) {
                metadata = metadata.at("data");
            }
            (void)unwrap_testflight_transport(argument,
                                              output,
                                              unhex(identity.at("udid").get<std::string>()),
                                              unbase64(metadata.at("dpInfo").get<std::string>()));
        } else {
            require(options.size() == 2 && options.contains("--tf-session"),
                    "TestFlight requires --tf-session");
            TestFlightClient client(read(options.at("--tf-session")));
            if (mode == "--tf-catalog") {
                client.save_catalog(output);
            } else if (mode == "--tf-install") {
                client.save_install_metadata(argument, output);
            } else {
                (void)client.download(argument, output, include_sinf);
            }
        }
        std::cout << "Completed. Result saved privately.\n";
        return 0;
    } catch (const apple_auth::Error& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    } catch (const std::exception&) {
        std::cerr << "Error: request failed; private values omitted.\n";
        return 1;
    }
}
