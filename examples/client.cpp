#include <apple_auth/client.hpp>
#include <fstream>
#include <iostream>

namespace {
void usage() {
    std::cerr << "Usage: apple-auth provision STATE_DIR [OPTIONS]\n"
                 "       apple-auth login STATE_DIR CREDENTIALS_FILE [OPTIONS]\n"
                 "Options: --device windows|mac|iphone|android\n"
                 "         --mac-model MacBookAir10,1 --macos-version 14.4.1\n"
                 "         --macos-build 23E224 (required for unknown releases)\n"
                 "         --user-agent AGENT --client-info INFO\n"
                 "         --header 'Name: value' (repeatable)\n"
                 "Credentials file: Apple ID on line one, password on line two.\n";
}

apple_auth::DevicePlatform device_platform(const std::string& name) {
    using Platform = apple_auth::DevicePlatform;
    if (name == "windows") {
        return Platform::windows;
    }
    if (name == "mac") {
        return Platform::mac;
    }
    if (name == "iphone") {
        return Platform::iphone;
    }
    if (name == "android") {
        return Platform::android;
    }
    throw std::runtime_error("Unknown device platform: " + name);
}

apple_auth::ClientOptions parse_options(int argc, char** argv, int first) {
    apple_auth::ClientOptions options;
    for (int i = first; i < argc; ++i) {
        const std::string flag(argv[i]);
        if (i + 1 == argc) {
            throw std::runtime_error("Missing value for " + flag);
        }
        const std::string value(argv[++i]);
        if (flag == "--device") {
            options.device_platform = device_platform(value);
        } else if (flag == "--mac-model") {
            options.mac_device.model = value;
        } else if (flag == "--macos-version") {
            options.mac_device.macos_version = value;
        } else if (flag == "--macos-build") {
            options.mac_device.macos_build = value;
        } else if (flag == "--user-agent") {
            options.user_agent = value;
        } else if (flag == "--client-info") {
            options.client_info = value;
        } else if (flag == "--header") {
            const auto colon = value.find(':');
            if (colon == std::string::npos || colon == 0) {
                throw std::runtime_error("Expected --header 'Name: value'");
            }
            const auto start = value.find_first_not_of(" \t", colon + 1);
            options.headers[value.substr(0, colon)] =
                start == std::string::npos ? "" : value.substr(start);
        } else {
            throw std::runtime_error("Unknown option: " + flag);
        }
    }
    return options;
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--help") {
            usage();
            return 0;
        }
        if (argc < 3 || (std::string(argv[1]) != "provision" && std::string(argv[1]) != "login")) {
            usage();
            return 2;
        }
        const bool login = std::string(argv[1]) == "login";
        if (login && (argc < 4 || std::string(argv[3]).starts_with("--"))) {
            throw std::runtime_error("Login requires a credentials file");
        }
        auto options = parse_options(argc, argv, login ? 4 : 3);
        apple_auth::Client client(argv[2], std::move(options));
        if (client.device_platform() == apple_auth::DevicePlatform::mac) {
            const auto device = client.mac_device();
            std::cout << "Mac: " << device.model << ", macOS " << device.macos_version << " ("
                      << device.macos_build << ")\n";
        }
        if (std::string(argv[1]) == "provision") {
            client.provision();
            std::cout << "Device profile is ready.\n";
        } else {
            std::ifstream credentials(argv[3]);
            std::string email, password;
            if (!std::getline(credentials, email) || !std::getline(credentials, password)) {
                throw std::runtime_error("Cannot read credentials file");
            }
            if (!email.empty() && email.back() == '\r') {
                email.pop_back();
            }
            if (!password.empty() && password.back() == '\r') {
                password.pop_back();
            }
            const auto session = client.login(email, password, [] {
                std::cerr << "Trusted-device verification code: " << std::flush;
                std::string code;
                if (!std::getline(std::cin, code)) {
                    throw std::runtime_error("Input closed");
                }
                return code;
            });
            session.save(std::filesystem::path(argv[2]) / "account-session.plist");
            std::cout << "Login completed; session saved.\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
