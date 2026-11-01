#include <apple_auth/client.hpp>
#include <fstream>
#include <iostream>
#include <iterator>
#include <nlohmann/json.hpp>

namespace {
using namespace apple_auth;
using Path = std::filesystem::path;

void require(bool condition, const char* message) {
    if (!condition) {
        throw Error(ErrorCode::invalid_argument, message);
    }
}

Bytes read(const Path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    require(bool(stream) && stream.tellg() >= 0 && stream.tellg() <= (1 << 20),
            "Invalid private input file");
    stream.seekg(0);
    return Bytes(std::istreambuf_iterator<char>{stream}, {});
}

TwoFactor verification() {
    return [] {
        std::cerr << "Verification code: " << std::flush;
        std::string code;
        require(bool(std::getline(std::cin, code)), "Verification input closed");
        return code;
    };
}

std::pair<std::string, std::string> credentials(const Path& path) {
    std::ifstream file(path);
    std::string email, password;
    require(bool(std::getline(file, email)) && bool(std::getline(file, password)),
            "Cannot read credentials file");
    for (auto* value : {&email, &password}) {
        if (!value->empty() && value->back() == '\r') {
            value->pop_back();
        }
    }
    if (email.starts_with("\xEF\xBB\xBF")) {
        email.erase(0, 3);
    }
    return {email, password};
}

void usage() {
    std::cout
        << "apple-auth-store mac-login STATE CREDENTIALS_FILE SESSION.plist\n"
           "apple-auth-store mac-pet-login STATE EMAIL ACCOUNT.plist SESSION.plist\n"
           "apple-auth-store configurator-login STATE CREDENTIALS_FILE SESSION.plist\n"
           "apple-auth-store ios-context SESSION.plist COUNTRY OUTPUT.json\n"
           "apple-auth-store tf-context SESSION.plist TF_PROFILE.json OUTPUT.json\n"
           "TF_PROFILE: {\"udid\":\"40 hex digits\",\"headers\":{...macOS TestFlight headers...}}\n"
           "Sessions and contexts contain secrets. Failed saved sessions never trigger a new "
           "login.\n";
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--help") {
        usage();
        return 0;
    }
    try {
        require(argc >= 2, "Missing command");
        const std::string command = argv[1];
        if (command == "ios-context" || command == "tf-context") {
            require(argc == 5, "Context export requires session, profile/country and output");
            const auto session = StoreSession::load(argv[2]);
            if (command == "ios-context") {
                session.save_ios_context(argv[4], argv[3]);
            } else {
                const auto data = read(argv[3]);
                const auto profile = nlohmann::json::parse(data.begin(), data.end());
                const auto encoded = profile.at("udid").get<std::string>();
                require(encoded.size() == 40 && encoded.find_first_not_of(
                                                    "0123456789abcdefABCDEF") == std::string::npos,
                        "Expected hardware20");
                Bytes hardware;
                for (std::size_t i = 0; i < encoded.size(); i += 2) {
                    hardware.push_back(
                        static_cast<std::uint8_t>(std::stoul(encoded.substr(i, 2), nullptr, 16)));
                }
                session.save_testflight_context(
                    argv[4], hardware, profile.at("headers").get<Headers>());
            }
        } else if (command == "mac-pet-login") {
            require(argc == 6 && !std::filesystem::exists(argv[5]),
                    "PET login requires state, email, account and new output");
            ClientOptions options;
            options.device_platform = DevicePlatform::mac;
            Client device(argv[2], options);
            const auto account = AccountSession::load(argv[4]);
            const auto session = device.login_store_with_pet(argv[3], account);
            session.save(argv[5]);
        } else {
            require(argc == 5 && (command == "mac-login" || command == "configurator-login") &&
                        !std::filesystem::exists(argv[4]),
                    "Invalid login command or output already exists");
            auto [email, password] = credentials(argv[3]);
            if (command == "configurator-login") {
                StoreClient device(argv[2], StoreProtocol::configurator);
                const auto session = device.login(email, password, verification());
                session.save(argv[4]);
            } else {
                ClientOptions options;
                options.device_platform = DevicePlatform::mac;
                Client device(argv[2], options);
                const auto account = device.login(email, password, verification());
                account.save(Path(argv[2]) / "account-session.plist");
                const auto session = device.login_store_with_pet(email, account);
                session.save(argv[4]);
            }
        }
        std::cout << "Completed. Private result saved.\n";
        return 0;
    } catch (const std::exception&) {
        std::cerr << "Store operation failed; no automatic relogin or purchase attempted.\n";
        return 1;
    }
}
