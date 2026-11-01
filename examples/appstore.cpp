#include <apple_auth/appstore.hpp>
#include <fstream>
#include <iostream>
#include <iterator>

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--help") {
        std::cout << "apple-auth-appstore CONTEXT.json catalog|metadata|download|acquire-free "
                     "APP_ID OUTPUT\n"
                     "apple-auth-appstore --mac STORE_DIR SESSION.plist COUNTRY "
                     "catalog|metadata|download|package APP_ID OUTPUT\n"
                     "Mac package saves a validated .pkg; download preserves the original asset.\n"
                     "Uses saved iOS Store cookies. acquire-free explicitly requests one "
                     "zero-price license.\n";
        return 0;
    }
    const bool mac = argc == 8 && std::string(argv[1]) == "--mac";
    if (!mac && argc != 5) {
        return 2;
    }
    try {
        const std::filesystem::path output = argv[mac ? 7 : 4];
        if (std::filesystem::exists(output)) {
            return 2;
        }
        std::unique_ptr<apple_auth::AppStoreIosClient> ios_client;
        std::unique_ptr<apple_auth::AppStoreMacClient> mac_client;
        if (mac) {
            const auto session = apple_auth::StoreSession::load(argv[3]);
            mac_client = std::make_unique<apple_auth::AppStoreMacClient>(session, argv[2], argv[4]);
        } else {
            std::ifstream input(argv[1], std::ios::binary);
            if (!input) {
                return 2;
            }
            const apple_auth::Bytes context(std::istreambuf_iterator<char>{input}, {});
            ios_client = std::make_unique<apple_auth::AppStoreIosClient>(context);
        }
        std::size_t end = 0;
        const auto id = std::stoull(argv[mac ? 6 : 3], &end);
        if (end != std::string(argv[mac ? 6 : 3]).size() || !id) {
            return 2;
        }
        const std::string operation = argv[mac ? 5 : 2];
        if (operation == "download" || (mac && operation == "package")) {
            if (mac) {
                const auto result = operation == "package"
                                        ? mac_client->download_package(id, output)
                                        : mac_client->download(id, output);
                std::cout << (result.package_validated
                                  ? "Mac installation package saved and checked.\n"
                              : result.transport_wrapped
                                  ? "Original Mac Store asset saved; transport wrapping remains.\n"
                                  : "Original Mac Store asset saved.\n");
            } else {
                (void)ios_client->download(id, output);
            }
        } else {
            if (operation != "catalog" && operation != "metadata" && operation != "acquire-free") {
                return 2;
            }
            if (mac && operation == "acquire-free") {
                return 2;
            }
            const auto data =
                mac ? (operation == "catalog" ? mac_client->catalog(id) : mac_client->metadata(id))
                : operation == "catalog"      ? ios_client->catalog(id)
                : operation == "acquire-free" ? ios_client->acquire_free(id)
                                              : ios_client->metadata(id);
            std::ofstream destination(output, std::ios::binary);
            if (!destination) {
                return 2;
            }
            std::filesystem::permissions(
                output, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
            destination.write(reinterpret_cast<const char*>(data.data()),
                              static_cast<std::streamsize>(data.size()));
            if (!destination) {
                return 2;
            }
        }
        std::cout << "Completed. Result saved privately.\n";
        return 0;
    } catch (const std::exception&) {
        std::cerr << "App Store request failed; no automatic login or purchase attempted.\n";
        return 1;
    }
}
