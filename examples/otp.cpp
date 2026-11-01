#include <apple_auth/core.hpp>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    try {
        if (argc != 3) {
            std::cerr << "Usage: apple_auth_otp PROFILE_FILE HARDWARE_HEX\n";
            return 2;
        }
        const std::string hex = argv[2];
        if (hex.size() != 40 ||
            hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
            throw std::runtime_error("Hardware binding must contain 40 hexadecimal digits");
        }
        apple_auth::HardwareId hardware{};
        for (std::size_t index = 0; index < hardware.size(); ++index) {
            hardware[index] =
                static_cast<std::uint8_t>(std::stoul(hex.substr(index * 2, 2), nullptr, 16));
        }
        const std::filesystem::path path = argv[1];
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            throw std::runtime_error("Cannot open profile file");
        }
        const apple_auth::Bytes file((std::istreambuf_iterator<char>(input)), {});
        const auto profile =
            apple_auth::Profile::import_file(file, hardware, path.filename().string());
        std::cout << "X-Apple-I-MD: "
                  << profile.otp_header(apple_auth::time_counter(std::time(nullptr))) << '\n'
                  << "X-Apple-I-MD-M: " << profile.machine_id_header() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
