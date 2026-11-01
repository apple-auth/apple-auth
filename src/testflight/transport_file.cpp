#include "testflight/internal.hpp"
#include <fstream>

namespace apple_auth::tfdetail {

std::uint64_t
unwrap_transport(const Path& source, const Path& destination, View hardware20, View dp_info88) {
    require(hardware20.size() == 20 && dp_info88.size() == 88,
            "Transport unwrap requires hardware20 and dpInfo88");
    require(!std::filesystem::exists(destination), "Transport output already exists");
    require(std::filesystem::absolute(source).lexically_normal() !=
                std::filesystem::absolute(destination).lexically_normal(),
            "Transport input and output must differ");
    std::ifstream input(source, std::ios::binary);
    require(bool(input), "Cannot open transport input");
    const TestFlightTransport cipher(hardware20, dp_info88);
    if (!destination.parent_path().empty()) {
        std::filesystem::create_directories(destination.parent_path());
    }
    const Path temporary = destination.string() + "." + hex(random_bytes(8)) + ".partial";
    std::uint64_t count = 0;
    try {
        std::ofstream output(temporary, std::ios::binary);
        require(bool(output), "Cannot create transport output");
        std::filesystem::permissions(
            temporary, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        std::array<std::uint8_t, 32768> buffer{};
        while (input.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) ||
               input.gcount()) {
            auto chunk = std::span(buffer).first(static_cast<std::size_t>(input.gcount()));
            cipher.decrypt_chunk(chunk);
            if (!count) {
                require(chunk.size() >= 4 && chunk[0] == 'P' && chunk[1] == 'K' && chunk[2] == 3 &&
                            chunk[3] == 4,
                        "Transport metadata does not produce an IPA");
            }
            output.write(reinterpret_cast<const char*>(chunk.data()),
                         static_cast<std::streamsize>(chunk.size()));
            require(bool(output), "Cannot write transport output");
            count += chunk.size();
        }
        require(input.eof() && count != 0, "Cannot read complete transport input");
        output.close();
        require(bool(output), "Cannot finalize transport output");
        std::filesystem::create_hard_link(temporary, destination);
        std::filesystem::remove(temporary);
    } catch (...) {
        std::error_code error;
        std::filesystem::remove(temporary, error);
        throw;
    }
    return count;
}

} // namespace apple_auth::tfdetail
