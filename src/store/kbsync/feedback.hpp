#pragma once
#include "store/data/arithmetic.hpp"
#include <cstdint>
#include <span>

namespace apple_auth::detail::kbsync {

class Feedback {
  public:
    void transform(std::span<std::uint8_t> data) {
        for (auto& byte : data) {
            const auto input = static_cast<std::uint32_t>(byte);
            byte ^= static_cast<std::uint8_t>(first_);
            const std::uint32_t mixed = input * feedback_values[0] - first_ + feedback_values[1];
            const auto quotient1 = (std::uint64_t(mixed) * feedback_values[2]) >> 61;
            const std::uint32_t reduced =
                mixed - static_cast<std::uint32_t>(quotient1) * feedback_values[3];
            const auto quotient2 = (std::uint64_t(reduced) * feedback_values[4]) >> 39;
            std::uint32_t folded = reduced - static_cast<std::uint32_t>(quotient2) * 257u + mixed;
            folded = (folded ^ fourth_) - second_;
            std::uint32_t feedback = third_ + (folded ^ feedback_values[5]) +
                                     (feedback_values[6] & (folded << 1)) + feedback_values[7];
            const auto paired = feedback ^ fourth_;
            const auto third = third_ ^ feedback;
            const std::uint32_t next_first = third + feedback - paired;
            feedback += second_;
            const auto second = next_first ^ feedback;
            first_ = second + feedback_values[8];
            fourth_ = first_ + paired;
            second_ = first_ ^ feedback;
            third_ = first_ + third;
        }
    }

  private:
    std::uint32_t first_ = feedback_values[9];
    std::uint32_t second_ = feedback_values[10];
    std::uint32_t third_ = feedback_values[11];
    std::uint32_t fourth_ = feedback_values[12];
};

} // namespace apple_auth::detail::kbsync
