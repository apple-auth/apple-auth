#include "adi/provisioning/adjustments.hpp"
#include "data_mask.hpp"

namespace apple_auth::detail {
namespace provisioning_seed_detail {
void adjust_hardware_seed(std::array<std::uint8_t, 384>& state,
                          std::span<std::uint8_t> output,
                          std::span<const std::uint8_t, 128> parameters) {
    if (output.empty()) {
        throw std::invalid_argument("Empty provisioning adjustment output");
    }
    const auto initial = state;
    static const auto working_base = data_mask::decode(
        std::array<std::uint8_t, 64>{
            0xD4, 0xC7, 0xE7, 0x17, 0x96, 0x84, 0xC9, 0xB2, 0x6B, 0xAF, 0x70, 0x82, 0x55,
            0xDA, 0x39, 0x6F, 0xDA, 0xBA, 0xC3, 0x02, 0x6E, 0x48, 0xB9, 0x2C, 0xDB, 0x30,
            0xCF, 0x4B, 0xBB, 0xD7, 0xFF, 0xD9, 0x15, 0xB9, 0x6D, 0xFE, 0x5F, 0xCB, 0x18,
            0x7B, 0x83, 0xD8, 0xB6, 0xC6, 0x3B, 0xB2, 0x3B, 0xB8, 0x4D, 0xF1, 0xD7, 0x1F,
            0x22, 0xF2, 0xD6, 0x1A, 0xF8, 0x73, 0xAC, 0xF1, 0xD2, 0xDE, 0xA9, 0x8D,
        },
        0x68E4F5EAU);
    auto working = working_base;
    std::array<std::uint8_t, 64> local{};
    std::array<std::uint8_t, 64> fixed{};
    for (std::size_t index = 0; index < local.size(); ++index) {
        local[index] = parameters[64 + index] ^ 0x78;
        fixed[index] = byte(parameters[index] + 0xE9);
    }
    const std::uint8_t table_26_lookup = fixed[initial[90] & 0x3FU];
    working[26] = byte((byte((word(initial[75]) * table_26_lookup) >> 1U) -
                        ((word(initial[75]) * table_26_lookup) & 0xF2U) + 0x79U) ^
                       0x79U);
    state[197] = byte(initial[69] + initial[197]);
    working[40] = byte(initial[231] ^ 0xF3U);
    state[239] = byte(initial[239] + 0xE1U);
    const std::uint8_t state_bits = byte((initial[153] & 0x1AU) | (initial[194] & 0xE4U));
    local[23] = byte(((word(state_bits) >> 1U) - (state_bits & 0xF0U) + 0x78U) ^ 0x78U);
    local[6] = 0x28U;
    const std::uint8_t table_5_lookup = working[initial[153] & 0x3FU];
    working[5] =
        byte((0x77U + ((table_5_lookup & 0x18U) ^ 0xDEU) -
              (((2U * 0x77U) + (0xFEU * ((table_5_lookup & 0x18U) ^ 0x22U))) & 0xF2U) + 0x79U) ^
             0x79U);
    local[5] = byte(2U * (fixed[initial[17] & 0x3FU] / 5U));
    const std::uint8_t shifted_constant =
        byte(xor_shifts(0x77U, (initial[230] & 7U), ((0U - initial[230]) & 7U)));
    const std::uint8_t output_mask = byte(shifted_constant & 0x92U);
    working[11] = byte(shifted_constant & 0x10U);
    const std::uint8_t table_22_lookup = local[initial[51] & 0x3FU];
    const std::uint8_t table_22_shift = working[initial[112] & 0x3FU];
    state[64] = byte(working[initial[103] & 0x3FU] + initial[64]);
    state[11] = byte(word(initial[121]) >> 1U);
    working[32] = byte((0x1AU + 0x4BU) ^ 0x80U);
    working[52] = byte(0xDCU ^ (byte((0x39U & 0xADU) ^ 0x83U) / 5U));
    const std::uint8_t table_45_lookup = working[initial[59] & 0x3FU];
    const std::uint8_t shifted_lookup = byte(xor_shifts(((table_22_lookup & 0x90U) ^ 0x2AU),
                                                        ((table_22_shift & 2U) ^ 7U),
                                                        ((table_22_shift & 2U) ^ 1U)));
    local[22] = byte(shifted_lookup + 0x62U);
    working[45] = byte((0xFDU + (((word(byte(table_45_lookup ^ 0x79U)) >> 1U) & 0x1CU) ^ 0x82U) -
                        (((2U * 0xFDU) + ((table_45_lookup & 0x38U) ^ 0x3CU)) & 0xF2U) + 0x79U) ^
                       0x79U);
    working[53] = 0x5EU;
    local[12] = 0x84U;
    const std::uint8_t output_8_lookup = local[initial[75] & 0x3FU];
    const std::uint8_t table_2_left = fixed[initial[198] & 0x3FU];
    const std::uint8_t table_2_right = fixed[initial[163] & 0x3FU];
    working[2] = byte(0x7CU + (((initial[65] & 0x33U) | ((table_2_right & table_2_left) & 0xCCU)) |
                               ((table_2_right | table_2_left) & 0xC8U)));
    state[81] = byte((2U * state[239]) + 0xA4U);
    const std::uint8_t difference_left = local[initial[130] & 0x3FU];
    const std::uint8_t difference_right = working[initial[83] & 0x3FU];
    working[41] = byte(0xA1U ^ (word(byte(state[64] ^ 0xFFU)) * (initial[151] ^ 0x2DU)));
    const std::uint8_t state_192_shift = working[initial[158] & 0x3FU];
    state[192] = byte((initial[192] ^ byte(0x50U << (state_192_shift & 7U))) ^
                      byte(0x50U >> ((0U - state_192_shift) & 7U)));
    const std::uint8_t combined_left = working[initial[191] & 0x3FU];
    const std::uint8_t combined_right = fixed[initial[175] & 0x3FU];
    state[76] = byte((0xC6U & 0xDDU) ^ 0x86U);
    working[49] = byte(0x80U + 0x43U);
    state[131] = byte(initial[131] - ((fixed[initial[160] & 0x3FU] / 3U) & 0x76U));
    const std::uint8_t state_10_lookup = local[initial[210] & 0x3FU];
    state[10] = byte(initial[10] -
                     (~((state_10_lookup & 0xFU) | (0xC5U & ((state_10_lookup & 0xF0U) ^ 0xFU)))));
    working[22] = byte(0xE6U - (((working[initial[72] & 0x3FU] ^ 0xDDU) & initial[139]) & 0xA7U));
    const std::uint8_t lookup_difference = byte((difference_right - difference_left) | 8U);
    const std::uint8_t lookup_bias = byte(0U - lookup_difference - 13U);
    local[14] = byte(
        local[initial[48] & 0x3FU] -
        ((fixed[lookup_bias & 0x3FU] & (working[11] ^ 0xFFU)) | (working[11] & 0x94U)) + 0xDAU);
    const std::uint8_t combined_lookups =
        byte((combined_left & combined_right) | ((combined_left | combined_right) & 0x7DU));
    const std::uint8_t folded_bits = std::rotl(combined_lookups, 1);
    working[51] = byte(folded_bits ^ 0xC1U);
    const std::uint8_t output_9_shift = local[initial[146] & 0x3FU];
    const std::uint8_t square_lookup = working[initial[247] & 0x3FU];
    working[32] =
        byte(working[32] ^ ((((0xE1U & 0xE2U) ^ 0xE2U) | (initial[203] & 0xE1U)) + 0xD8U));
    const std::uint8_t output_21_lookup = local[initial[211] & 0x3FU];
    const std::uint8_t state_77_left = fixed[initial[180] & 0x3FU];
    const std::uint8_t state_77_right = fixed[initial[194] & 0x3FU];
    const std::uint8_t state_77_bits = byte(((initial[23] ^ 0x40U) | state_77_left) & 0xB9U);
    state[77] =
        byte((((initial[23] & state_77_left) | state_77_bits) & (word(state_77_right) * 3U)) |
             (((((3U * state_77_right) + 0x80U) | (initial[23] & state_77_left)) | state_77_bits) &
              0x75U));
    working[57] = byte(lookup_difference + 0x6DU + 0x4DU);
    local[53] = initial[238];
    local[41] = byte(cube_byte((fixed[lookup_bias & 0x3FU] + 0x80U) & 0x63U));
    working[29] = byte(0x9CU - initial[207]);
    local[49] =
        byte((~(((initial[115] & 0x75U) | (fixed[initial[113] & 0x3FU] & 0x8AU)) ^ 0x1BU)) ^ 0x78U);
    const std::uint8_t table_36_lookup = working[initial[185] & 0x3FU];
    const std::uint8_t table_36_mask = local[initial[242] & 0x3FU];
    working[36] = byte((fixed[table_36_lookup & 0x3FU] ^ 0xC4U) ^
                       ((table_36_mask & 0x43U) | (0x39U & (table_36_mask | 0x43U))));
    local[46] =
        byte((((0x1CU & 0xC1U) ^ 0xC1U) |
              (xor_shifts(0xF6U, ((0U - initial[128]) & 7U), (initial[128] & 7U)) & 0x1CU)) ^
             0x8AU);
    local[48] = 0xD4U;
    const std::uint8_t table_10_lookup = working[initial[166] & 0x3FU];
    working[10] = byte(0x59U ^ ((0xA7U & (table_10_lookup ^ 0x88U)) |
                                (((~(0xA7U ^ 0x79U)) | (~(table_10_lookup ^ 0x79U))) & 0x51U)));
    const std::uint8_t square_input =
        byte((square_lookup & (local[6] ^ 0xFFU)) | (local[6] & 0x69U));
    const std::uint8_t squared_lookup = byte(word(square_input) * square_input);
    const std::uint8_t table_34_lookup = working[(squared_lookup & 0x3FU) ^ 0xBU];
    const std::uint8_t table_34_mask = working[initial[147] & 0x3FU];
    working[34] = byte(0xD5U + table_34_lookup +
                       ((initial[53] & table_34_mask) | ((initial[53] | table_34_mask) & 0x33U)));
    const std::uint8_t state_163_left = local[initial[116] & 0x3FU];
    const std::uint8_t state_163_right = local[initial[56] & 0x3FU];
    const std::uint8_t state_163_lookup = working[initial[143] & 0x3FU];
    const std::uint8_t square_adjustment = byte(squared_lookup ^ 0xCBU);
    state[163] = byte(initial[163] - (((word(state_163_lookup) * 3U) & (0xD9U ^ 0xFFU)) |
                                      (0xD9U & ((state_163_right & (square_adjustment ^ 0xFFU)) |
                                                (square_adjustment & state_163_left)))));
    local[8] = byte((0x8CU & 0xCBU) ^ 0xA7U);
    const std::uint8_t table_7_lookup = fixed[state[76] & 0x3FU];
    working[7] =
        byte(0xA8U - ((table_7_lookup & 0x18U) | (working[51] & (table_7_lookup | 0x18U))));
    working[2] = byte(
        ((byte(((word(byte(lookup_bias | 0xC3U)) * 0xCDU) & 0xFC00U) >> 10U) ^ 0x39U) + 0x40U) ^
        0x79U);
    working[23] = byte(0x15U + 5U);
    const std::uint8_t output_0_lookup = fixed[initial[130] & 0x3FU];
    const std::uint8_t table_11_left = local[initial[32] & 0x3FU];
    const std::uint8_t table_11_right = fixed[state[10] & 0x3FU];
    working[11] = byte(initial[237] & ((table_11_left & table_11_right) |
                                       (((table_11_left ^ 0x20U) | table_11_right) & 0xDEU)));
    state[32] =
        byte(initial[32] - (((initial[111] / 5U) & (folded_bits ^ 0x3EU)) | (working[51] & 0x19U)));
    const std::uint8_t output_delta = byte((initial[180] & 0xC3U) | 0x10U);
    const std::array<std::uint8_t, 32> adjustments = {
        byte(0U -
             (word(byte((output_0_lookup & 0x88U) | 0x17U)) * ((output_0_lookup & 0x88U) | 0x17U)) +
             0xE7U),
        0x78U,
        0xDDU,
        0x6FU,
        0x79U,
        0xB2U,
        byte(0U - lookup_difference + 0xB3U),
        0x88U,
        byte(output_mask -
             ((((output_8_lookup + 0xCFU) & output_delta) |
               (((output_8_lookup ^ 0x40U) + 0xFU) & 0x2DU)) |
              (output_delta & 0x2DU)) +
             0x1DU),
        xor_shifts(fixed[initial[127] & 0x3FU],
                   (output_9_shift + 0xB6U) & 7U,
                   ((output_9_shift ^ 0xFFU) + 0x53U) & 7U),
        0xA7U,
        square_adjustment,
        0x3FU,
        0x41U,
        0xB9U,
        6U,
        0xE0U,
        0xBBU,
        working[51],
        0xB1U,
        0x63U,
        byte(((output_21_lookup ^ 0x18U) | 0x9EU) + fixed[initial[187] & 0x3FU] + 0x2AU),
        0xC3U,
        0x3BU,
        0x7DU,
        byte(shifted_lookup + 0x62U),
        0xC3U,
        0xD3U,
        0xA5U,
        0x93U,
        0x94U,
        0xDEU,
    };
    for (std::size_t index = 0; index < adjustments.size(); ++index) {
        add_wrapped(output, index, adjustments[index]);
    }

    fold_adjustment_tables(output, working, local);
}
} // namespace provisioning_seed_detail
} // namespace apple_auth::detail
