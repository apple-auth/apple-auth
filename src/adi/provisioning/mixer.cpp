#include "adi/provisioning/adjustments.hpp"
#include "data_mask.hpp"

namespace apple_auth::detail {
namespace provisioning_mixer_detail {
void adjust_hardware_mixer(std::array<std::uint8_t, 384>& state,
                           std::span<std::uint8_t> output,
                           std::span<const std::uint8_t, 128> parameters) {
    if (output.empty()) {
        throw std::invalid_argument("Empty provisioning adjustment output");
    }
    const auto initial = state;
    static const auto working_base = data_mask::decode(
        std::array<std::uint8_t, 64>{
            0x46, 0x33, 0xFD, 0xCE, 0xB9, 0xFD, 0x4F, 0x2F, 0x05, 0xDA, 0x3C, 0x75, 0xB9,
            0x67, 0x3B, 0xAB, 0xCD, 0x39, 0x6E, 0xB1, 0x0F, 0x1F, 0xF6, 0xDF, 0xAA, 0x84,
            0x87, 0xAD, 0x7B, 0x49, 0x20, 0x0E, 0xE9, 0x80, 0xB2, 0x6B, 0x1C, 0xE9, 0x89,
            0xA6, 0xB5, 0xBC, 0x9E, 0xE5, 0x1F, 0x2C, 0x26, 0x55, 0xA3, 0x5E, 0x00, 0x89,
            0xE5, 0x0D, 0x80, 0x29, 0xD3, 0x98, 0x1F, 0xE8, 0x0F, 0xF0, 0xD5, 0xF9,
        },
        0xE3630E3DU);
    auto working = working_base;
    std::array<std::uint8_t, 64> local{};
    std::array<std::uint8_t, 64> fixed{};
    for (std::size_t index = 0; index < local.size(); ++index) {
        local[index] = parameters[64 + index] ^ 0x7D;
        fixed[index] = byte(parameters[index] + 0xBA);
    }
    working[26] = byte(initial[54] ^ 0x73U);
    working[40] = 0xFAU;
    local[25] = 0x4BU;
    local[47] = byte((((local[initial[144] & 0x3FU] & 0xEEU) ^ 0xFEU) + 0x15U) ^ 0xCAU);
    local[58] = byte(0U - initial[97] + 0xE8U);
    state[227] = initial[63];
    local[26] = byte(
        (((0U - (((0xEDU ^ 0xFFU) & 0xC9U) | (0xEDU & (initial[148] + 0x6BU))) + 0x31U) ^ 0x7DU) +
         0x80U) ^
        0x7DU);
    state[34] = byte(working[initial[28] & 0x3FU] + initial[34] + 0x4BU);
    local[8] = byte((~(fixed[initial[41] & 0x3FU] | 0xEDU)) | (((0x8EU * 0xFDU) + 0xBAU) & 0xECU));
    const std::uint8_t rotation_source = fixed[initial[191] & 0x3FU];
    const std::uint8_t table_2_left = working[initial[103] & 0x3FU];
    const std::uint8_t table_2_right = working[initial[24] & 0x3FU];
    working[2] = byte((((word(initial[80]) * table_2_left) & (word(table_2_right) * 0x9AU)) |
                       ((word(table_2_right) * 0x9AU) & 0x76U)) |
                      ((word(initial[80]) * table_2_left) & 0x76U));
    state[199] =
        byte(initial[199] - ((initial[178] & 0xA5U) | ((word(initial[114]) * 3U) & 0x5AU)));
    working[38] = byte(0x41U + fixed[initial[29] & 0x3FU]);
    state[95] = byte(initial[95] - local[initial[5] & 0x3FU]);
    working[15] = byte(0xEBU + (2U * working[initial[52] & 0x3FU]) - cube_byte(initial[54]));
    working[10] = byte((initial[148] + 0x4DU) ^ 0x80U);
    working[50] = 0x42U;
    const std::uint8_t table_11_lookup = working[initial[184] & 0x3FU];
    const std::uint8_t table_11_shift = working[initial[65] & 0x3FU];
    local[14] =
        byte((word(byte((local[58] & 0x6DU) ^ 0x92U)) * ((local[58] & 0x6DU) ^ 0x92U)) + 0x26U);
    local[28] = byte(((initial[158] & local[initial[37] & 0x3FU]) - initial[51]) ^ 0xADU);
    local[11] =
        xor_shifts(table_11_lookup & 0x81U, (table_11_shift & 4U) ^ 5U, (table_11_shift & 4U) ^ 3U);
    const std::uint8_t output_2_shift = working[initial[109] & 0x3FU];
    const std::uint8_t majority_left = fixed[initial[245] & 0x3FU];
    const std::uint8_t majority_right = fixed[initial[45] & 0x3FU];
    local[62] =
        byte((((initial[69] + 0x80U) & 0x10U) | ((word(initial[112]) * 2U) & 0x6CU)) ^ 0x6BU);
    const std::uint8_t state_24_mask = local[initial[24] & 0x3FU];
    const std::uint8_t lookup_bias =
        byte(0U - (word(rotation_source) >> 1U) + (rotation_source & 0x36U) + 0x64U);
    const std::uint8_t rotated_bits = byte(
        ((initial[162] & std::rotl(rotation_source, 7)) | ((initial[162] | lookup_bias) & 0x18U)) ^
        0x63U);
    const std::uint8_t state_24_lookup = fixed[rotated_bits & 0x3FU];
    working[42] = 0x96U;
    state[24] = byte((state_24_lookup | 0xCDU) ^ ((state_24_mask ^ 0x7DU) & 0x47U) ^ 0xE5U);
    const std::uint8_t state_95_bits = byte(((initial[95] & 0x16U) ^ 0x31U) + 0x63U);
    working[3] = byte((state_95_bits & 0x8AU) ^ 0x64U);
    const std::uint8_t combined_left = local[initial[74] & 0x3FU];
    const std::uint8_t cubed_bits = cube_byte(byte(state_95_bits | (initial[200] + 0x80U)));
    const std::uint8_t combined_right = local[(0U - cubed_bits + 0x16U) & 0x3FU];
    local[40] = byte(cube_byte(byte((initial[245] & 0x18U) ^ 0x63U)) + 0xAEU);
    state[174] = byte(0U - fixed[working[initial[92] & 0x3FU] & 0x3FU] - fixed[initial[6] & 0x3FU] +
                      initial[174]);
    const std::uint8_t state_103_lookup = working[initial[59] & 0x3FU];
    const std::uint8_t majority_bits =
        byte((majority_right & majority_left) | ((majority_right | majority_left) & state_95_bits));
    const std::uint8_t table_bits =
        byte(((majority_bits & 0x99U) | (local[26] & ((majority_bits ^ 0x19U) | 0x99U))) ^ 0xBEU);
    const std::uint8_t selected_bits =
        byte((state_103_lookup & 0x2CU) | (table_bits & ((state_103_lookup & 0xD3U) ^ 0x2CU)));
    const std::uint8_t shift_source = byte(initial[21] | fixed[state[34] & 0x3FU]);
    state[103] =
        byte(initial[103] ^ xor_shifts(selected_bits, shift_source & 7U, (0U - shift_source) & 7U));
    working[60] = byte(0x97U + 4U);
    const std::uint8_t state_23_bits =
        byte((initial[45] & 0xF4U) | ((fixed[initial[173] & 0x3FU] / 3U) & 9U));
    state[23] = byte(state_23_bits ^ 2U);
    const std::uint8_t shifted_lookup = byte(xor_shifts(
        fixed[((0xFDU ^ 0x7FU) + 0xC6U) & 0x3FU], ((0U - initial[120]) & 7U), (initial[120] & 7U)));
    const std::uint8_t scaled_bits = byte(((3U * rotated_bits) & 0x3DU) + rotated_bits);
    state[235] = byte(initial[235] ^
                      ((shifted_lookup & scaled_bits) | ((shifted_lookup | scaled_bits) & 0xDEU)));
    working[15] = byte(working[15] + 0x32U);
    working[53] = byte(0x13U ^ ((((0xE1U & 0xBCU) ^ 0xBCU) & (working[38] ^ 0xFFU)) |
                                ((0U - cubed_bits + 0x96U) & working[38])));
    state[126] = byte(initial[126] ^ (word(byte(local[initial[74] & 0x3FU] + 0x3BU)) * 3U));
    state[224] = 0xEEU;
    state[253] = initial[146];
    const std::uint8_t table_36_left = local[state[235] & 0x3FU];
    const std::uint8_t table_36_right = working[initial[111] & 0x3FU];
    state[10] = byte(initial[10] + 0x7DU);
    working[36] = byte((((word(initial[99]) * 2U) ^
                         (((table_36_right ^ 0x5AU) & 0xF0U) | ((table_36_left ^ 0x7DU) & 0xFU))) ^
                        0xE1U) ^
                       0x5DU);
    const std::uint8_t output_30_left = working[initial[9] & 0x3FU];
    const std::uint8_t output_30_right = local[initial[168] & 0x3FU];
    const std::uint8_t combined_lookups =
        byte(((combined_right ^ 1U) & (combined_left ^ 1U)) |
             (0x2CU & ((combined_right ^ 1U) | (combined_left ^ 1U))));
    const std::uint8_t lookup_index =
        byte((word(combined_lookups) >> 1U) - (combined_lookups & 0xCU) + 6U);
    working[13] = 0xAU;
    const std::uint8_t table_2_mask = local[initial[53] & 0x3FU];
    const std::uint8_t table_2_bits = byte(fixed[initial[105] & 0x3FU] | 0x48U);
    working[2] = byte((table_2_bits & (table_2_mask ^ 0xFFU)) |
                      ((table_2_bits | (table_2_mask ^ 0xFFU)) & 0xE8U));
    const std::uint8_t product =
        byte(word(local[initial[22] & 0x3FU]) * fixed[initial[165] & 0x3FU]);
    working[55] = byte(word(product) * product);
    const std::uint8_t output_7_lookup = fixed[working[initial[62] & 0x3FU] & 0x3FU];
    state[252] = byte(initial[252] ^ 0x5CU);
    working[51] =
        byte(0xFAU + (initial[210] | (local[58] + local[(output_7_lookup / 5U) ^ 0x34U])));
    state[33] = byte(initial[33] - byte((word(working[initial[249] & 0x3FU]) * 0xA1U) >> 1U));
    local[27] = byte((word(initial[217]) * initial[217]) + 0xDCU);
    state[172] = byte(initial[172] ^ (initial[40] & 0x51U) ^ 0xD5U);
    working[56] = byte((initial[106] & (lookup_index ^ 0x18U)) |
                       ((lookup_index ^ 0xA7U) & ((initial[22] & 0x24U) ^ 0x8BU)));
    const std::uint8_t table_32_lookup = fixed[initial[181] & 0x3FU];
    working[32] =
        byte(0xE8U + (((((local[initial[130] & 0x3FU] ^ 0x7DU) & 0x32U) |
                        (fixed[initial[213] & 0x3FU] & 0xCDU)) ^
                       0x30U) &
                      ((table_32_lookup & local[8]) | (0xBAU & (table_32_lookup | local[8])))));
    const std::uint8_t output_18_left = working[initial[165] & 0x3FU];
    local[1] = byte(local[initial[35] & 0x3FU] ^ 0x3CU);
    const std::uint8_t output_18_right = local[initial[85] & 0x3FU];
    const std::array<std::uint8_t, 32> adjustments = {
        byte(lookup_index ^ 0xE7U),
        0x46U,
        xor_shifts(byte(word(fixed[initial[254] & 0x3FU]) * 3U),
                   output_2_shift & 7U,
                   (0U - output_2_shift) & 7U),
        0xFAU,
        0xFU,
        0x2CU,
        0xCU,
        byte((output_7_lookup / 5U) ^ 0x74U),
        0x26U,
        byte(fixed[initial[136] & 0x3FU] + 0x25U),
        0xBCU,
        0x6BU,
        0x48U,
        state_95_bits,
        0x48U,
        0xA1U,
        0xD0U,
        scaled_bits,
        byte((((output_18_right ^ 0x7DU) & 0x5EU) |
              ((word(byte(output_18_left ^ 0x5AU)) * 2U) & 0xA0U)) ^
             0xFCU),
        0x3AU,
        table_bits,
        0x7BU,
        0x6BU,
        byte(0U - cubed_bits + 0x96U),
        0xEEU,
        0x42U,
        0x77U,
        initial[105],
        0xFAU,
        2U,
        byte(((output_30_left & output_30_right) |
              (((output_30_left ^ 8U) | (output_30_right ^ 9U)) & 0x76U)) &
             0xD6U),
        0x67U,
    };
    for (std::size_t index = 0; index < adjustments.size(); ++index) {
        add_wrapped(output, index, adjustments[index]);
    }

    fold_adjustment_tables(output, working, local);
}
} // namespace provisioning_mixer_detail
} // namespace apple_auth::detail
