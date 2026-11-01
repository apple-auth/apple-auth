#include "adi/data/tables.hpp"
#include "adi/internal.hpp"

namespace apple_auth::detail {
namespace {
std::array<std::uint8_t, 16> reduction_input(const std::array<std::uint8_t, 13>& bias) {
    using file_key_detail::byte;
    std::array<std::uint8_t, 16> input{};
    // Reduction input; this is separate from the provisioned OTP seed.
    input[0] = byte(bias[7] + bias[6] + 0x97U);
    input[1] = byte(0x27U);
    input[2] = byte((std::rotl(byte(bias[12]), int(6U)) ^ 0x61U) + 0x87U);
    input[3] = byte(bias[5] + bias[8] + 0xA9U);
    input[4] = byte(0xD5U);
    input[5] = byte(0xFU);
    input[6] = byte((bias[1] ^ 0x70U) + 0xB9U);
    input[7] = byte((bias[2] ^ 0xDAU) + 0x47U);
    input[8] = byte(bias[11] + 3U);
    input[9] = byte(0x25U);
    input[10] = byte(0U - bias[3] + 0xEU);
    input[11] = byte(0x23U);
    input[12] = byte(0U - bias[0] + 0xEBU);
    input[13] = byte(bias[4] + (bias[10] ^ 0x34U) + 0xBU);
    input[14] = byte(0x93U);
    input[15] = byte((bias[9] ^ 0x24U) + 0xCDU);
    return input;
}
} // namespace

FileKeyNonlinearState mutate_file_key_state(const FileKeyDiffusionState& initial,
                                            std::span<const std::uint8_t, 128> tables) {
    using file_key_detail::byte;
    using file_key_detail::cube_byte;
    using file_key_detail::word;
    using file_key_detail::xor_shifts;
    FileKeyNonlinearState result{initial, {}, {}};
    std::copy(tables.begin(), tables.end(), result.tables.begin());

    const std::uint8_t state_94_lookup = result.tables[initial[40] & 0x3FU];
    const std::uint8_t state_94_mask = result.tables[64U + (initial[52] & 0x3FU)];
    const std::uint8_t selected_bits =
        byte(((state_94_lookup ^ 0x73U) & 0x75U) | ((tables[33] ^ 0x73U) & 0x8AU));
    result.state[94] =
        byte(initial[94] - (((selected_bits ^ 0x73U) &
                             (((tables[36] ^ 0x73U) & 0x20U) | (state_94_mask & tables[36]))) |
                            (((selected_bits ^ 0xF3U) | ((tables[36] ^ 0x73U) & 0x20U) |
                              (state_94_mask & tables[36])) &
                             0x2BU)));
    result.state[64] =
        byte(initial[64] ^ (file_key_fixed_table[initial[85] & 0x3FU] & 0xAU) ^ 0x22U);
    const std::uint8_t bias_2_lookup = result.tables[initial[157] & 0x3FU];
    const std::uint8_t bias_6_lookup = result.tables[initial[104] & 0x3FU];
    result.tables[8] = byte(0xFCU);
    result.state[175] = byte(initial[175] - initial[52]);
    const std::uint8_t bias_1_lookup = result.tables[64U + (initial[44] & 0x3FU)];
    result.state[100] = byte(initial[100] - 3U);
    result.tables[67] = byte(result.tables[initial[17] & 0x3FU] + tables[67]);
    result.state[101] =
        byte(initial[101] - (byte((((tables[96] ^ 0x73U) & 0x8CU) |
                                   ((file_key_fixed_table[initial[57] & 0x3FU] ^ 0x73U) & 0x73U)) ^
                                  0x30U) /
                             3U));
    const std::uint8_t state_249_lookup = file_key_fixed_table[initial[217] & 0x3FU];
    result.state[249] =
        byte(initial[249] - ((word(initial[7]) >> 1U) | ((state_249_lookup & 0x36U) ^ 6U) |
                             (tables[79] & ((state_249_lookup ^ 0x73U) | 0x36U))));
    result.state[30] = byte(initial[30] ^ 0x58U);
    result.state[215] =
        cube_byte(byte((result.tables[initial[241] & 0x3FU] & 0xC8U) | (tables[64] & 0x37U)));
    const std::uint8_t cubed_bits =
        cube_byte(byte((initial[21] & initial[109]) | ((initial[21] | initial[109]) & 0x73U)));
    result.tables[127] = byte(result.tables[(0U - cubed_bits) & 0x3FU]);
    const std::uint8_t table_62_lookup = result.tables[initial[13] & 0x3FU];
    result.tables[62] = byte(xor_shifts((table_62_lookup & 0x2CU),
                                        (byte(cube_byte(initial[146])) & 7U),
                                        ((0U - byte(cube_byte(initial[146]))) & 7U)));
    const std::uint8_t table_11_shift = result.tables[64U + (initial[220] & 0x3FU)];
    const std::uint8_t majority_bits =
        byte((tables[74] & initial[131]) | (tables[81] & (tables[74] | initial[131])));
    result.tables[11] =
        byte(tables[11] +
             xor_shifts(majority_bits, ((0U - table_11_shift) & 7U), (table_11_shift & 7U)));
    const std::uint8_t state_67_shift = result.tables[64U + (initial[27] & 0x3FU)];
    result.state[67] =
        byte(initial[67] - xor_shifts((word(initial[10]) >> 1U),
                                      ((0U - (word(state_67_shift) * state_67_shift)) & 7U),
                                      (byte(word(state_67_shift) * state_67_shift) & 7U)));
    result.state[195] =
        byte(initial[195] + ((file_key_fixed_table[initial[136] & 0x3FU] & 0xACU) ^ 0x16U));
    const std::uint8_t bias_4_lookup = result.tables[initial[182] & 0x3FU];
    const std::uint8_t table_104_left = result.tables[initial[196] & 0x3FU];
    const std::uint8_t table_104_right = result.tables[64U + (initial[21] & 0x3FU)];
    result.tables[104] = byte(tables[104] + result.tables[64U + (initial[127] & 0x3FU)] -
                              ((table_104_right & table_104_left) |
                               (((table_104_right ^ 0x32U) | (table_104_left ^ 0x32U)) & 0x49U)));
    result.tables[50] = byte(
        ((((initial[140] + 0x40U) & ((result.tables[64U + (initial[65] & 0x3FU)] & 2U) ^ 0x24U)) ^
          0x22U) +
         0x51U) ^
        0x73U);
    result.state[151] = byte(0U);
    result.tables[2] = byte(byte((initial[134] & 0x89U) | 0x74U) / 5U);
    result.tables[11] =
        byte(result.tables[11] + ((((result.tables[initial[39] & 0x3FU] ^ 0x40U) + 0x32U) & 0x32U) |
                                  (byte((word(tables[20]) * 0xABU) >> 9U) & 0x4DU)));
    result.state[237] = byte(initial[237] + (file_key_fixed_table[initial[201] & 0x3FU] ^ 0xB8U));
    const std::uint8_t table_16_lookup = result.tables[(bias_4_lookup + 0x4DU) & 0x3FU];
    const std::uint8_t bias_0_lookup = result.tables[64U + (initial[120] & 0x3FU)];
    result.tables[16] = byte(tables[16] + (((initial[208] + 0x2BU) & (result.tables[8] ^ 0xFFU)) |
                                           (result.tables[8] & (word(table_16_lookup) >> 1U))));
    const std::uint8_t table_75_lookup = result.tables[64U + (initial[162] & 0x3FU)];
    result.tables[75] =
        byte(tables[75] ^ (word(byte((table_75_lookup & 0x7EU) |
                                     ((tables[4] ^ 1U) & ((table_75_lookup ^ 0x73U) | 0x7EU)))) >>
                           1U));
    result.tables[37] = byte((result.tables[initial[65] & 0x3FU] + 0x31U) ^ tables[37] ^ 0x12U);
    result.tables[117] = byte(0U - initial[103] + tables[117]);
    result.state[227] = byte(initial[227] + (0xFEU * result.tables[64U + (initial[173] & 0x3FU)]));
    const std::uint8_t scaled_lookup =
        byte((((file_key_fixed_table[initial[56] & 0x3FU] ^ 0xA1U) * 0xABU) & 0xFE00U) >> 9U);
    result.tables[64] = byte(result.tables[64U + (scaled_lookup & 0x3FU)] ^ tables[64]);
    result.tables[31] = byte(tables[31] + (0U - (word(initial[26]) * initial[26])));
    const std::uint8_t table_39_lookup = result.tables[initial[136] & 0x3FU];
    const std::uint8_t table_39_bits =
        byte((table_39_lookup & tables[66]) | (tables[59] & (table_39_lookup | tables[66])));
    result.tables[39] =
        byte(((word(tables[55]) >> 1U) & table_39_bits) |
             (((word(byte(tables[55] ^ 0x73U)) >> 1U) & 0x3DU) ^ 0x39U) | (table_39_bits & 0xBDU));
    const std::uint8_t shifted_bits =
        byte((initial[92] & (tables[103] ^ 0xFFU)) | (tables[103] & 0x8AU));
    result.tables[76] = byte(tables[76] - xor_shifts(shifted_bits,
                                                     ((initial[155] / 5U) & 7U),
                                                     ((0U - (initial[155] / 5U)) & 7U)));
    result.tables[26] = byte(tables[26] ^ 0xFDU);
    result.tables[24] = byte(tables[24] + (0xD3U * tables[47] * tables[47]));
    const std::uint8_t bias_11_lookup = result.tables[initial[116] & 0x3FU];
    result.state[96] = byte((0xFEU * result.tables[64U + (initial[85] & 0x3FU)]) - 1U);
    const std::uint8_t state_39_bits = byte((word(initial[39]) >> 1U) & 0x33U);
    result.tables[54] = byte(tables[54] ^ (result.tables[(state_39_bits + 0x26U) & 0x3FU] &
                                           (file_key_fixed_table[initial[33] & 0x3FU] ^ 0x47U)));
    const std::uint8_t table_52_left = result.tables[64U + (initial[239] & 0x3FU)];
    const std::uint8_t bias_9_lookup = result.tables[64U + (initial[105] & 0x3FU)];
    const std::uint8_t table_122_bits =
        byte((tables[20] & (tables[35] ^ 0x7FU)) | ((initial[221] + 0x80U) & tables[35]));
    result.tables[122] = byte((((initial[142] & 0x80U) | (table_122_bits & 0x7FU)) -
                               ((word(table_122_bits) * 2U) & 0xE6U) + 0x73U) ^
                              0x73U);
    result.state[44] =
        byte(initial[44] ^ ((result.tables[initial[171] & 0x3FU] / 5U) + initial[24]));
    result.tables[104] =
        byte((((word(initial[137]) >> 1U) & 0x5FU) | ((tables[10] ^ 0x73U) & 0x20U)) ^
             result.tables[104] ^ 0x20U);
    result.tables[25] = byte(tables[25] ^ (word(byte((result.state[67] & 0x4FU) ^ 0x20U)) * 3U));
    result.tables[51] = byte(0xB5U);
    result.tables[100] = byte(tables[100] ^ 0xBDU);
    result.state[188] = byte(
        ((((result.tables[initial[37] & 0x3FU] ^ 0x73U) & 0x5EU) | ((tables[81] ^ 0x73U) & 0xA1U)) ^
         0x7DU) +
        initial[188]);
    const std::uint8_t table_38_lookup = file_key_fixed_table[initial[193] & 0x3FU];
    result.tables[38] =
        byte(tables[38] - (((table_38_lookup ^ 0x47U) & initial[61]) |
                           (tables[84] & ((table_38_lookup ^ 0x47U) | initial[61]))));
    const std::uint8_t table_52_right = result.tables[initial[159] & 0x3FU];
    result.tables[52] =
        byte((((((table_52_left | initial[148]) & 6U) ^ 6U) & (table_52_right ^ 0x71U)) |
              ((table_52_left | initial[148]) & 2U) | ((table_52_right ^ 0x73U) & 0x11U)) ^
             tables[52] ^ 0x31U);
    const std::uint8_t state_39_bias = byte(state_39_bits + 0x66U);
    const std::uint8_t table_28_bits =
        byte((tables[97] & initial[116]) | (tables[30] & (tables[97] | initial[116])));
    const std::uint8_t shifted_bias = byte(word(state_39_bias) >> 1U);
    result.tables[28] =
        byte((shifted_bias & table_28_bits) | (result.tables[2] & (table_28_bits | shifted_bias)));
    const std::uint8_t table_35_lookup = result.tables[64U + (initial[41] & 0x3FU)];
    const std::uint8_t bias_12_lookup = result.tables[64U + (result.state[188] & 0x3FU)];
    const std::uint8_t table_35_bits =
        byte((table_35_lookup & initial[247]) | (tables[96] & (table_35_lookup | initial[247])));
    const std::uint8_t shifted_table =
        byte(xor_shifts(tables[111], (initial[4] & 7U), ((0U - initial[4]) & 7U)));
    result.tables[35] =
        byte(tables[35] + ((table_35_bits & shifted_table) | (result.tables[62] & shifted_table) |
                           (table_35_bits & result.tables[62])));
    const std::uint8_t square_input =
        byte((tables[53] & (tables[123] ^ 0xFFU)) | (tables[123] & 0x23U));
    result.tables[20] = byte(word(square_input) * square_input);
    result.tables[42] = byte(tables[42] + tables[3] - ((tables[125] & 0x25U) ^ 0xAU));

    // Byte biases used to prepare the reduction's sixteen-byte input.
    const std::uint8_t bias_bits =
        byte((bias_0_lookup & tables[81]) | (tables[73] & (bias_0_lookup | tables[81])));
    const std::uint8_t shifted_constant = xor_shifts(0x37U, tables[3] & 7U, (0U - tables[3]) & 7U);
    result.input = reduction_input({
        byte((bias_bits & tables[117]) | (((bias_bits ^ 0x30U) | (tables[117] ^ 0x30U)) & 0x4FU)),
        byte(bias_1_lookup / 5U),
        byte(((initial[125] & 0xC9U) | 2U) ^ ((bias_2_lookup ^ 0xFFU) - 2U)),
        byte(cubed_bits + 0x80U),
        byte(bias_4_lookup + 0x1AU),
        byte(scaled_lookup + 0x6FU),
        byte((((tables[68] & 0x9FU) ^ 0x3EU) & (word(bias_6_lookup) * bias_6_lookup)) ^ 0x4BU),
        byte((shifted_constant & 0x2DU) | ((shifted_constant | 0x2DU) & tables[82])),
        state_39_bias,
        byte(((bias_9_lookup ^ 0x73U) & 0x20U) |
             (((table_52_left | initial[148]) ^ 0x14U) & 0xC6U)),
        byte(file_key_fixed_table[initial[239] & 0x3FU] ^ 0x73U),
        byte(word(byte((initial[69] & 0x55U) ^ 0x22U)) * (bias_11_lookup ^ 0xFFU)),
        byte(bias_12_lookup ^ 0x73U),
    });
    return result;
}
} // namespace apple_auth::detail
