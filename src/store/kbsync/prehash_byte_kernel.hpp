#pragma once
#include "store/data/arithmetic.hpp"
#include "store/data/prehash_maps.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::kbsync::detail {

inline void prehash_byte_kernel(std::array<std::uint8_t, 64>& table,
                                std::array<std::uint8_t, 319>& state,
                                std::array<std::uint8_t, 64>& pad,
                                const std::array<std::uint8_t, 64>& source_pad,
                                std::array<std::uint8_t, 16>& output) {
    // Promote substitutions before arithmetic to preserve unsigned 32-bit operations.
    const auto substitute = [](unsigned index, std::uint32_t value) -> std::uint32_t {
        return prehash_byte_maps[index][value & prehash_kernel_values[0]];
    };

    // Preserve load order: table, pad and source_pad may refer to the same array.
    const std::uint32_t b0 = state[18];
    const std::uint32_t b1 = table[((b0 & prehash_kernel_values[1]) ^ prehash_kernel_values[2])];
    const std::uint32_t b2 = source_pad[57];
    const std::uint32_t b3 = state[25];
    pad[7] =
        static_cast<std::uint8_t>((((b3 >> 1) & prehash_kernel_values[3]) ^
                                   (b2 & prehash_kernel_values[4]) ^ prehash_kernel_values[5]));
    const std::uint32_t b4 = state[138];
    const std::uint32_t b5 = source_pad[3];
    const std::uint32_t mixed0 = substitute(12, (prehash_kernel_values[0] & substitute(47, b1)));
    pad[55] =
        static_cast<std::uint8_t>(((b4 & prehash_kernel_values[6]) ^ prehash_kernel_values[7] ^
                                   (b4 & prehash_kernel_values[8] & substitute(47, b1)) ^
                                   (prehash_kernel_values[9] & mixed0)));
    const std::uint32_t b6 = state[150];
    const std::uint32_t b7 = state[179];
    const std::uint32_t b8 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b7))];
    const std::uint32_t b9 = state[237];
    const std::uint32_t b10 = table[15];
    const std::uint32_t mixed1 = substitute(
        12, (prehash_kernel_values[10] & prehash_word_maps[0][(b6)&prehash_kernel_values[0]]));
    const std::uint32_t mixed2 = substitute(
        0,
        (prehash_kernel_values[11] +
         (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b10)) +
         ((b9 & prehash_kernel_values[13]) ^ (b8 & prehash_kernel_values[14]) ^
          prehash_kernel_values[15] ^ (prehash_kernel_values[16] & mixed1) ^
          (prehash_kernel_values[10] & b9 & prehash_word_maps[0][(b6)&prehash_kernel_values[0]]) ^
          (prehash_kernel_values[10] & b8 & prehash_word_maps[0][(b6)&prehash_kernel_values[0]]))));
    const std::uint32_t mixed3 = (prehash_kernel_values[0] & mixed2);
    table[15] = static_cast<std::uint8_t>(mixed3);
    const std::uint32_t b11 = state[249];
    const std::uint32_t b12 = table[47];
    const std::uint32_t b13 = state[195];
    const std::uint32_t b14 = table[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b13))];
    table[47] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(1,
                    (prehash_kernel_values[17] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b12)) +
                     (prehash_kernel_values[0] & substitute(51, b14))))));
    const std::uint32_t b15 = state[200];
    const std::uint32_t b16 = state[202];
    const std::uint32_t b17 = table[8];
    const std::uint32_t b18 = state[112];
    const std::uint32_t b19 = state[33];
    const std::uint32_t b20 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b19))];
    const std::uint32_t b21 = source_pad[19];
    const std::uint32_t b22 = source_pad[3];
    const std::uint32_t b23 = table[3];
    const std::uint32_t mixed4 =
        ((prehash_kernel_values[18] *
          (prehash_kernel_values[19] ^ (prehash_kernel_values[0] & b23))) >>
         9);
    const std::uint32_t mixed5 =
        ((b21 & mixed4) ^ (b21 & b22) ^ (prehash_kernel_values[20] & b21) ^
         (prehash_kernel_values[21] & b21 & b22 & mixed4) ^ (b22 & prehash_kernel_values[22]) ^
         prehash_kernel_values[23] ^ (prehash_kernel_values[24] & substitute(49, b23)));
    table[0] = static_cast<std::uint8_t>(mixed5);
    const std::uint32_t b24 = table[23];
    const std::uint32_t b25 = state[174];
    table[23] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(2,
                    ((prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b24)) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b25)) +
                     prehash_kernel_values[25]))));
    const std::uint32_t b26 = source_pad[57];
    const std::uint32_t b27 = source_pad[18];
    const std::uint32_t mixed6 =
        (prehash_kernel_values[26] ^ (prehash_kernel_values[27] & substitute(47, b1)));
    const std::uint32_t b28 = pad[mixed6];
    pad[61] = static_cast<std::uint8_t>(
        (prehash_kernel_values[28] +
         ((b27 & prehash_kernel_values[29]) ^ (prehash_kernel_values[30] & b26) ^
          (prehash_kernel_values[30] & b27 & b26) ^ prehash_kernel_values[31])));
    const std::uint32_t b29 = state[167];
    const std::uint32_t b30 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b29))];
    const std::uint32_t b31 = source_pad[24];
    const std::uint32_t b32 = state[20];
    const std::uint32_t b33 = state[234];
    const std::uint32_t b34 = source_pad[43];
    const std::uint32_t b35 = state[128];
    const std::uint32_t b36 = table[43];
    const std::uint32_t mixed7 =
        (prehash_kernel_values[22] ^ (b32 & b33 & b31) ^ (b32 & b33 & b30 & b31) ^
         (b32 & b33 & b34) ^ (b31 & b34) ^ (b30 & b31 & b34) ^ (b30 & prehash_kernel_values[32]) ^
         (b32 & b30 & prehash_kernel_values[33]) ^ (b33 & b30 & prehash_kernel_values[33]) ^
         (b32 & b33 & b30 & prehash_kernel_values[34]) ^ (b31 & prehash_kernel_values[32]) ^
         (prehash_kernel_values[35] & b32 & b31) ^ (prehash_kernel_values[35] & b33 & b31) ^
         (b30 & b31 & prehash_kernel_values[32]) ^ (prehash_kernel_values[35] & b32 & b30 & b31) ^
         (prehash_kernel_values[35] & b33 & b30 & b31) ^ (b34 & prehash_kernel_values[32]) ^
         (prehash_kernel_values[35] & b32 & b34) ^ (prehash_kernel_values[35] & b33 & b34) ^
         (b30 & b34 & prehash_kernel_values[34]));
    const std::uint32_t mixed8 = (prehash_kernel_values[36] + mixed7);
    pad[12] = static_cast<std::uint8_t>(mixed8);
    const std::uint32_t b37 = state[201];
    const std::uint32_t b38 = table[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b37))];
    const std::uint32_t b39 = state[171];
    const std::uint32_t b40 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b39))];
    table[43] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(3,
                    (prehash_kernel_values[37] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b36)) +
                     ((prehash_kernel_values[38] & b40) ^
                      (prehash_kernel_values[0] & substitute(49, b38)))))));
    const std::uint32_t b41 = state[196];
    const std::uint32_t b42 = table[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b41))];
    const std::uint32_t b43 = state[117];
    const std::uint32_t b44 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b43))];
    const std::uint32_t b45 = table[32];
    const std::uint32_t b46 = state[89];
    table[32] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(4,
                    (prehash_kernel_values[14] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b46)) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b45))))));
    const std::uint32_t b47 = source_pad[28];
    const std::uint32_t b48 = state[174];
    const std::uint32_t mixed9 = ((prehash_kernel_values[0] * (prehash_kernel_values[24] ^ b20)) +
                                  (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b18)) +
                                  prehash_kernel_values[39]);
    const std::uint32_t mixed10 =
        (prehash_kernel_values[40] ^ (prehash_kernel_values[41] & b16 & b15) ^
         (prehash_kernel_values[41] & b16 & b17) ^ (prehash_kernel_values[41] & b15 & b17) ^
         (prehash_kernel_values[42] & b16 & b15 & mixed9) ^
         (prehash_kernel_values[42] & b16 & b17 & mixed9) ^
         (prehash_kernel_values[42] & b15 & b17 & mixed9) ^ (prehash_kernel_values[43] & mixed9) ^
         (1u & b16 & b15 & (2u + b18 + b20)) ^ (1u & b16 & b17 & (2u + b18 + b20)) ^
         (1u & b15 & b17 & (2u + b18 + b20)));
    const std::uint32_t b49 = table[mixed10];
    const std::uint32_t b50 = state[70];
    const std::uint32_t mixed11 = ((prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b49)) +
                                   prehash_kernel_values[44]);
    const std::uint32_t mixed12 = (prehash_kernel_values[45] +
                                   (prehash_kernel_values[45] * (prehash_kernel_values[12] ^ b48)));
    const std::uint32_t mixed13 = (mixed12 << 3);
    const std::uint32_t mixed14 =
        (prehash_kernel_values[46] ^ (b47 & mixed11) ^ (prehash_kernel_values[47] & b47 & mixed13) ^
         (prehash_kernel_values[47] & mixed11 & mixed13) ^ (prehash_kernel_values[22] & mixed11) ^
         (prehash_kernel_values[46] & substitute(52, mixed12)));
    const std::uint32_t mixed15 =
        (prehash_kernel_values[48] +
         (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b50)) + mixed14);
    const std::uint32_t mixed16 = substitute(5, mixed15);
    const std::uint32_t mixed17 = (prehash_kernel_values[0] & mixed16);
    state[70] = static_cast<std::uint8_t>(mixed17);
    const std::uint32_t b51 = state[154];
    state[58] = static_cast<std::uint8_t>(
        (prehash_kernel_values[4] ^ (prehash_kernel_values[13] & substitute(23, b51))));
    const std::uint32_t b52 = table[28];
    const std::uint32_t b53 = state[230];
    const std::uint32_t b54 =
        source_pad[(prehash_kernel_values[49] ^ (prehash_kernel_values[50] & b52))];
    state[230] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(6,
                    (prehash_kernel_values[20] + (prehash_kernel_values[24] ^ b54) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b53))))));
    const std::uint32_t b55 = state[38];
    const std::uint32_t b56 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b55))];
    pad[19] = static_cast<std::uint8_t>(b56);
    const std::uint32_t b57 = state[156];
    pad[25] =
        static_cast<std::uint8_t>((prehash_kernel_values[51] + (prehash_kernel_values[12] ^ b57)));
    const std::uint32_t b58 = state[29];
    const std::uint32_t b59 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b58))];
    const std::uint32_t b60 = table[26];
    const std::uint32_t b61 = state[153];
    const std::uint32_t b62 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b61))];
    const std::uint32_t b63 = state[173];
    const std::uint32_t b64 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b63))];
    table[26] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(7,
                    (9u + (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b60)) +
                     (prehash_kernel_values[52] ^ (prehash_kernel_values[13] & b64)) +
                     ((b62 & prehash_kernel_values[53]) ^ prehash_kernel_values[54])))));
    const std::uint32_t b65 = state[240];
    pad[41] =
        static_cast<std::uint8_t>((prehash_kernel_values[55] + ((prehash_kernel_values[12] ^ b65) *
                                                                prehash_kernel_values[55])));
    const std::uint32_t b66 = table[mixed6];
    const std::uint32_t b67 = table[42];
    const std::uint32_t b68 = table[13];
    const std::uint32_t b69 = table[60];
    const std::uint32_t mixed18 = (prehash_kernel_values[45] +
                                   (prehash_kernel_values[45] * (prehash_kernel_values[12] ^ b69)));
    const std::uint32_t mixed19 =
        (prehash_kernel_values[56] + ((b68 & mixed18) ^ (prehash_kernel_values[12] & mixed18)) +
         (prehash_kernel_values[57] * (4u ^
                                       (prehash_kernel_values[58] & (b68 << 1) & (mixed18 << 1)) ^
                                       (4u & substitute(48, mixed18)))));
    const std::uint32_t mixed20 = (b66 & b67 & b68 & mixed19);
    const std::uint32_t mixed21 = (prehash_kernel_values[59] & b66 & mixed19);
    const std::uint32_t mixed22 = (prehash_kernel_values[59] & b67 & mixed19);
    const std::uint32_t mixed23 = (prehash_kernel_values[19] & b66 & b67 & mixed19);
    const std::uint32_t mixed24 = (prehash_kernel_values[19] & b68 & mixed19);
    const std::uint32_t mixed25 = (prehash_kernel_values[60] & b66 & b68 & mixed19);
    const std::uint32_t mixed26 = (prehash_kernel_values[60] & b67 & b68 & mixed19);
    const std::uint32_t mixed27 = substitute(9, mixed19);
    const std::uint32_t mixed28 = (prehash_kernel_values[12] & mixed27);
    const std::uint32_t mixed29 =
        (prehash_kernel_values[12] ^ (prehash_kernel_values[32] & b66) ^
         (prehash_kernel_values[32] & b67) ^ (prehash_kernel_values[61] & b66 & b67) ^
         (prehash_kernel_values[61] & b68) ^ (prehash_kernel_values[32] & b66 & b68) ^
         (prehash_kernel_values[32] & b67 & b68) ^ (b66 & b67 & b68 & prehash_kernel_values[62]) ^
         mixed20 ^ mixed21 ^ mixed22 ^ mixed23 ^ mixed24 ^ mixed25 ^ mixed26 ^ mixed28);
    state[192] = static_cast<std::uint8_t>(mixed29);
    const std::uint32_t b70 = state[184];
    const std::uint32_t b71 = source_pad[38];
    const std::uint32_t b72 = source_pad[24];
    const std::uint32_t b73 =
        source_pad[(prehash_kernel_values[41] ^ (prehash_kernel_values[1] & b72))];
    const std::uint32_t b74 = table[34];
    table[34] = static_cast<std::uint8_t>(
        (prehash_kernel_values[63] ^ b74 ^ (b71 & b70 & b73) ^ (prehash_kernel_values[29] & b71) ^
         (prehash_kernel_values[64] & b70) ^ (prehash_kernel_values[29] & b71 & b70) ^
         (prehash_kernel_values[65] & b71 & b73) ^ (prehash_kernel_values[34] & b70 & b73) ^
         (prehash_kernel_values[66] & b73)));
    pad[33] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(8, b5)));
    const std::uint32_t b75 = table[24];
    const std::uint32_t b76 = table[57];
    const std::uint32_t b77 = state[217];
    const std::uint32_t b78 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b77))];
    pad[32] = static_cast<std::uint8_t>(prehash_kernel_values[67]);
    const std::uint32_t b79 = state[253];
    const std::uint32_t b80 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b79))];
    const std::uint32_t b81 = state[104];
    const std::uint32_t mixed30 =
        ((prehash_kernel_values[68] & b80) ^ (prehash_kernel_values[69] & b76 & b80) ^
         (prehash_kernel_values[70] &
          substitute(12,
                     ((prehash_kernel_values[65] ^ (prehash_kernel_values[0] & b11) ^
                       (prehash_kernel_values[10] &
                        prehash_word_maps[0][(b6)&prehash_kernel_values[0]])) >>
                      (1u ^ (7u & b78))))) ^
         (prehash_kernel_values[70] &
          substitute(12,
                     ((prehash_kernel_values[71] ^ (prehash_kernel_values[0] & b11) ^
                       prehash_word_maps[0][(b6)&prehash_kernel_values[0]])
                      << (7u & (7u * (1u ^ b78)))))));
    const std::uint32_t mixed31 =
        (prehash_kernel_values[69] +
         (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b81)) + mixed30);
    const std::uint32_t mixed32 = substitute(9, mixed31);
    const std::uint32_t mixed33 = (prehash_kernel_values[0] & mixed32);
    state[104] = static_cast<std::uint8_t>(mixed33);
    const std::uint32_t b82 = table[48];
    table[48] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(10, b82)));
    const std::uint32_t b83 = state[163];
    const std::uint32_t b84 = table[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b83))];
    const std::uint32_t mixed34 =
        (prehash_kernel_values[1] &
         (prehash_kernel_values[72] +
          (prehash_kernel_values[1] * (prehash_kernel_values[68] ^ b35))));
    const std::uint32_t b85 = pad[mixed34];
    const std::uint32_t b86 = state[3];
    const std::uint32_t b87 = table[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b86))];
    const std::uint32_t b88 = state[80];
    const std::uint32_t b89 = source_pad[51];
    const std::uint32_t b90 = state[222];
    const std::uint32_t mixed35 =
        ((prehash_kernel_values[19] ^ (b87 & b88) ^ (b87 & b89) ^ (b88 & b89) ^
          (prehash_kernel_values[32] & b87) ^ (prehash_kernel_values[32] & b88)) *
         (8u ^ (prehash_kernel_values[13] & b85) ^ (prehash_kernel_values[14] & b84)));
    const std::uint32_t mixed36 = substitute(48, mixed35);
    const std::uint32_t mixed37 =
        (prehash_kernel_values[73] ^ (prehash_kernel_values[73] & mixed36));
    const std::uint32_t mixed38 = (prehash_kernel_values[0] & substitute(12, mixed35));
    const std::uint32_t mixed39 = (mixed37 + mixed38);
    const std::uint32_t mixed40 = substitute(12, mixed39);
    const std::uint32_t mixed41 = (prehash_kernel_values[21] & mixed40);
    const std::uint32_t mixed42 = (prehash_kernel_values[21] ^ mixed38);
    const std::uint32_t mixed43 = (mixed37 + mixed42);
    const std::uint32_t mixed44 = substitute(12, mixed43);
    const std::uint32_t mixed45 = (prehash_kernel_values[38] & mixed44);
    const std::uint32_t mixed46 =
        (mixed42 + (prehash_kernel_values[74] ^ (prehash_kernel_values[74] & mixed36)));
    const std::uint32_t mixed47 = substitute(12, mixed46);
    const std::uint32_t mixed48 = (prehash_kernel_values[72] & mixed47);
    const std::uint32_t mixed49 =
        ((2u ^ (2u & prehash_word_maps[0][((b85 * (1u ^ (b87 & b88) ^ (b87 & b89) ^ (b88 & b89)))) &
                                          prehash_kernel_values[0]])) +
         (prehash_kernel_values[75] ^ mixed38));
    const std::uint32_t mixed50 = substitute(7, mixed49);
    const std::uint32_t mixed51 = (7u & mixed50);
    const std::uint32_t mixed52 =
        (prehash_kernel_values[27] ^ mixed41 ^ mixed45 ^ mixed48 ^ mixed51);
    const std::uint32_t mixed53 = (prehash_kernel_values[57] * mixed52);
    const std::uint32_t mixed54 =
        (prehash_kernel_values[76] +
         (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b90)) + mixed53);
    const std::uint32_t mixed55 = substitute(11, mixed54);
    const std::uint32_t mixed56 = (prehash_kernel_values[0] & mixed55);
    state[222] = static_cast<std::uint8_t>(mixed56);
    pad[51] = static_cast<std::uint8_t>(prehash_kernel_values[76]);
    pad[7] = static_cast<std::uint8_t>(prehash_kernel_values[51]);
    const std::uint32_t b91 = state[232];
    const std::uint32_t b92 = table[8];
    table[8] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(13,
                    (prehash_kernel_values[77] +
                     (prehash_kernel_values[0] ^ (prehash_kernel_values[7] & b91)) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b92))))));
    const std::uint32_t b93 = state[8];
    const std::uint32_t b94 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b93))];
    const std::uint32_t b95 = state[23];
    const std::uint32_t b96 = state[67];
    const std::uint32_t b97 = table[26];
    table[26] = static_cast<std::uint8_t>(
        (b97 ^ (((b95 & b94) ^ (prehash_kernel_values[78] & b95) ^
                 (prehash_kernel_values[79] & b94) ^ prehash_kernel_values[80]) +
                (prehash_kernel_values[81] ^ (prehash_kernel_values[82] & b44) ^
                 (prehash_kernel_values[33] & b96 & b44) ^ (prehash_kernel_values[83] & b96) ^
                 (prehash_kernel_values[41] & b42) ^ (prehash_kernel_values[11] & b42 & b96)))));
    const std::uint32_t b98 = state[61];
    const std::uint32_t b99 = table[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b98))];
    const std::uint32_t b100 = state[25];
    const std::uint32_t b101 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b100))];
    const std::uint32_t b102 = state[98];
    const std::uint32_t b103 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b102))];
    const std::uint32_t b104 = table[60];
    const std::uint32_t b105 = state[189];
    const std::uint32_t mixed57 =
        (((prehash_kernel_values[84] ^ (b99 & b101) ^ (b103 & b104) ^
           (prehash_kernel_values[19] & b101) ^ (prehash_kernel_values[33] & b104) ^
           (prehash_kernel_values[85] & b103)) +
          prehash_kernel_values[86]) ^
         (prehash_kernel_values[70] &
          substitute(12,
                     (prehash_kernel_values[87] +
                      (prehash_kernel_values[88] ^ (b99 & b101) ^ (b103 & b104) ^
                       (prehash_kernel_values[19] & b101) ^ (prehash_kernel_values[33] & b104) ^
                       (prehash_kernel_values[85] & b103))))) ^
         (prehash_kernel_values[70] &
          substitute(12,
                     (prehash_kernel_values[89] +
                      (prehash_kernel_values[90] ^ (b99 & b101) ^ (b103 & b104) ^
                       (prehash_kernel_values[19] & b101) ^ (prehash_kernel_values[33] & b104) ^
                       (prehash_kernel_values[85] & b103))))));
    const std::uint32_t mixed58 = ((prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b105)) +
                                   prehash_kernel_values[91] + mixed57);
    const std::uint32_t mixed59 = substitute(14, mixed58);
    const std::uint32_t mixed60 = (prehash_kernel_values[0] & mixed59);
    state[189] = static_cast<std::uint8_t>(mixed60);
    const std::uint32_t b106 = state[55];
    const std::uint32_t b107 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b106))];
    const std::uint32_t b108 = table[62];
    const std::uint32_t mixed61 =
        (b104 ^ (prehash_kernel_values[0] +
                 (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b107))));
    const std::uint32_t mixed62 = (prehash_kernel_values[9] + (mixed61 * mixed61) +
                                   (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b108)));
    const std::uint32_t mixed63 = substitute(48, mixed62);
    const std::uint32_t mixed64 = substitute(50, mixed62);
    const std::uint32_t mixed65 = (prehash_kernel_values[0] & mixed64);
    const std::uint32_t mixed66 =
        ((prehash_kernel_values[12] ^ b108) + (prehash_kernel_values[57] * mixed61 * mixed61) +
         prehash_kernel_values[92]);
    const std::uint32_t mixed67 = substitute(54, mixed62);
    const std::uint32_t mixed68 = (b104 ^ (1u + (3u * b107)));
    const std::uint32_t mixed69 = (b108 + (prehash_kernel_values[57] * mixed68 * mixed68));
    const std::uint32_t mixed70 = substitute(52, mixed62);
    const std::uint32_t mixed71 = ((prehash_kernel_values[0] & substitute(55, mixed62)) |
                                   (prehash_kernel_values[0] & mixed67) |
                                   (prehash_kernel_values[0] & substitute(56, mixed69)) |
                                   (prehash_kernel_values[0] & mixed70));
    const std::uint32_t mixed72 = (prehash_kernel_values[57] ^ mixed71);
    const std::uint32_t mixed73 = (mixed65 | mixed72);
    const std::uint32_t mixed74 =
        (mixed65 ^ (prehash_kernel_values[0] & substitute(50, mixed66)) ^ mixed73);
    const std::uint32_t mixed75 = ((prehash_kernel_values[0] & mixed63) | mixed74);
    const std::uint32_t mixed76 = (mixed62 ^ mixed75);
    const std::uint32_t mixed77 = (prehash_kernel_values[21] & mixed76);
    const std::uint32_t mixed78 = (prehash_kernel_values[93] & mixed63);
    const std::uint32_t mixed79 = (prehash_kernel_values[93] ^ mixed78);
    const std::uint32_t mixed80 =
        (prehash_kernel_values[69] ^ (prehash_kernel_values[94] & mixed67));
    const std::uint32_t mixed81 = (7u ^ (prehash_kernel_values[95] & mixed70));
    const std::uint32_t mixed82 =
        (prehash_kernel_values[96] ^ (prehash_kernel_values[97] & mixed64));
    const std::uint32_t mixed83 =
        (mixed80 | mixed81 | mixed82 |
         (prehash_kernel_values[46] ^ (prehash_kernel_values[46] & substitute(55, mixed69))));
    const std::uint32_t mixed84 = (prehash_kernel_values[57] ^ mixed83);
    const std::uint32_t mixed85 = (mixed79 | mixed84);
    const std::uint32_t mixed86 =
        (mixed62 ^ mixed78 ^ (prehash_kernel_values[93] & substitute(48, mixed66)) ^ mixed85);
    const std::uint32_t mixed87 = (prehash_kernel_values[38] & mixed86);
    const std::uint32_t mixed88 = (prehash_kernel_values[42] & mixed63);
    const std::uint32_t mixed89 = (prehash_kernel_values[42] ^ mixed88);
    const std::uint32_t mixed90 = (prehash_kernel_values[72] & mixed70);
    const std::uint32_t mixed91 = (prehash_kernel_values[72] ^ mixed90);
    const std::uint32_t mixed92 =
        (prehash_kernel_values[98] ^ (prehash_kernel_values[98] & substitute(54, mixed69)));
    const std::uint32_t mixed93 =
        (prehash_kernel_values[99] & mixed64 & mixed89 & mixed91 & mixed92);
    const std::uint32_t mixed94 = (prehash_kernel_values[0] & substitute(58, mixed62));
    const std::uint32_t mixed95 =
        (prehash_kernel_values[24] ^ (prehash_kernel_values[24] & mixed63));
    const std::uint32_t mixed96 =
        (prehash_kernel_values[14] ^ (prehash_kernel_values[14] & substitute(52, mixed69)));
    const std::uint32_t mixed97 = (prehash_kernel_values[4] & mixed64 & mixed95 & mixed96);
    const std::uint32_t mixed98 = (8u & mixed63);
    const std::uint32_t mixed99 =
        (prehash_kernel_values[100] ^ (prehash_kernel_values[100] & mixed63));
    const std::uint32_t mixed100 = substitute(50, mixed69);
    const std::uint32_t mixed101 = (8u & mixed99 & mixed100);
    const std::uint32_t mixed102 = substitute(48, mixed69);
    const std::uint32_t mixed103 = (4u & mixed102);
    const std::uint32_t mixed104 = (prehash_kernel_values[101] ^ mixed77 ^ mixed87 ^
                                    (prehash_kernel_values[0] & substitute(57, mixed62)) ^ mixed93 ^
                                    (prehash_kernel_values[1] & substitute(12, mixed62)) ^ mixed94 ^
                                    mixed97 ^ mixed98 ^ mixed101 ^ mixed103);
    table[62] = static_cast<std::uint8_t>(mixed104);
    const std::uint32_t b109 = state[218];
    const std::uint32_t b110 = state[202];
    const std::uint32_t b111 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b110))];
    const std::uint32_t b112 = source_pad[substitute(53, b109)];
    pad[48] = static_cast<std::uint8_t>(
        ((prehash_kernel_values[57] * ((prehash_kernel_values[44] & b111) ^ (6u & b112))) +
         prehash_kernel_values[102]));
    const std::uint32_t b113 = state[22];
    const std::uint32_t b114 = state[87];
    state[22] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(15,
                    ((prehash_kernel_values[12] ^ b114) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b113)) +
                     prehash_kernel_values[103]))));
    const std::uint32_t b115 = state[200];
    const std::uint32_t b116 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b115))];
    const std::uint32_t b117 = state[76];
    const std::uint32_t mixed105 = (prehash_kernel_values[104] ^ mixed78 ^ mixed83);
    const std::uint32_t mixed106 = ((prehash_kernel_values[57] ^ b116) | mixed105);
    const std::uint32_t mixed107 = (prehash_kernel_values[38] & mixed106);
    const std::uint32_t mixed108 = (prehash_kernel_values[105] & b116 & mixed99);
    const std::uint32_t mixed109 = (prehash_kernel_values[38] ^ mixed98 ^ (8u & mixed100) ^
                                    (8u & b116 & mixed100) ^ mixed107 ^ mixed108);
    const std::uint32_t mixed110 = (prehash_kernel_values[57] * mixed109);
    const std::uint32_t mixed111 = (8u & (b116 >> 1) & mixed99);
    const std::uint32_t mixed112 = (8u & (b116 >> 1) & mixed99 & mixed100);
    const std::uint32_t mixed113 = (prehash_kernel_values[4] & (b116 >> 1) & mixed64 & mixed95);
    const std::uint32_t mixed114 =
        (prehash_kernel_values[4] & (b116 >> 1) & mixed64 & mixed95 & mixed96);
    const std::uint32_t mixed115 = (1u ^ mixed88);
    const std::uint32_t mixed116 = (7u ^ mixed90);
    const std::uint32_t mixed117 =
        (prehash_kernel_values[1] ^ (prehash_kernel_values[26] & mixed64));
    const std::uint32_t mixed118 = (mixed92 | mixed115 | mixed116 | mixed117);
    const std::uint32_t mixed119 = (prehash_kernel_values[57] ^ mixed62 ^ mixed118);
    const std::uint32_t mixed120 = ((prehash_kernel_values[57] ^ (b116 >> 1)) | mixed119);
    const std::uint32_t mixed121 = (prehash_kernel_values[99] & mixed120);
    const std::uint32_t mixed122 = ((prehash_kernel_values[57] ^ (b116 >> 1)) | mixed86);
    const std::uint32_t mixed123 = (prehash_kernel_values[38] & mixed122);
    const std::uint32_t mixed124 =
        (prehash_kernel_values[106] ^ (prehash_kernel_values[12] & (b116 >> 1)) ^
         (prehash_kernel_values[107] & mixed62 & (b116 >> 1)) ^ mixed94 ^ mixed97 ^ mixed103 ^
         (4u & (b116 >> 1) & (6u ^ (6u & mixed102))) ^ mixed111 ^ mixed112 ^
         (prehash_kernel_values[85] & substitute(9, mixed62)) ^ mixed113 ^ mixed114 ^ mixed121 ^
         mixed123);
    const std::uint32_t mixed125 = (prehash_kernel_values[108] + mixed110 + mixed124);
    const std::uint32_t mixed126 = (prehash_kernel_values[108] ^ b117 ^ mixed125);
    state[76] = static_cast<std::uint8_t>(mixed126);
    const std::uint32_t b118 = table[37];
    const std::uint32_t b119 =
        pad[(prehash_kernel_values[1] & (prehash_kernel_values[109] + (3u * b28 * b28)))];
    table[37] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(16,
                    (prehash_kernel_values[11] + (prehash_kernel_values[0] * b119) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b118))))));
    const std::uint32_t b120 = source_pad[20];
    const std::uint32_t b121 = state[75];
    const std::uint32_t b122 = source_pad[57];
    const std::uint32_t b123 = state[253];
    const std::uint32_t mixed127 =
        (prehash_kernel_values[110] ^
         (prehash_kernel_values[45] &
          substitute(12,
                     (prehash_kernel_values[111] + (prehash_kernel_values[30] ^ (b120 & b121) ^
                                                    (prehash_kernel_values[65] & b120) ^
                                                    (prehash_kernel_values[112] & (b122 << 1)) ^
                                                    (prehash_kernel_values[22] & b121))))) ^
         (prehash_kernel_values[113] &
          substitute(12,
                     (prehash_kernel_values[114] + (prehash_kernel_values[51] ^ (b120 & b121) ^
                                                    (prehash_kernel_values[65] & b120) ^
                                                    (prehash_kernel_values[112] & (b122 << 1)) ^
                                                    (prehash_kernel_values[22] & b121))))) ^
         (prehash_kernel_values[112] &
          substitute(12,
                     (prehash_kernel_values[55] + (prehash_kernel_values[115] ^ (b120 & b121) ^
                                                   (prehash_kernel_values[65] & b120) ^
                                                   (prehash_kernel_values[112] & (b122 << 1)) ^
                                                   (prehash_kernel_values[22] & b121))))));
    const std::uint32_t mixed128 =
        (4u + (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b123)) + mixed127);
    const std::uint32_t mixed129 = substitute(17, mixed128);
    const std::uint32_t mixed130 = (prehash_kernel_values[0] & mixed129);
    state[253] = static_cast<std::uint8_t>(mixed130);
    const std::uint32_t b124 = state[148];
    table[23] = static_cast<std::uint8_t>(b124);
    const std::uint32_t b125 = state[168];
    const std::uint32_t b126 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b125))];
    const std::uint32_t b127 = state[161];
    const std::uint32_t b128 = state[252];
    const std::uint32_t b129 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b128))];
    const std::uint32_t b130 = source_pad[3];
    const std::uint32_t b131 = table[50];
    const std::uint32_t mixed131 = (mixed8 & b127);
    const std::uint32_t mixed132 = (mixed8 & b126);
    const std::uint32_t mixed133 = substitute(12, mixed8);
    const std::uint32_t mixed134 = (prehash_kernel_values[32] & mixed133);
    const std::uint32_t mixed135 =
        (prehash_kernel_values[116] ^ mixed131 ^ mixed132 ^ (b127 & b126) ^
         (prehash_kernel_values[19] & b126) ^ (prehash_kernel_values[22] & b127) ^ mixed134);
    const std::uint32_t mixed136 = (prehash_kernel_values[57] * mixed135);
    const std::uint32_t mixed137 =
        ((prehash_kernel_values[34] ^ (prehash_kernel_values[117] & b129) ^
          (prehash_kernel_values[118] & b130)) +
         mixed136);
    const std::uint32_t mixed138 = (b131 ^ mixed137);
    table[50] = static_cast<std::uint8_t>(mixed138);
    const std::uint32_t b132 = source_pad[24];
    const std::uint32_t b133 = table[57];
    const std::uint32_t b134 = state[236];
    const std::uint32_t b135 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b134))];
    table[57] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(2,
                    (prehash_kernel_values[119] + (prehash_kernel_values[24] ^ b135) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b133))))));
    const std::uint32_t b136 = state[41];
    const std::uint32_t b137 = state[235];
    const std::uint32_t b138 = source_pad[28];
    const std::uint32_t mixed139 =
        ((prehash_kernel_values[90] * (prehash_kernel_values[12] ^ b136)) +
         ((prehash_kernel_values[9] +
           (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b137))) *
          (prehash_kernel_values[0] +
           (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b136)))) +
         prehash_kernel_values[120]);
    const std::uint32_t mixed140 =
        (prehash_kernel_values[21] &
         (b138 ^ (b138 | (prehash_kernel_values[0] & substitute(18, mixed139)))));
    const std::uint32_t mixed141 = substitute(50, mixed139);
    const std::uint32_t mixed142 = substitute(48, mixed139);
    const std::uint32_t mixed143 =
        (prehash_kernel_values[93] ^ (prehash_kernel_values[93] & mixed142));
    const std::uint32_t mixed144 =
        (prehash_kernel_values[94] ^ (prehash_kernel_values[94] & substitute(54, mixed139)));
    const std::uint32_t mixed145 =
        (prehash_kernel_values[38] & b138 & mixed141 & mixed143 & mixed144);
    const std::uint32_t mixed146 = substitute(52, mixed139);
    const std::uint32_t mixed147 =
        (prehash_kernel_values[95] ^ (prehash_kernel_values[95] & mixed146));
    const std::uint32_t mixed148 =
        (prehash_kernel_values[46] & b138 & mixed141 & mixed143 & mixed147);
    const std::uint32_t mixed149 =
        (prehash_kernel_values[38] & b138 & mixed141 & mixed143 & mixed144 & mixed147);
    const std::uint32_t mixed150 =
        (prehash_kernel_values[42] ^ (prehash_kernel_values[42] & mixed142));
    const std::uint32_t mixed151 =
        (prehash_kernel_values[99] & b138 &
         (prehash_kernel_values[72] ^ (prehash_kernel_values[72] & mixed146)) & mixed150);
    const std::uint32_t mixed152 = (prehash_kernel_values[98] & b138 & mixed141 & mixed150);
    const std::uint32_t mixed153 =
        (prehash_kernel_values[16] ^ (prehash_kernel_values[121] & b138) ^
         (prehash_kernel_values[96] & b138 & mixed139) ^ mixed140 ^ mixed145 ^ mixed148 ^ mixed149 ^
         mixed151 ^ mixed152 ^ (prehash_kernel_values[4] & mixed141) ^
         (prehash_kernel_values[4] & b138 & mixed141) ^ (prehash_kernel_values[14] & mixed142) ^
         (prehash_kernel_values[14] & b138 &
          (prehash_kernel_values[24] ^ (prehash_kernel_values[24] & mixed142))) ^
         (prehash_kernel_values[0] & substitute(58, mixed139)) ^
         (prehash_kernel_values[24] & substitute(9, mixed139)));
    pad[18] = static_cast<std::uint8_t>(mixed153);
    const std::uint32_t b139 = state[30];
    pad[10] = static_cast<std::uint8_t>(
        (prehash_kernel_values[122] + (prehash_kernel_values[12] ^ b139)));
    const std::uint32_t b140 = table[18];
    const std::uint32_t b141 = state[116];
    const std::uint32_t b142 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b141))];
    table[18] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(19,
                    (prehash_kernel_values[5] + (prehash_kernel_values[0] * b142) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b140))))));
    const std::uint32_t b143 = source_pad[57];
    const std::uint32_t b144 = table[mixed34];
    const std::uint32_t b145 = table[49];
    const std::uint32_t b146 = table[45];
    const std::uint32_t b147 = state[39];
    const std::uint32_t b148 =
        table[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b147))];
    const std::uint32_t b149 = state[78];
    const std::uint32_t mixed154 =
        (prehash_kernel_values[123] ^ (prehash_kernel_values[38] & (b148 << 1) & (b146 << 1)) ^
         (prehash_kernel_values[123] & (b145 << 1)) ^
         (prehash_kernel_values[48] & (b146 << 1) & (b145 << 1)) ^
         (prehash_kernel_values[123] & (b144 << 1)) ^
         (prehash_kernel_values[123] & (b146 << 1) & (b144 << 1)) ^
         (prehash_kernel_values[123] & (b145 << 1) & (b144 << 1)) ^
         (prehash_kernel_values[48] & (b146 << 1) & (b145 << 1) & (b144 << 1)) ^
         (prehash_kernel_values[85] & (b146 << 1)));
    const std::uint32_t mixed155 = (prehash_kernel_values[57] * mixed154);
    const std::uint32_t mixed156 =
        (prehash_kernel_values[124] + mixed155 +
         (prehash_kernel_values[19] ^ (b146 & b145 & b144) ^
          (prehash_kernel_values[125] & b148 & b146) ^ (prehash_kernel_values[126] & b145) ^
          (prehash_kernel_values[127] & b146 & b145) ^ (prehash_kernel_values[19] & b144) ^
          (prehash_kernel_values[19] & b146 & b144) ^ (prehash_kernel_values[19] & b145 & b144) ^
          (prehash_kernel_values[4] & b148) ^ (prehash_kernel_values[100] & b146)));
    const std::uint32_t mixed157 = substitute(12, mixed156);
    const std::uint32_t mixed158 = (prehash_kernel_values[112] & mixed157);
    const std::uint32_t mixed159 =
        (prehash_kernel_values[128] ^ (1u & b148 & b146) ^ (1u & b144) ^ (1u & b146 & b144) ^
         (1u & b145 & b144) ^ (1u & b146 & b145 & b144) ^ mixed158);
    const std::uint32_t mixed160 = (prehash_kernel_values[118] + mixed159);
    const std::uint32_t mixed161 = substitute(12, mixed160);
    const std::uint32_t mixed162 = (prehash_kernel_values[45] & mixed161);
    const std::uint32_t mixed163 = (prehash_kernel_values[0] & mixed157);
    const std::uint32_t mixed164 = (prehash_kernel_values[2] ^ mixed163);
    const std::uint32_t mixed165 = (prehash_kernel_values[17] + mixed164);
    const std::uint32_t mixed166 = substitute(12, mixed165);
    const std::uint32_t mixed167 = (prehash_kernel_values[112] & mixed166);
    const std::uint32_t mixed168 = (prehash_kernel_values[92] ^ mixed163);
    const std::uint32_t mixed169 = (prehash_kernel_values[129] + mixed168);
    const std::uint32_t mixed170 = substitute(12, mixed169);
    const std::uint32_t mixed171 = (prehash_kernel_values[113] & mixed170);
    const std::uint32_t mixed172 = (prehash_kernel_values[110] ^ mixed162 ^ mixed167 ^ mixed171);
    const std::uint32_t mixed173 =
        ((prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b149)) +
         prehash_kernel_values[130] + mixed172);
    const std::uint32_t mixed174 = substitute(20, mixed173);
    const std::uint32_t mixed175 = (prehash_kernel_values[0] & mixed174);
    state[78] = static_cast<std::uint8_t>(mixed175);
    const std::uint32_t b150 = table[34];
    const std::uint32_t b151 = state[36];
    const std::uint32_t b152 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b150 & b151) ^
                    (prehash_kernel_values[111] & b150) ^ (prehash_kernel_values[111] & b151))];
    const std::uint32_t b153 = state[160];
    state[160] = static_cast<std::uint8_t>((prehash_kernel_values[22] ^ b152 ^ b153));
    const std::uint32_t b154 = state[103];
    state[103] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(21,
                    (prehash_kernel_values[94] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b154))))));
    const std::uint32_t b155 = table[57];
    const std::uint32_t b156 = state[211];
    const std::uint32_t b157 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b156))];
    pad[23] = static_cast<std::uint8_t>(
        (prehash_kernel_values[131] ^ b157 ^
         (b157 & ((prehash_kernel_values[18] *
                   (prehash_kernel_values[19] ^ (prehash_kernel_values[0] & b155))) >>
                  9)) ^
         (prehash_kernel_values[24] & substitute(49, b155))));
    const std::uint32_t b158 = state[185];
    const std::uint32_t b159 =
        source_pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b158))];
    const std::uint32_t b160 = source_pad[38];
    const std::uint32_t b161 = state[120];
    const std::uint32_t b162 = pad[(prehash_kernel_values[2] ^ (prehash_kernel_values[1] & b161))];
    const std::uint32_t b163 = state[130];
    const std::uint32_t b164 = table[28];
    table[28] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(4,
                    (prehash_kernel_values[132] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b164))))));
    // Seed the digest, then apply the two recovered output passes.
    output.fill(static_cast<std::uint8_t>(prehash_kernel_values[18]));
    const std::uint32_t b165 = output[0];
    output[0] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(22,
                    (prehash_kernel_values[95] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b165)) +
                     (b11 ^ prehash_kernel_values[133] ^ (prehash_kernel_values[112] & mixed1))))));
    const std::uint32_t b166 = output[1];
    output[1] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(23, b166)));
    const std::uint32_t b167 = output[2];
    output[2] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(23, b167)));
    const std::uint32_t b168 = output[3];
    output[3] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(24,
                    ((prehash_kernel_values[12] ^ b35) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b168)) +
                     prehash_kernel_values[134]))));
    const std::uint32_t b169 = output[4];
    output[4] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(23, b169)));
    const std::uint32_t b170 = output[5];
    const std::uint32_t mixed176 =
        (prehash_kernel_values[110] ^
         (prehash_kernel_values[45] &
          substitute(12,
                     (prehash_kernel_values[43] + (prehash_kernel_values[135] ^
                                                   (prehash_kernel_values[33] & b44) ^
                                                   (prehash_kernel_values[11] & b42))))) ^
         (prehash_kernel_values[113] &
          substitute(12,
                     (prehash_kernel_values[136] + (prehash_kernel_values[116] ^
                                                    (prehash_kernel_values[33] & b44) ^
                                                    (prehash_kernel_values[11] & b42))))) ^
         (prehash_kernel_values[112] &
          substitute(12,
                     (prehash_kernel_values[22] + (prehash_kernel_values[49] ^
                                                   (prehash_kernel_values[33] & b44) ^
                                                   (prehash_kernel_values[11] & b42))))));
    const std::uint32_t mixed177 =
        (prehash_kernel_values[137] +
         (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b170)) + mixed176);
    const std::uint32_t mixed178 = substitute(25, mixed177);
    const std::uint32_t mixed179 = (prehash_kernel_values[0] & mixed178);
    output[5] = static_cast<std::uint8_t>(mixed179);
    const std::uint32_t b171 = output[6];
    output[6] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(26,
                    (prehash_kernel_values[90] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b171))))));
    const std::uint32_t b172 = output[7];
    output[7] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(23, b172)));
    const std::uint32_t b173 = output[8];
    output[8] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(27, b173)));
    const std::uint32_t b174 = output[9];
    output[9] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(28,
                    (prehash_kernel_values[138] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b174))))));
    const std::uint32_t b175 = output[10];
    output[10] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(29,
                    (prehash_kernel_values[10] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b175))))));
    const std::uint32_t b176 = output[11];
    output[11] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(30,
                    (prehash_kernel_values[139] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b176)) +
                     (prehash_kernel_values[0] & substitute(31, b109))))));
    const std::uint32_t b177 = output[12];
    output[12] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(32,
                    (prehash_kernel_values[100] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b177))))));
    const std::uint32_t b178 = output[13];
    output[13] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(33,
                    (prehash_kernel_values[109] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b178))))));
    const std::uint32_t b179 = output[14];
    output[14] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(27, b179)));
    const std::uint32_t b180 = output[15];
    output[15] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(22,
                    (prehash_kernel_values[43] + (3u * b28 * b28) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b180))))));
    // Final output pass.
    const std::uint32_t b181 = output[0];
    output[0] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(29,
                    (prehash_kernel_values[140] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b181)) +
                     (prehash_kernel_values[0] & substitute(34, b143))))));
    const std::uint32_t b182 = output[1];
    const std::uint32_t mixed180 = substitute(48, mixed9);
    const std::uint32_t mixed181 =
        (prehash_kernel_values[112] ^ (prehash_kernel_values[112] & mixed180));
    const std::uint32_t mixed182 =
        (prehash_kernel_values[128] ^ (prehash_kernel_values[33] & mixed180) ^
         (prehash_kernel_values[141] & (b16 << 1) & (b15 << 1) & mixed181) ^
         (prehash_kernel_values[141] & (b16 << 1) & (b17 << 1) & mixed181) ^
         (prehash_kernel_values[141] & (b15 << 1) & (b17 << 1) & mixed181));
    const std::uint32_t mixed183 = (prehash_kernel_values[57] * mixed182);
    const std::uint32_t mixed184 =
        (prehash_kernel_values[127] ^ (b16 & b15 & mixed9) ^ (b16 & b17 & mixed9) ^
         (b15 & b17 & mixed9) ^ (b16 & b15 & prehash_kernel_values[80]) ^
         (b16 & b17 & prehash_kernel_values[80]) ^ (b15 & b17 & prehash_kernel_values[80]) ^
         (prehash_kernel_values[135] & substitute(12, mixed9)));
    const std::uint32_t mixed185 = (prehash_kernel_values[142] + mixed183 + mixed184);
    const std::uint32_t mixed186 = substitute(12, mixed185);
    const std::uint32_t mixed187 = (prehash_kernel_values[0] & mixed186);
    const std::uint32_t mixed188 = (prehash_kernel_values[68] ^ mixed187);
    const std::uint32_t mixed189 = (prehash_kernel_values[135] + mixed188);
    const std::uint32_t mixed190 = (prehash_kernel_values[112] & mixed186);
    const std::uint32_t mixed191 =
        ((1u & b16 & b15 & (2u + b18 + b20)) ^ (1u & b16 & b17 & (2u + b18 + b20)) ^
         (1u & b15 & b17 & (2u + b18 + b20)) ^ prehash_kernel_values[143] ^ (1u & b16 & b15) ^
         (1u & b16 & b17) ^ (1u & b15 & b17) ^ mixed190);
    const std::uint32_t mixed192 = (prehash_kernel_values[144] + mixed191);
    const std::uint32_t mixed193 = substitute(12, mixed192);
    const std::uint32_t mixed194 = (prehash_kernel_values[113] & mixed193);
    const std::uint32_t mixed195 = (prehash_kernel_values[60] ^ mixed187);
    const std::uint32_t mixed196 = (prehash_kernel_values[145] + mixed195);
    const std::uint32_t mixed197 = substitute(12, mixed196);
    const std::uint32_t mixed198 = (prehash_kernel_values[113] & mixed197);
    const std::uint32_t mixed199 = (mixed189 ^ mixed194 ^ mixed198);
    const std::uint32_t mixed200 =
        (prehash_kernel_values[146] +
         (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b182)) + mixed199);
    const std::uint32_t mixed201 = substitute(35, mixed200);
    const std::uint32_t mixed202 = (prehash_kernel_values[0] & mixed201);
    output[1] = static_cast<std::uint8_t>(mixed202);
    const std::uint32_t b183 = output[2];
    output[2] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(36,
                    (prehash_kernel_values[147] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b183))))));
    const std::uint32_t b184 = output[3];
    output[3] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(
             37,
             (prehash_kernel_values[12] +
              (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b184)) +
              (prehash_kernel_values[0] & substitute(38, b59)) +
              (substitute(59, b59) ? prehash_kernel_values[148] : prehash_kernel_values[149])))));
    const std::uint32_t b185 = output[4];
    output[4] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(39,
                    (prehash_kernel_values[21] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b185))))));
    const std::uint32_t b186 = output[5];
    output[5] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(15,
                    (prehash_kernel_values[46] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b186))))));
    const std::uint32_t b187 = output[6];
    output[6] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(40, b187)));
    const std::uint32_t b188 = output[7];
    output[7] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(40, b188)));
    const std::uint32_t b189 = output[8];
    output[8] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(41, b189)));
    const std::uint32_t b190 = output[9];
    output[9] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(42,
                    (prehash_kernel_values[74] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b190)) +
                     (prehash_kernel_values[0] & substitute(43, b132))))));
    const std::uint32_t b191 = output[10];
    const std::uint32_t mixed203 =
        (prehash_kernel_values[150] >>
         (1u ^ (6u & b162) ^ (7u & b162 & b160) ^ (7u & b160 & b159) ^ (1u & b160) ^ (1u & b159)));
    const std::uint32_t mixed204 =
        ((4u & (prehash_kernel_values[57] *
                (1u ^ (b162 & b160) ^ (b160 & b159) ^ (6u & b162) ^ (1u & b160) ^ (1u & b159)))) ^
         (2u & (prehash_kernel_values[57] *
                (1u ^ (b162 & b160) ^ (b160 & b159) ^ (1u & b160) ^ (1u & b159) ^ (2u & b162)))) ^
         (1u & (1u ^ b160 ^ b159 ^ (b162 & b160) ^ (b160 & b159))));
    const std::uint32_t mixed205 = (prehash_kernel_values[151] << mixed204);
    const std::uint32_t mixed206 = (prehash_kernel_values[36] ^ mixed203 ^ mixed205);
    const std::uint32_t mixed207 = (prehash_kernel_values[152] + mixed206);
    const std::uint32_t mixed208 = substitute(12, mixed207);
    const std::uint32_t mixed209 = (prehash_kernel_values[45] & mixed208);
    const std::uint32_t mixed210 = (prehash_kernel_values[153] ^ mixed203 ^ mixed205);
    const std::uint32_t mixed211 = (prehash_kernel_values[154] + mixed210);
    const std::uint32_t mixed212 = substitute(12, mixed211);
    const std::uint32_t mixed213 = (prehash_kernel_values[113] & mixed212);
    const std::uint32_t mixed214 = (prehash_kernel_values[92] ^ mixed203 ^ mixed205);
    const std::uint32_t mixed215 = (prehash_kernel_values[155] + mixed214);
    const std::uint32_t mixed216 = substitute(12, mixed215);
    const std::uint32_t mixed217 = (prehash_kernel_values[112] & mixed216);
    const std::uint32_t mixed218 = (prehash_kernel_values[110] ^ mixed209 ^ mixed213 ^ mixed217);
    const std::uint32_t mixed219 = (prehash_kernel_values[57] * mixed218);
    const std::uint32_t mixed220 =
        (prehash_kernel_values[156] +
         (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b191)) + mixed219);
    const std::uint32_t mixed221 = substitute(44, mixed220);
    const std::uint32_t mixed222 = (prehash_kernel_values[0] & mixed221);
    output[10] = static_cast<std::uint8_t>(mixed222);
    const std::uint32_t b192 = output[11];
    output[11] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(45,
                    (prehash_kernel_values[46] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b192))))));
    const std::uint32_t b193 = output[12];
    output[12] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(5,
                    (prehash_kernel_values[30] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b193))))));
    const std::uint32_t b194 = output[13];
    output[13] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(20,
                    (prehash_kernel_values[157] +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b194)) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b163))))));
    const std::uint32_t b195 = output[14];
    output[14] = static_cast<std::uint8_t>((prehash_kernel_values[0] & substitute(41, b195)));
    const std::uint32_t b196 = output[15];
    output[15] = static_cast<std::uint8_t>(
        (prehash_kernel_values[0] &
         substitute(46,
                    (prehash_kernel_values[158] +
                     (prehash_kernel_values[159] ^ (prehash_kernel_values[14] & b75) ^
                      (prehash_kernel_values[13] & b76)) +
                     (prehash_kernel_values[0] * (prehash_kernel_values[12] ^ b196)) +
                     (prehash_kernel_values[63] ^ (prehash_kernel_values[0] & mixed0))))));
}

} // namespace apple_auth::detail::kbsync::detail
