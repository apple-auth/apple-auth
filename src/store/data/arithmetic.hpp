#pragma once
#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::kbsync {
inline const auto feedback_values = data_mask::decode(std::array<std::uint32_t, 13>{0x54D355C9U,
                                                                                    0x2D9E7CAAU,
                                                                                    0x9A41A296U,
                                                                                    0xE3FED667U,
                                                                                    0x4D9EF319U,
                                                                                    0xECD12178U,
                                                                                    0x391848E2U,
                                                                                    0x6C37B08AU,
                                                                                    0x2A108BEAU,
                                                                                    0x582BD938U,
                                                                                    0xD41C3681U,
                                                                                    0xB71886FBU,
                                                                                    0x4CDD0E38U},
                                                      0x01121923U);
inline const auto fresh_values =
    data_mask::decode(std::array<std::uint32_t, 1>{0x42D994F4U}, 0x3508F3D2U);
inline const auto mac_values =
    data_mask::decode(std::array<std::uint32_t, 2>{0x48FBF0DDU, 0xEA37F8C4U}, 0x0D3AADCAU);
inline const auto packet_values =
    data_mask::decode(std::array<std::uint32_t, 1>{0xA6DEC04DU}, 0x8C05028AU);
inline const auto prehash_values = data_mask::decode(std::array<std::uint32_t, 16>{0xE62D9267U,
                                                                                   0xDA520390U,
                                                                                   0xDD80221EU,
                                                                                   0xE1C5F257U,
                                                                                   0xAD221445U,
                                                                                   0x1A473402U,
                                                                                   0x65D9C91FU,
                                                                                   0xC2A64374U,
                                                                                   0x530AE257U,
                                                                                   0xE492C422U,
                                                                                   0x3FE0B652U,
                                                                                   0x0EB86DDDU,
                                                                                   0x60FABA56U,
                                                                                   0xC0B8382FU,
                                                                                   0x330A1C7FU,
                                                                                   0x60A9C7F4U},
                                                     0xD431663EU);
inline const auto prehash_kernel_values = data_mask::decode(
    std::array<std::uint32_t, 160>{
        0x0D35E6C6U, 0x8FA146FFU, 0x485BBAD1U, 0xDF808AFDU, 0x14329765U, 0x9D5E9715U, 0xB98BC447U,
        0xE36B4DAFU, 0xD3834579U, 0xDD6DFA8BU, 0x24D67297U, 0xB9EF4303U, 0x60E61757U, 0xE3D22EE5U,
        0x64559C73U, 0x2CCA67D5U, 0x64F05918U, 0x96132C1FU, 0x803B82B6U, 0xFF731EECU, 0x0ADD7BFFU,
        0x13731963U, 0x79A77925U, 0x4779F2AFU, 0x5F8071C7U, 0x66D459CCU, 0x5171418AU, 0x51B01F88U,
        0xE56BBB8BU, 0xD1C7668DU, 0x9C0347CDU, 0x69FB3896U, 0xD1B9F178U, 0x1F67C04FU, 0x08D73ED7U,
        0x0CD351FFU, 0xB887EDB6U, 0xE3B1CFD0U, 0x92E55227U, 0x2D9C692DU, 0xB25D5B3AU, 0x3EF4A746U,
        0xE91A5F35U, 0xFD96A0BAU, 0x198EFA57U, 0x1DD36267U, 0x4183517AU, 0x5FA09D72U, 0xCE2E8B96U,
        0xF58E496EU, 0xA849947EU, 0xC291BEB9U, 0x5E0E3AB0U, 0xB05E6404U, 0xE4474C0FU, 0xB7F80112U,
        0x4DB80CF3U, 0x3694A5FBU, 0xE75AE9F5U, 0xF5EE1543U, 0xDD2E2628U, 0x2623A5D4U, 0x039D2F20U,
        0x6B314D0DU, 0x128DF55CU, 0x2AA0D967U, 0x03C2AA22U, 0x8639CE1EU, 0x41A485ADU, 0xF30D4827U,
        0x1B04C05CU, 0x1ECEDA51U, 0x753D2B9EU, 0xD979F3B0U, 0x0739C830U, 0xF90B7466U, 0x658F1D51U,
        0x4086475FU, 0x859FECB8U, 0x7B8AB2FBU, 0x965C8F9AU, 0xF0C6704BU, 0xE697472FU, 0xC217B22BU,
        0xBFF067A9U, 0xD0F8E003U, 0xAC4954B0U, 0x5CA6A00CU, 0x9CF20A54U, 0x6B30B9FFU, 0xFDBD7A70U,
        0xF21506AAU, 0x0BDA9E14U, 0x598224CEU, 0xBF916D0AU, 0xD5F2E8BDU, 0x95AB9ACFU, 0x3940D072U,
        0x4B61345EU, 0xD07491B8U, 0x0AB1A7D5U, 0xF711C780U, 0xCEC587C5U, 0xB8EA09B4U, 0x39B4C3C1U,
        0x99AEF88BU, 0x9161806AU, 0x8D200550U, 0x3CBDD2CEU, 0x5AFEC2CDU, 0xD69D9672U, 0xECDC59D8U,
        0x9B4C0DA5U, 0x460B65D4U, 0x7F607FFCU, 0x62E75DDFU, 0xA1FEEF22U, 0xFF12769CU, 0x8B70F4C9U,
        0x29BD32C9U, 0x705FAA8FU, 0x279D5273U, 0x36A56FEDU, 0xF19A2441U, 0x16138D17U, 0x9137C2F6U,
        0x4795C1D4U, 0x09F5E2AFU, 0x021E0BE7U, 0x50BFBCCEU, 0xBC74983DU, 0xC0725407U, 0xD6B48F92U,
        0xAC1FB7B4U, 0x06F7EAF2U, 0x8BD47B24U, 0x93965FE6U, 0xAB817CFAU, 0x07D6604DU, 0xB0B7D54DU,
        0x09F939E0U, 0xF455CEDFU, 0x01576291U, 0x4D2072EAU, 0xD02C3FBEU, 0x52A2CEDEU, 0x640145FBU,
        0xDBBC5110U, 0x63418A47U, 0x12C664A4U, 0x1560B12FU, 0x96F308E6U, 0x0B1A7983U, 0xC1C42CD4U,
        0x324DDEF1U, 0x45CE2CD4U, 0x744AC782U, 0x44043511U, 0x68B5AA24U, 0x62F33664U},
    0x27D7CA57U);
inline const auto record_values =
    data_mask::decode(std::array<std::uint32_t, 1>{0x45F312BBU}, 0xA0F8BB5FU);
} // namespace apple_auth::detail::kbsync
