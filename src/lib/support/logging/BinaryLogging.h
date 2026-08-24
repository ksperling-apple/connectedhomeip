/*
 *    Copyright (c) 2020-2023 Project CHIP Authors
 *    Copyright (c) 2013-2017 Nest Labs, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *      This file defines macros, constants, and interfaces for logging binary
 *      data (represented by ByteSpan).
 */

#pragma once

#include <lib/core/CHIPConfig.h>

#include <lib/support/Span.h>
#include <lib/support/logging/TextOnlyLogging.h>

namespace chip {
namespace Logging {

#if CHIP_DETAIL_LOGGING

/**
 * @def ChipLogByteSpan(MOD, DATA)
 *
 * @brief
 *   Log a byte span for the specified module in the 'Detail' category.
 *
 */
#define ChipLogByteSpan(MOD, DATA) ChipInternalLogByteSpan(MOD, DETAIL, DATA)

#else // CHIP_DETAIL_LOGGING
#define ChipLogByteSpan(MOD, DATA) ((void) 0)
#endif // CHIP_DETAIL_LOGGING

/**
 * @def ChipLogFormatX160
 * @def ChipLogValueX160(SPAN)
 *
 * Macros for logging a FixedByteSpan<20> (e.g. a certificate identifier or a hash) as a hexadecimal big endian value.
 *  Example Usage:
 *
 *  @code
 *  FixedByteSpan<20> skid = ...;
 *  ChipLogProgress(Foo, "Revoking certificate " ChipLogFormatX160, ChipLogValueX160(skid));
 *  @endcode
 **/
#define ChipLogFormatX160 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32
// clang-format off
#define ChipLogValueX160(aValue)                    \
    ::chip::Logging::Internal::Big32FromSpan<20>(aValue, 16), \
    ::chip::Logging::Internal::Big32FromSpan<20>(aValue, 12), \
    ::chip::Logging::Internal::Big32FromSpan<20>(aValue, 8),  \
    ::chip::Logging::Internal::Big32FromSpan<20>(aValue, 4),  \
    ::chip::Logging::Internal::Big32FromSpan<20>(aValue, 0)
// clang-format on

namespace Internal {
template <size_t N>
inline uint32_t Big32FromSpan(const FixedByteSpan<N> & span, size_t ofs)
{
    return (static_cast<uint32_t>(span.data()[ofs + 3]) << 24) | static_cast<uint32_t>(span.data()[ofs + 2] << 16) |
        static_cast<uint32_t>(span.data()[ofs + 1] << 8) | static_cast<uint32_t>(span.data()[ofs]);
}
} // namespace Internal

// _CHIP_USE_LOGGING is defined in TextOnlyLogging.h
#if _CHIP_USE_LOGGING

void LogByteSpan(uint8_t module, uint8_t category, const ByteSpan & span);

#if CHIP_SYSTEM_CONFIG_PLATFORM_LOG
#ifndef ChipPlatformLogByteSpan
#error "CHIP_SYSTEM_CONFIG_PLATFORM_LOG is enabled but ChipPlatformLogByteSpan() is not defined"
#endif
#define ChipInternalLogByteSpan(...) ChipPlatformLogByteSpan(__VA_ARGS__)
#else // CHIP_SYSTEM_CONFIG_PLATFORM_LOG
#define ChipInternalLogByteSpan(MOD, CAT, DATA)                                                                                    \
    if (CHIP_CONFIG_LOG_MODULE_##MOD && IsModuleCategoryEnabled(MOD, CAT))                                                         \
    {                                                                                                                              \
        ChipInternalLogByteSpanImpl(MOD, CHIP_LOG_CATEGORY_##CAT, DATA);                                                           \
    }
#endif // CHIP_SYSTEM_CONFIG_PLATFORM_LOG

#define ChipInternalLogByteSpanImpl(MOD, CAT, DATA)                                                                                \
    do                                                                                                                             \
    {                                                                                                                              \
        if (chip::Logging::IsCategoryEnabled(CAT))                                                                                 \
        {                                                                                                                          \
            chip::Logging::LogByteSpan(chip::Logging::kLogModule_##MOD, CAT, DATA);                                                \
        }                                                                                                                          \
    } while (0)

#endif // _CHIP_USE_LOGGING

} // namespace Logging
} // namespace chip
