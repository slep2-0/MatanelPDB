#pragma once

// SPDX-License-Identifier: Apache-2.0

namespace MatanelPDB {
namespace Detail {

// memcpy equivalent for no CRT, buffers must be valid and must not overlap.
inline void CopyBytes(
    void* Destination,
    const void* Source,
    decltype(sizeof(0)) ByteCount
) noexcept
{
    // volatile byte writes prevent replacement with a CRT memcpy call (because CRT memcpy doesnt take volatile args).
    volatile unsigned char* Output = static_cast<volatile unsigned char*>(Destination);
    const unsigned char* Input = static_cast<const unsigned char*>(Source);
    for (decltype(sizeof(0)) i = 0; i < ByteCount; ++i) {
        Output[i] = Input[i];
    }
}

} // namespace Detail
} // namespace MatanelPDB
