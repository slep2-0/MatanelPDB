#pragma once

// SPDX-License-Identifier: Apache-2.0

#include "PeImage.h"

namespace MatanelPDB {
namespace PEUtils {

namespace Wire {

// The fixed portion of a CodeView RSDS payload. The PDB name follows it and
// has a variable length, including a terminating null byte.
#pragma pack(push, 1)
struct RsdsPrefix {
    U8 Signature[4];
    U8 Guid[16];
    U32 Age;
};
#pragma pack(pop)

static_assert(sizeof(RsdsPrefix) == 24, "Unexpected RSDS prefix layout");

constexpr U8 RsdsSignature[4] = {'R', 'S', 'D', 'S'};

} // namespace Wire

struct RsdsInfo {
    Wire::U8 Guid[16]; // Raw bytes in the RSDS record, not a formatted GUID string.
    Wire::U32 Age;
    const char* PdbName; // Borrows storage from Payload, never free this pointer.
    ViewSize PdbNameLength; // Excludes the terminating zero byte.
};

// Extracts the PDB identity from the CodeView RSDS payload.
ParseStatus ParseRsds(ImageView Payload, RsdsInfo* Info) noexcept;

}
}
