#pragma once

// SPDX-License-Identifier: Apache-2.0

#include "../msf/msf.h"

namespace MatanelPDB {
namespace PDB {

// The fixed header at the start of PDB Info stream 1.
// The GUID remains in its 16 byte ondisk representation, integer fields are decoded to host order.
struct PdbInfoHeader {
    MSF::Wire::U32 Version;
    MSF::Wire::U32 Signature;
    MSF::Wire::U32 Age;
    MSF::Wire::U8 Guid[16];
};

constexpr MSF::ViewSize PdbInfoHeaderByteSize = 28;

// Interprets bytes already copied from the beginning of PDB Info stream 1.
MSF::ParseStatus ParsePdbInfoHeader(
    const MSF::Wire::U8* Bytes,
    MSF::ViewSize ByteCount,
    PdbInfoHeader* Info
) noexcept;

} // namespace PDB
} // namespace MatanelPDB
