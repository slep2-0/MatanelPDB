// SPDX-License-Identifier: Apache-2.0

#include "PdbInfo.h"
#include "../common/Bytes.h"

#include <stddef.h>

namespace MatanelPDB {
namespace PDB {

static_assert(__is_standard_layout(PdbInfoHeader),
              "PDB Info header must have a standard layout");
static_assert(__is_trivially_copyable(PdbInfoHeader),
              "PDB Info header must support byte copying");
static_assert(sizeof(PdbInfoHeader) == PdbInfoHeaderByteSize,
              "Unexpected PDB Info header size");
static_assert(offsetof(PdbInfoHeader, Version) == 0 &&
              offsetof(PdbInfoHeader, Signature) == 4 &&
              offsetof(PdbInfoHeader, Age) == 8 &&
              offsetof(PdbInfoHeader, Guid) == 12,
              "Unexpected PDB Info header field offsets");

using namespace MSF;
ParseStatus
ParsePdbInfoHeader(
    const MSF::Wire::U8* Bytes,
    MSF::ViewSize ByteCount,
    PdbInfoHeader* Info
) noexcept

/*++

    Routine Description:

        Parses the fixed 28-byte header at the start of PDB Info stream 1.
        The caller supplies bounded stream bytes, this routine does not locate
        or copy the stream from the MSF container. Publishes Info only on
        success.

    Arguments:

        Bytes - Readable bytes beginning at offset zero of PDB Info stream 1.

        ByteCount - Number of readable bytes at Bytes.

        Info - Receives Version, Signature, Age, and the raw GUID bytes.

    Return Value:

        Success when the fixed header has been copied. InvalidArgument for a
        null input, null output, or zero byte count. TruncatedFile when fewer
        than 28 bytes are available. Info is unchanged on failure.

    Notes:

        The byte copy requires a little endian target. 
        Success reports header extraction, supported version validation remains to be implemented.

--*/

{
    if (!Bytes || !Info || !ByteCount) {
        return ParseStatus::InvalidArgument;
    }

    // Prevent reading beyond the supplied buffer.
    if (ByteCount < PdbInfoHeaderByteSize) {
        // Not enough for the header
        return ParseStatus::TruncatedFile;
    }

    // The assertions protect the object layout, this copy relies on a little endian target.
    PdbInfoHeader Parsed;
    MatanelPDB::Detail::CopyBytes(&Parsed, Bytes, PdbInfoHeaderByteSize);
    MatanelPDB::Detail::CopyBytes(Info, &Parsed, PdbInfoHeaderByteSize);
    return ParseStatus::Success;
}

} // namespace PDB
} // namespace MatanelPDB
