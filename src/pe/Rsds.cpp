// SPDX-License-Identifier: Apache-2.0

#include "Rsds.h"

namespace MatanelPDB {
namespace PEUtils {

ParseStatus
ParseRsds(
    ImageView Payload,
    RsdsInfo* Info
) noexcept

/*++

    Routine Description:

        Validates a bounded CodeView RSDS payload and extracts its PDB GUID,
        Age, and null termed PDB name. The name in RsdsInfo borrows bytes
        from Payload and is valid only while Payload remains alive.

    Arguments:

        Payload - Bytes of one CodeView debug payload, with its exact readable size.

        Info - Receives the identity only when parsing succeeds.

    Return Value:

        Success for a complete RSDS record, otherwise a parse status describing
        a null argument, truncated payload, or invalid format.

    Notes:

        The fixed prefix is 24 bytes. The remaining bytes must contain a
        terminating zero for the PDB name. Do not read beyond Payload.ByteCount.

--*/

{
    if (!Payload.Bytes || !Info) {
        return ParseStatus::InvalidArgument;
    }

    // Before comparing sig make sure the struct has enough space
    // + 1 for a nullterm, so [ PREFIX STRUCT | NAME WITH NULLTERM ]
    if (Payload.ByteCount < sizeof(Wire::RsdsPrefix) + 1) {
        return ParseStatus::TruncatedImage;
    }

    // Make sure the RSDS Signature is good
    for (int i = 0; i < sizeof(Wire::RsdsPrefix::Signature); i++) {
        if (Payload.Bytes[i] != Wire::RsdsSignature[i]) {
            return ParseStatus::InvalidFormat;
        }
    }

    // Cast to the struct
    const Wire::RsdsPrefix* Rsds = (const Wire::RsdsPrefix*)(Payload.Bytes);

    // Verify that within the name we return it is actually nulltermed
    bool NullTermFound = false;
    ViewSize NameLength = 0;
    const Wire::U8* NameStart = (const Wire::U8*)(Payload.Bytes + sizeof(Wire::RsdsPrefix));

    for (ViewSize i = 0; i < Payload.ByteCount - sizeof(Wire::RsdsPrefix); i++) {
        if (NameStart[i] == '\0') {
            // Null terminator found
            NullTermFound = true;
            NameLength = i;
            break;
        }
    }

    if (!NullTermFound || !NameLength) {
        return ParseStatus::InvalidFormat;
    }

    // Fill in the info struct now
    Info->Age = Rsds->Age;
    Info->PdbNameLength = NameLength;

    for (int i = 0; i < sizeof(Info->Guid); i++) {
        Info->Guid[i] = Rsds->Guid[i];
    }

    Info->PdbName = (const char*)NameStart;

    // All good, return success now
    return ParseStatus::Success;
}

}
}
