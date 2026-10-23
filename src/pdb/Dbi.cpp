// SPDX-License-Identifier: Apache-2.0

#include "Dbi.h"
#include "../common/Bytes.h"

#include <stddef.h>

namespace MatanelPDB {
namespace PDB {

// static and ben-el
static_assert(sizeof(DbiHeader) == DbiHeaderByteSize,
              "Unexpected modern DBI header size");
static_assert(offsetof(DbiHeader, VersionSignature) == 0 &&
              offsetof(DbiHeader, VersionHeader) == 4 &&
              offsetof(DbiHeader, Age) == 8 &&
              offsetof(DbiHeader, GlobalStreamIndex) == 12 &&
              offsetof(DbiHeader, BuildNumber) == 14 &&
              offsetof(DbiHeader, PublicStreamIndex) == 16 &&
              offsetof(DbiHeader, PdbDllVersion) == 18 &&
              offsetof(DbiHeader, SymRecordStream) == 20 &&
              offsetof(DbiHeader, PdbDllRbld) == 22 &&
              offsetof(DbiHeader, ModInfoSize) == 24 &&
              offsetof(DbiHeader, SectionContributionSize) == 28 &&
              offsetof(DbiHeader, SectionMapSize) == 32 &&
              offsetof(DbiHeader, SourceInfoSize) == 36 &&
              offsetof(DbiHeader, TypeServerMapSize) == 40 &&
              offsetof(DbiHeader, MFCTypeServerIndex) == 44 &&
              offsetof(DbiHeader, OptionalDbgHeaderSize) == 48 &&
              offsetof(DbiHeader, ECSubstreamSize) == 52 &&
              offsetof(DbiHeader, Flags) == 56 &&
              offsetof(DbiHeader, Machine) == 58 &&
              offsetof(DbiHeader, Padding) == 60,
              "Unexpected modern DBI header field offsets");

using namespace MSF;

ParseStatus
ParseDbiHeader(
    const Wire::U8* Bytes,
    ViewSize ByteCount,
    DbiHeader* Info
) noexcept

/*++

    Routine Description:

        Decodes and validates the fixed 64-byte modern DBI header at offset
        zero of stream INDEX_DBI (3). Supports version V70 and publishes Info
        only after header validation succeeds.

        The caller supplies bytes already obtained from the stream. This
        routine does not allocate memory or read the MSF container.

    Arguments:

        Bytes - Readable bytes beginning at offset zero of DBI stream 3.
                The buffer may be unaligned.

        ByteCount - Number of readable bytes at Bytes. Providing only the
                    first 64 bytes is sufficient, any later bytes are ignored.

        Info - Caller owned output receiving the decoded fixed header.
               Must not overlap the input buffer. Unchanged on failure.

    Return Value:

        Success - The supported fixed header was decoded and validated.

        InvalidArgument - Bytes or Info is null.

        TruncatedFile - The input is too short for the fixed header.

        UnsupportedFormat - The version signature or version header selects
                            a layout this parser does not support.

        InvalidFormat - A substream byte size is negative or violates its
                        required length alignment.

    Notes:

        Header validation alone does not prove that the declared substreams
        fit the complete DBI stream. That needs its actual stream byte size.
        Stream index validation against the MSF directory and image identity
        comparison belong to the caller (or a later integration routine).

        GlobalStreamIndex, PublicStreamIndex, and SymRecordStream are stream
        numbers, not byte offsets. DbiAbsentStreamIndex means no stream.
        Their presence is not required merely to extract this header.

        The ondisk integers are little endian. The layout assertions above
        establish size and field offsets, they do not establish endianness
        or make a direct cast from an arbitrary byte buffer safe.

--*/

{
    if (!Bytes || !Info) {
        return ParseStatus::InvalidArgument;
    }

    // Make sure the file has enough size
    if (ByteCount < DbiHeaderByteSize) {
        return ParseStatus::TruncatedFile;
    }

    // Copy into a local object, the integers still need to be little endian
    // but who compiles a PDB for big endian, damn..
    DbiHeader Header;
    MatanelPDB::Detail::CopyBytes(&Header, Bytes, DbiHeaderByteSize);

    // Start validating the header before returning it to the caller
    // I wish my life was easier, but i cant wait to see the end result of this project
    if (Header.VersionSignature != DbiVersionSignature) {
        // Invalid sig
        return ParseStatus::UnsupportedFormat;
    }

    // Verify the version is the one we support only right now
    if (Header.VersionHeader != static_cast<Wire::U32>(DbiStreamVersion::V70)) {
        // Only V70 is supported right now
        return ParseStatus::UnsupportedFormat;
    }

    // Zero means an empty or omitted substream, which is okay. A negative byte size is invalid
    // and would become a huge length if converted to an unsigned size.
    if (Header.ModInfoSize < 0 ||
        Header.SectionContributionSize < 0 ||
        Header.SectionMapSize < 0 ||
        Header.SourceInfoSize < 0 ||
        Header.TypeServerMapSize < 0 ||
        Header.OptionalDbgHeaderSize < 0 ||
        Header.ECSubstreamSize < 0) {
        return ParseStatus::InvalidFormat;
    }

    // Metadata lengths are aligned to 4 bytes, optional debug indices are 2 bytes each.
    if (Header.ModInfoSize % 4 != 0 ||
        Header.SectionContributionSize % 4 != 0 ||
        Header.SectionMapSize % 4 != 0 ||
        Header.SourceInfoSize % 4 != 0 ||
        Header.TypeServerMapSize % 4 != 0 ||
        Header.OptionalDbgHeaderSize % 2 != 0) {
        return ParseStatus::InvalidFormat;
    }

    // DBI Header is all good, publish to caller
    MatanelPDB::Detail::CopyBytes(Info, &Header, DbiHeaderByteSize);
    return ParseStatus::Success;
}

} // namespace PDB
} // namespace MatanelPDB
