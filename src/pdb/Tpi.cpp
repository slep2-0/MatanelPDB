// Licensed under Apache License 2.0

#include "Tpi.h"
#include "../common/Bytes.h"

#include <stddef.h>

namespace MatanelPDB {
namespace PDB {

static_assert(__is_standard_layout(TpiHeader),
              "TPI header must have a standard layout");
static_assert(__is_trivially_copyable(TpiHeader),
              "TPI header must support byte copying");
static_assert(sizeof(TpiHeader) == TpiHeaderByteSize,
              "Unexpected modern TPI header size");
static_assert(offsetof(TpiHeader, Version) == 0 &&
              offsetof(TpiHeader, HeaderSize) == 4 &&
              offsetof(TpiHeader, TypeIndexBegin) == 8 &&
              offsetof(TpiHeader, TypeIndexEnd) == 12 &&
              offsetof(TpiHeader, TypeRecordBytes) == 16 &&
              offsetof(TpiHeader, HashStreamIndex) == 20 &&
              offsetof(TpiHeader, HashAuxStreamIndex) == 22 &&
              offsetof(TpiHeader, HashKeySize) == 24 &&
              offsetof(TpiHeader, NumHashBuckets) == 28 &&
              offsetof(TpiHeader, HashValueBufferOffset) == 32 &&
              offsetof(TpiHeader, HashValueBufferLength) == 36 &&
              offsetof(TpiHeader, IndexOffsetBufferOffset) == 40 &&
              offsetof(TpiHeader, IndexOffsetBufferLength) == 44 &&
              offsetof(TpiHeader, HashAdjBufferOffset) == 48 &&
              offsetof(TpiHeader, HashAdjBufferLength) == 52,
              "Unexpected modern TPI header field offsets");

static_assert(__is_standard_layout(TpiTypeRecordPrefix),
              "TPI record prefix must have a standard layout");
static_assert(__is_trivially_copyable(TpiTypeRecordPrefix),
              "TPI record prefix must support byte copying");
static_assert(sizeof(TpiTypeRecordPrefix) == TpiTypeRecordPrefixByteSize,
              "Unexpected TPI record prefix size");
static_assert(offsetof(TpiTypeRecordPrefix, RecordLen) == 0 &&
              offsetof(TpiTypeRecordPrefix, RecordKind) == 2,
              "Unexpected TPI record prefix field offsets");
static_assert(__is_trivially_copyable(TpiTypeRecordView),
              "TPI record view must support value copying");

using namespace MSF;

ParseStatus
ParseTpiHeader(
    const Wire::U8* Bytes,
    ViewSize ByteCount,
    TpiHeader* Info
) noexcept

/*++

    Routine Description:

        Decodes the fixed 56 byte TPI header at offset zero of stream
        INDEX_TPI (2). Supports version V80 with a 56 byte header. Checks
        the type index range and the consistency of the declared record
        count and byte length. Publishes Info only after these checks pass.

    Arguments:

        Bytes - contains readable bytes beginning at offset zero of TPI.
        The buffer may be unaligned.

        ByteCount - The number of readable bytes at Bytes. The first
        56 bytes are sufficient and later bytes are ignored.

        Info - The decoded header. It must not overlap Bytes
        and remains unchanged on failure.

    Return Value:

        Success means the fixed header and record metadata are valid.
        InvalidArgument means Bytes or Info is null.
        TruncatedFile means fewer than 56 bytes are available.
        UnsupportedFormat means the TPI version is unsupported.
        InvalidFormat means the header size or type record metadata
        is inconsistent.

    Notes:

        The type index end is exclusive. Indices below
        TpiFirstNonPrimitiveTypeIndex are reserved for primitive types.

        The caller validates the declared record region against the
        complete TPI stream size before reading any records. This routine
        does not parse individual records or allocate memory.

        Hash metadata is copied without validating its referenced streams
        or buffers. Validate it before using hash data. Hash stream indices
        are MSF stream numbers and buffer offsets refer to the hash stream.
        TpiAbsentStreamIndex means no referenced stream.

        Serialized integers are little endian. Copying into the local
        header requires a little endian target and does not swap bytes.

*/

{
    if (!Bytes || !Info) {
        return ParseStatus::InvalidArgument;
    }

    // The 56 byte header must be readable obviously
    if (ByteCount < TpiHeaderByteSize) {
        return ParseStatus::TruncatedFile;
    }

    // Copy the remote header into a local one
    // they must be little endian too
    TpiHeader Header;
    MatanelPDB::Detail::CopyBytes(&Header, Bytes, TpiHeaderByteSize);

    // Make sure the version matches
    if (Header.Version != static_cast<Wire::U32>(TpiStreamVersion::V80)) {
        return ParseStatus::UnsupportedFormat;
    }

    // Make sure the header reported size matches our expected one
    if (Header.HeaderSize != TpiHeaderByteSize) {
        // InvalidFormat since we already verified the stream version is V80
        return ParseStatus::InvalidFormat;
    }

    // Validate our default identifier range matches with the header
    // And is not a malforemd header
    if (Header.TypeIndexBegin < TpiFirstNonPrimitiveTypeIndex ||
        Header.TypeIndexEnd < Header.TypeIndexBegin) {
        return ParseStatus::InvalidFormat;
    }

    // Calculate the amount of TPI records (each record is an index)
    Wire::U32 RecordCount = Header.TypeIndexEnd - Header.TypeIndexBegin;

    // Make sure the records are aligned to 4 byte alignment
    if (Header.TypeRecordBytes % 4 != 0) {
        return ParseStatus::InvalidFormat;
    }

    // Make sure the record count isnt zero, and if its not, the size listed isnt zero
    // because that would mean TypeIndexBegin/End is lying to us. (malformed)
    if (RecordCount == 0 && Header.TypeRecordBytes != 0) {
        return ParseStatus::InvalidFormat;
    }

    // Make sure RecordCount is the same byte count as TypeRecordBytes
    // we divide to avoid mult overflow
    if (RecordCount > Header.TypeRecordBytes / 4) {
        // RecordCount isnt the same count as in the file
        return ParseStatus::InvalidFormat;
    }

    // phew, all good now
    MatanelPDB::Detail::CopyBytes(Info, &Header, TpiHeaderByteSize);
    return ParseStatus::Success;
}

ParseStatus
ParseTpiTypeRecord(
    const Wire::U8* Bytes,
    ViewSize ByteCount,
    TpiTypeRecordView* Info
) noexcept

/*++

    Routine Description:

        Decodes the four byte prefix of one TPI leaf record. Validates
        that the declared length covers the kind, that the complete record
        fits the supplied bytes and that its size is aligned to four bytes.
        Returns the raw kind, complete byte size and a borrowed payload view.
        Publishes Info only after these checks pass.

    Arguments:

        Bytes begins at a record boundary within the TPI record region.
        The buffer may be unaligned.

        ByteCount is the number of readable bytes from Bytes, limited to
        the remaining TPI record region. Later records may be present
        and are ignored by this call.

        Info receives the record view. It must not overlap the input
        buffer and remains unchanged on failure.

    Return Value:

        Success means the record framing is valid and Info is populated.
        InvalidArgument means Bytes or Info is null.
        TruncatedFile means the prefix or declared record is incomplete.
        InvalidFormat means the declared length cannot cover the kind
        or the complete record size violates the required alignment.

    Notes:

        RecordLen excludes its own two byte field. RecordByteSize includes
        that field, the kind, payload and padding. PayloadBytes begins
        after the complete four byte prefix. PayloadByteCount includes
        any trailing padding and can be zero.

        The payload borrows the input buffer. Keep that buffer alive and
        immutable while using the returned view. This routine allocates
        no memory and does not decode payload fields or padding contents.

        Unknown kinds are returned unchanged. A later payload decoder
        decides whether it supports the kind. Type indices are assigned
        by record traversal and are not stored in this prefix.

        Serialized integers are little endian. Copying the prefix into
        a local object requires a little endian target.

*/

{
    if (!Bytes || !Info) {
        return ParseStatus::InvalidArgument;
    }

    if (ByteCount < TpiTypeRecordPrefixByteSize) {
        return ParseStatus::TruncatedFile;
    }

    // Copy header
    TpiTypeRecordPrefix Prefix;
    MatanelPDB::Detail::CopyBytes(&Prefix, Bytes, TpiTypeRecordPrefixByteSize);

    // Start validations like always
    // Require that there is enough bytes for the kind represented by this prefix
    if (Prefix.RecordLen < sizeof(Prefix.RecordKind)) {
        return ParseStatus::InvalidFormat;
    }

    ViewSize RecordByteSize = (ViewSize)Prefix.RecordLen + TpiTypeRecordLengthFieldByteSize;

    // Make sure the record fits in
    if (RecordByteSize > ByteCount) {
        return ParseStatus::TruncatedFile;
    }

    // Make sure its aligned
    if (RecordByteSize % TpiTypeRecordAlignment != 0) {
        return ParseStatus::InvalidFormat;
    }

    // Prepare the local record view struct
    TpiTypeRecordView View;
    View.PayloadByteCount = RecordByteSize - sizeof(TpiTypeRecordPrefix);
    View.PayloadBytes = Bytes + TpiTypeRecordPrefixByteSize;
    View.RecordKind = Prefix.RecordKind;
    View.RecordByteSize = RecordByteSize;

    // Publish and goodbye
    MatanelPDB::Detail::CopyBytes(Info, &View, sizeof(TpiTypeRecordView));
    return ParseStatus::Success;
}

ParseStatus
BuildTpiRecordIndex(
    const Wire::U8* TpiBytes,
    ViewSize TpiByteCount,
    TpiTypeRecordLocation* Records,
    ViewSize RecordCapacity,
    ViewSize* RecordCount
) noexcept

/*++

    Routine Description:

        Parses the TPI header and validates that its record region fits the
        supplied stream bytes. Walks that region with ParseTpiTypeRecord and
        requires both the consumed byte count and the record count to match
        the header. Produces an ordered table of type indices, stream byte
        offsets and complete record sizes. Allocates no memory.

    Arguments:

        TpiBytes contains the assembled TPI stream beginning with its header
        at offset zero. The buffer may be unaligned and must remain immutable
        throughout the call. Preserve its contents for later indexed reads.

        TpiByteCount is the number of readable bytes at TpiBytes. Bytes after
        the declared record region are ignored.

        Records receives the record locations in type index order. It may
        be null to query the required number of entries. The buffer must not
        overlap TpiBytes or RecordCount and remains unchanged on failure.

        RecordCapacity is the number of entries available in Records.
        Its unit is TpiTypeRecordLocation objects.

        RecordCount receives the validated record count on Success or
        BufferTooSmall. It must not overlap the input buffer and remains
        unchanged on other failures.

    Return Value:

        Success means the complete declared record sequence is valid and
        the requested table was produced. An empty sequence needs no table.
        InvalidArgument means TpiBytes or RecordCount is null.
        TruncatedFile means the header, record region or a record is incomplete.
        UnsupportedFormat means the TPI header selects an unsupported version.
        InvalidFormat means header or record metadata is inconsistent.
        BufferTooSmall means a nonempty sequence needs a larger output table
        or Records is null. The complete sequence is validated before returning
        BufferTooSmall and Records is unchanged.

    Notes:

        Type indices begin at Header.TypeIndexBegin and increase by one for
        each record. StreamByteOffset is relative to TpiBytes and identifies
        the first byte of the record prefix. Type indices are identifiers.

        Record traversal is limited to Header.TypeRecordBytes following the
        header. Unknown kinds are indexed with the same framing rules.
        Individual payloads and referenced hash streams require their own
        validation before use. No payload fields are decoded by this routine.

*/

{
    // Implement header parsing, complete record validation and table publication here
    (void)TpiBytes;
    (void)TpiByteCount;
    (void)Records;
    (void)RecordCapacity;
    (void)RecordCount;
    return ParseStatus::NotImplemented;
}

} // namespace PDB
} // namespace MatanelPDB
