#pragma once

// Licensed under Apache License 2.0

#include "../msf/msf.h"

namespace MatanelPDB {
namespace PDB {

// TPI format versions are independent of DBI and MSF versions
enum class TpiStreamVersion : MSF::Wire::U32 {
    V40 = 19950410,
    V41 = 19951122,
    V50 = 19961031,
    V70 = 19990903,
    V80 = 20040203
};

constexpr MSF::ViewSize TpiHeaderByteSize = 56;
constexpr MSF::Wire::U32 TpiFirstNonPrimitiveTypeIndex = 0x1000;
constexpr MSF::Wire::U16 TpiAbsentStreamIndex = 0xFFFF;

// Fixed modern TPI header at offset zero of stream INDEX_TPI (2)
// Parsed integer fields are in host order
// Offset comments describe positions within the serialized header
struct TpiHeader {
    MSF::Wire::U32 Version;                  // 0: TPI format version
    MSF::Wire::U32 HeaderSize;               // 4: byte offset where type records begin
    MSF::Wire::U32 TypeIndexBegin;           // 8: identifier of the first type record
    MSF::Wire::U32 TypeIndexEnd;             // 12: identifier after the last type record
    MSF::Wire::U32 TypeRecordBytes;          // 16: byte length of the type record region
    MSF::Wire::U16 HashStreamIndex;          // 20: MSF stream containing type hash data
    MSF::Wire::U16 HashAuxStreamIndex;       // 22: auxiliary hash stream or absent sentinel
    MSF::Wire::U32 HashKeySize;              // 24: byte size of each hash value
    MSF::Wire::U32 NumHashBuckets;           // 28: number of hash buckets
    MSF::Wire::I32 HashValueBufferOffset;    // 32: hash value buffer offset in the hash stream
    MSF::Wire::U32 HashValueBufferLength;    // 36: hash value buffer byte length
    MSF::Wire::I32 IndexOffsetBufferOffset;  // 40: type index lookup buffer offset in the hash stream
    MSF::Wire::U32 IndexOffsetBufferLength;  // 44: type index lookup buffer byte length
    MSF::Wire::I32 HashAdjBufferOffset;      // 48: hash adjustment buffer offset in the hash stream
    MSF::Wire::U32 HashAdjBufferLength;      // 52: hash adjustment buffer byte length
};

constexpr MSF::ViewSize TpiTypeRecordPrefixByteSize = 4;
constexpr MSF::ViewSize TpiTypeRecordLengthFieldByteSize = 2; // start to end
constexpr MSF::ViewSize TpiTypeRecordAlignment = 4;

// Selected leaf kinds for later payload decoding
enum class TpiTypeRecordKind : MSF::Wire::U16 {
    FieldList = 0x1203,
    Class = 0x1504,
    Structure = 0x1505,
    Union = 0x1506,
    Enum = 0x1507
};

// Serialized prefix shared by TPI leaf records
// RecordLen includes the kind, payload and padding but excludes its own field
struct TpiTypeRecordPrefix {
    MSF::Wire::U16 RecordLen;
    MSF::Wire::U16 RecordKind;
};

// PayloadBytes borrows the input buffer which must remain alive and immutable (meaning you must keep the Bytes argument alive)
// This output object is not a serialized record layout
struct TpiTypeRecordView {
    MSF::Wire::U16 RecordKind;              // Raw kind value including unknown kinds
    MSF::ViewSize RecordByteSize;          // Complete record including the prefix and padding
    const MSF::Wire::U8* PayloadBytes;      // First byte after the four byte prefix
    MSF::ViewSize PayloadByteCount;        // Bytes after the prefix including any padding
};

// One entry in a table ordered by consecutive type indices
// StreamByteOffset is measured from the beginning of the assembled TPI stream
struct TpiTypeRecordLocation {
    MSF::Wire::U32 TypeIndex;              // Identifier assigned to this record
    MSF::ViewSize StreamByteOffset;        // Byte offset of the record prefix within TPI
    MSF::ViewSize RecordByteSize;          // Complete record including prefix and padding
};

// Decodes the fixed header and validates the metadata needed for record traversal
MSF::ParseStatus ParseTpiHeader(
    const MSF::Wire::U8* Bytes,
    MSF::ViewSize ByteCount,
    TpiHeader* Info
) noexcept;

// Validates one record boundary and returns a borrowed view of its payload
MSF::ParseStatus ParseTpiTypeRecord(
    const MSF::Wire::U8* Bytes,
    MSF::ViewSize ByteCount,
    TpiTypeRecordView* Info
) noexcept;

// Validates the TPI record sequence and maps type indices to record locations
MSF::ParseStatus BuildTpiRecordIndex(
    const MSF::Wire::U8* TpiBytes,
    MSF::ViewSize TpiByteCount,
    TpiTypeRecordLocation* Records,
    MSF::ViewSize RecordCapacity,
    MSF::ViewSize* RecordCount
) noexcept;

} // namespace PDB
} // namespace MatanelPDB
