#pragma once

// SPDX-License-Identifier: Apache-2.0

#include "../msf/msf.h"

namespace MatanelPDB {
namespace PDB {

// DBI versions are independent of the MSF container version.
enum class DbiStreamVersion : MSF::Wire::U32 {
    VC41 = 930803,
    V50 = 19960307,
    V60 = 19970606,
    V70 = 19990903,
    V110 = 20091201
};

constexpr MSF::ViewSize DbiHeaderByteSize = 64;
constexpr MSF::Wire::I32 DbiVersionSignature = -1;
constexpr MSF::Wire::U16 DbiAbsentStreamIndex = 0xFFFF;

// Fixed modern DBI header at offset zero of stream INDEX_DBI (3)
// Integer values in parsed output are in host order, offset comments describe
// the little endian file layout, not permission to cast arbitrary input bytes.
// linkion: https://www.llvm.org/docs/PDB/DbiStream.html#stream-header
struct DbiHeader {
    MSF::Wire::I32 VersionSignature;          // 0: modern layout marker (-1).
    MSF::Wire::U32 VersionHeader;             // 4: DbiStreamVersion value.
    MSF::Wire::U32 Age;                       // 8: DBI age for image binding.
    MSF::Wire::U16 GlobalStreamIndex;         // 12: global symbol index stream.
    MSF::Wire::U16 BuildNumber;               // 14: packed toolchain version.
    MSF::Wire::U16 PublicStreamIndex;         // 16: public symbol index stream.
    MSF::Wire::U16 PdbDllVersion;             // 18: producer DLL version.
    MSF::Wire::U16 SymRecordStream;           // 20: shared symbol record stream.
    MSF::Wire::U16 PdbDllRbld;                // 22: producer DLL rebuild value.
    MSF::Wire::I32 ModInfoSize;               // 24: module information byte size.
    MSF::Wire::I32 SectionContributionSize;   // 28: section contributions byte size.
    MSF::Wire::I32 SectionMapSize;            // 32: section map byte size.
    MSF::Wire::I32 SourceInfoSize;            // 36: source file information byte size.
    MSF::Wire::I32 TypeServerMapSize;         // 40: type server map byte size.
    MSF::Wire::U32 MFCTypeServerIndex;        // 44: index, not a substream size.
    MSF::Wire::I32 OptionalDbgHeaderSize;     // 48: optional debug stream indices byte size.
    MSF::Wire::I32 ECSubstreamSize;           // 52: Edit and Continue byte size.
    MSF::Wire::U16 Flags;                     // 56: packed DBI flags.
    MSF::Wire::U16 Machine;                   // 58: target machine code.
    MSF::Wire::U32 Padding;                   // 60: reserved padding.
};

// Parses only the fixed header, initial supported version is V70.
MSF::ParseStatus ParseDbiHeader(
    const MSF::Wire::U8* Bytes,
    MSF::ViewSize ByteCount,
    DbiHeader* Info
) noexcept;

} // namespace PDB
} // namespace MatanelPDB
