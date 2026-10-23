#pragma once

// SPDX-License-Identifier: Apache-2.0

namespace MatanelPDB {
namespace MSF {

using ViewSize = decltype(sizeof(0));

namespace Wire {

using U8 = unsigned char;
using U16 = unsigned short;
using U32 = unsigned int;
using I32 = signed int;

static_assert(sizeof(U8) == 1 && sizeof(U16) == 2 && sizeof(U32) == 4 && sizeof(I32) == 4,
              "Unsupported MSF field widths");

// MSF 2.00 uses a different header and block-map layout from MSF 7.00.
// Only the fixed prefix is represented here, more header data follows it.
// i am honestly not sure if this will be even used, but im adding it anyway
// Win10 probably uses Msf7, and I say Win10 because we use ExAllocatePool2 on allocs which is Win10+ only
// If we ever switch to WithTag then atleast we are covered on the older ntoskrnls with this PDB parser
// Note that this is a generic PDB parser, so this isnt kernel mode only, its just standard compilable C++.
#pragma pack(push, 1)
struct Msf2HeaderPrefix {
    U8 Magic[44];
    U32 BlockSize;
    U16 FreeBlockMapBlock;
    U16 NumBlocks;
    U32 NumDirectoryBytes;
};
#pragma pack(pop)

static_assert(sizeof(Msf2HeaderPrefix) == 56,
              "Unexpected MSF 2.00 header prefix layout");

// Fixed MSF 7.00 superblock at file offset zero. Its block map and stream directory are somewhere else in the file.
#pragma pack(push, 1)
struct Msf7Superblock {
    U8 Magic[30];
    U8 Padding[2]; // Between the 30-byte signature and the aligned BlockSize.
    U32 BlockSize;
    U32 FreeBlockMapBlock;
    U32 NumBlocks;
    U32 NumDirectoryBytes;
    U32 Reserved;
    U32 BlockMapAddr;
};
#pragma pack(pop)

static_assert(sizeof(Msf7Superblock) == 56,
              "Unexpected MSF 7.00 superblock layout");

} // namespace Wire

namespace Detail {

// BlockSize must be nonzero. Count a partially filled final block.
constexpr ViewSize BytesToBlocks(ViewSize ByteCount, Wire::U32 BlockSize) noexcept
{
    return ByteCount / BlockSize + (ByteCount % BlockSize != 0);
}

// MSF 7 block counts and block sizes are 32-bit fields. Keep their product
// wide until the caller has checked it against its file or buffer size.
constexpr unsigned long long BlocksToBytes(Wire::U32 BlockCount, Wire::U32 BlockSize) noexcept
{
    return static_cast<unsigned long long>(BlockCount) * BlockSize;
}

} // namespace Detail

struct FileView {
    const Wire::U8* Bytes;
    ViewSize ByteCount;
};

enum class ContainerFormat : unsigned char {
    Msf2,
    Msf7
};

struct Msf2HeaderInfo {
    Wire::U32 BlockSize;
    Wire::U16 FreeBlockMapBlock;
    Wire::U16 NumBlocks;
    Wire::U32 NumDirectoryBytes;
};

struct Msf7SuperblockInfo {
    Wire::U32 BlockSize;
    Wire::U32 FreeBlockMapBlock;
    Wire::U32 NumBlocks;
    Wire::U32 NumDirectoryBytes;
    Wire::U32 BlockMapAddr;
};

// Format identifies which header is meaningful. The other header is zeroed.
struct ContainerHeaderInfo {
    ContainerFormat Format;
    Msf2HeaderInfo Msf2;
    Msf7SuperblockInfo Msf7;
};

struct Msf7StreamInfo {
    Wire::U32 ByteSize;       // 0xFFFFFFFF means absent
    ViewSize DirectoryBlockListByteOffset; // Byte offset within DirectoryBytes
    ViewSize BlockCount;
};

enum class ParseStatus : unsigned char {
    Success,
    InvalidArgument,
    TruncatedFile,
    InvalidFormat,
    UnsupportedFormat,
    NotImplemented,
    BufferTooSmall
};

// Detects the container layout and forwards to its header parser.
ParseStatus ParseContainerHeader(FileView File, ContainerHeaderInfo* Info) noexcept;

// Identifies a supported MSF container by its file signature.
ParseStatus DetectContainerFormat(FileView File, ContainerFormat* Format) noexcept;

// Validates each format's fixed header against the supplied file bounds.
ParseStatus ParseMsf2Header(FileView File, Msf2HeaderInfo* Info) noexcept;
ParseStatus ParseMsf7Superblock(FileView File, Msf7SuperblockInfo* Info) noexcept;

// Msf7 routines
ParseStatus ReadMsf7DirectoryBlockMap(
    FileView File,
    const Msf7SuperblockInfo& Header,
    Wire::U32* DirectoryBlocks,
    ViewSize DirectoryBlockCapacity,
    ViewSize* DirectoryBlockCount
) noexcept;

ParseStatus CopyMsf7StreamDirectory(
    FileView File,
    const Msf7SuperblockInfo& Header,
    const Wire::U32* DirectoryBlocks,
    ViewSize DirectoryBlockCount,
    Wire::U8* DirectoryBytes,
    ViewSize DirectoryCapacity
) noexcept;

ParseStatus ParseMsf7StreamDirectory(
    const Wire::U8* DirectoryBytes,
    ViewSize DirectoryByteCount,
    const Msf7SuperblockInfo& Header,
    Msf7StreamInfo* Streams,
    ViewSize StreamCapacity,
    ViewSize* StreamCount
) noexcept;

ParseStatus CopyMsf7StreamRange(
    FileView File,
    const Msf7SuperblockInfo& Header,
    const Wire::U8* DirectoryBytes,
    ViewSize DirectoryByteCount,
    const Msf7StreamInfo& Stream,
    ViewSize StreamOffset,
    ViewSize BytesToCopy,
    Wire::U8* Destination,
    ViewSize DestinationCapacity
) noexcept;

} // namespace MSF
} // namespace MatanelPDB

// Arithmetic conveniences for validated MSF block sizes. Arguments are
// evaluated once by the inline functions; these macros do not validate input.
#define BYTES_TO_BLOCKS(Bytes, BlockSize) \
    (::MatanelPDB::MSF::Detail::BytesToBlocks((Bytes), (BlockSize)))
#define BLOCKS_TO_BYTES(Blocks, BlockSize) \
    (::MatanelPDB::MSF::Detail::BlocksToBytes((Blocks), (BlockSize)))
