// SPDX-License-Identifier: Apache-2.0

#include "msf.h"

// The 2 sigs by microsoft, direct link: https://github.com/microsoft/microsoft-pdb/blob/master/PDB/msf/msf.cpp#L961
// no need to reverse engineer everything!
static const char szHdrMagic[0x2c] = "Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47";
static const char szBigHdrMagic[0x1e] = "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53";

// i will not make a for loop again, sorry
static inline int fastest_memcmp_ever(
    const void* a,
    const void* b,
    unsigned long long size)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;

    for (unsigned long long i = 0; i < size; ++i) {
        if (x[i] != y[i])
            return x[i] - y[i];
    }

    return 0;
}

namespace MatanelPDB {
namespace MSF {

static inline Wire::U32 ConstructToLittleEndian(const Wire::U8* Data)
{
    return
        static_cast<Wire::U32>(Data[0]) |
        (static_cast<Wire::U32>(Data[1]) << 8) |
        (static_cast<Wire::U32>(Data[2]) << 16) |
        (static_cast<Wire::U32>(Data[3]) << 24);
}

// Checks the file range and fixed MSF metadata blocks. It does not detect
// overlap with the directory blocks named by the separate directory map.
static inline bool IsUsableMsf7BlockNumber(
    Wire::U32 BlockNumber,
    const Msf7SuperblockInfo& Header) noexcept
{
    if (!Header.BlockSize || BlockNumber == 0 ||
        BlockNumber >= Header.NumBlocks ||
        BlockNumber == Header.BlockMapAddr) {
        return false;
    }

    const Wire::U32 IntervalPosition = BlockNumber % Header.BlockSize;
    return IntervalPosition != 1 && IntervalPosition != 2;
}

// Returns the byte offset of a complete physical block within FileByteCount.
// The division check also makes the multiplication safe for 32-bit ViewSize.
static inline bool TryGetBlockStartOffset(
    Wire::U32 BlockNumber,
    Wire::U32 BlockSize,
    ViewSize FileByteCount,
    ViewSize* BlockStartOffset) noexcept
{
    if (!BlockStartOffset || !BlockSize ||
        BlockNumber >= FileByteCount / BlockSize) {
        return false;
    }

    *BlockStartOffset = static_cast<ViewSize>(BlockNumber) * BlockSize;
    return true;
}

ParseStatus
ParseContainerHeader(
    FileView File,
    ContainerHeaderInfo* Info
) noexcept

/*++

    Routine Description:

        Detects the MSF container format, calls the corresponding header
        parser, and returns that parser's status. Publishes Info only on success.

    Arguments:

        File - Entire readable PDB file and its actual byte count.

        Info - Receives the detected format and its validated header metadata
               only when parsing succeeds.

    Return Value:

        InvalidArgument for a null input or output, otherwise the status from
        format detection or the selected header parser.

--*/

{
    if (!File.Bytes || !Info) {
        return ParseStatus::InvalidArgument;
    }

    ContainerFormat Format{};
    ParseStatus Status = DetectContainerFormat(File, &Format);
    if (Status != ParseStatus::Success) {
        return Status;
    }

    ContainerHeaderInfo Parsed{};
    if (Format == ContainerFormat::Msf2) {
        Status = ParseMsf2Header(File, &Parsed.Msf2);
    } else if (Format == ContainerFormat::Msf7) {
        Status = ParseMsf7Superblock(File, &Parsed.Msf7);
    } else {
        return ParseStatus::UnsupportedFormat;
    }

    if (Status == ParseStatus::Success) {
        Parsed.Format = Format;
        *Info = Parsed;
    }

    return Status;
}

ParseStatus
DetectContainerFormat(
    FileView File,
    ContainerFormat* Format
) noexcept

/*++

    Routine Description:

        Identifies the MSF container layout from the bounded file signature.

    Arguments:

        File - Entire readable PDB file and its actual byte count.

        Format - Receives the identified format only on success.

    Return Value:

        Success for a recognized format, otherwise a parse status. The
        initial stub returns NotImplemented.

--*/

{
    if (!File.Bytes || !Format) {
        return ParseStatus::InvalidArgument;
    }

    // As it turns out, both of the structures have the same byte size
    // I'm pretty sure microsoft did this for sizeof checks like this one below
    // but even though they are the same, i'll still separate it with an OR because
    // maybe it changes, and the OR will catch it, its just 4 ish more CPU cycles, dont cry!
    if (File.ByteCount < sizeof(Wire::Msf2HeaderPrefix) || File.ByteCount < sizeof(Wire::Msf7Superblock)) {
        return ParseStatus::TruncatedFile;
    }

    // Compare with both sigs to see which one it is.
    // I could just compare a direct byte ptr instead of each header variable
    // But its more readable and explicit
    const Wire::Msf2HeaderPrefix* Msf2Header = (const Wire::Msf2HeaderPrefix*)File.Bytes;
    const Wire::Msf7Superblock* Msf7Superb = (const Wire::Msf7Superblock*)File.Bytes;

    if (fastest_memcmp_ever(Msf2Header->Magic, szHdrMagic, sizeof(Msf2Header->Magic)) == 0) {
        // This is an Msf2 PDB.
        *Format = ContainerFormat::Msf2;
        return ParseStatus::Success;
    }
    else if (fastest_memcmp_ever(Msf7Superb->Magic, szBigHdrMagic, sizeof(Msf7Superb->Magic)) == 0) {
        // Msf7 PDB.
        *Format = ContainerFormat::Msf7;
        return ParseStatus::Success;
    }

    // Signature is not MSF 2 or 7, meaning this isn't a PDB version we support (or its just not a pdb).
    return ParseStatus::UnsupportedFormat;
}

ParseStatus
ParseMsf2Header(
    FileView File,
    Msf2HeaderInfo* Info
) noexcept

/*++

    Routine Description:

        Validates the MSF 2.00 header prefix and returns its block and
        directory metadata. The older format has its own block-map layout.

    Arguments:

        File - Entire readable PDB file and its actual byte count.

        Info - Receives validated metadata only on success.

    Return Value:

        Success for a valid MSF 2.00 header, otherwise a parse status. The
        initial stub returns NotImplemented.

--*/

{
    (void)File;
    (void)Info;
    return ParseStatus::NotImplemented;
}

ParseStatus
ParseMsf7Superblock(
    FileView File,
    Msf7SuperblockInfo* Info
) noexcept

/*++

    Routine Description:

        Validates the fixed MSF 7.00 superblock at the beginning of a
        bounded PDB file and returns its block and directory metadata.

    Arguments:

        File - Entire readable PDB file and its actual byte count.

        Info - Receives validated metadata only when parsing succeeds.

    Return Value:

        Success for a supported, valid superblock, otherwise a parse status
        describing the failure.

    Notes:

        This routine does not parse the block map, stream directory, or any
        PDB streams. Validate all declared offsets, counts, and products
        before using them to access File.Bytes.

--*/

{
    if (!File.Bytes || !Info) {
        return ParseStatus::InvalidArgument;
    }

    // Confirm struct size
    if (File.ByteCount < sizeof(Wire::Msf7Superblock)) {
        return ParseStatus::TruncatedFile;
    }

    // Validate sig
    if (fastest_memcmp_ever(File.Bytes, szBigHdrMagic, sizeof(Wire::Msf7Superblock::Magic)) != 0) {
        // Invalid Signature
        return ParseStatus::InvalidFormat;
    }

    const Wire::Msf7Superblock* Msf7Header = (const Wire::Msf7Superblock*)File.Bytes;
    Wire::U32 BlockSize = Msf7Header->BlockSize;
    Wire::U32 NumBlocks = Msf7Header->NumBlocks;
    Wire::U32 NumDirectoryBytes = Msf7Header->NumDirectoryBytes;
    Wire::U32 FreeBlockMapBlock = Msf7Header->FreeBlockMapBlock;
    Wire::U32 BlockMapAddr = Msf7Header->BlockMapAddr;

    // Validate these offsets and sizes before returning success
    // BlockSize must be a power of 2 (from 512), and not be above a 4KiB block
    // no bit tricks here people
    if (BlockSize != 512 && BlockSize != 1024 && BlockSize != 2048 && BlockSize != 4096) {
        return ParseStatus::InvalidFormat;
    }

    // A complete file must contain complete blocks, not incomplete ones
    if (File.ByteCount % BlockSize != 0) {
        return ParseStatus::InvalidFormat;
    }

    // validate the amount of blocks, is actually the amount in the file
    // use division so we dont overflow
    if (NumBlocks != File.ByteCount / BlockSize) {
        // Invalid number of blocks specified
        return ParseStatus::InvalidFormat;
    }

    // FreeBlockMapBlock is either 1 or 2 only.
    // Would you use > or != here, personally I want to be explicit
    if (FreeBlockMapBlock != 1 && FreeBlockMapBlock != 2) {
        return ParseStatus::InvalidFormat;
    }

    // Block 0 contains the superblock, blocks 1 and 2 are reserved for the
    // free block maps. 
    // The block map must name a later block in this file.
    if (BlockMapAddr < 3 || BlockMapAddr >= NumBlocks ||
        BlockMapAddr % BlockSize == 1 || BlockMapAddr % BlockSize == 2) {
        return ParseStatus::InvalidFormat;
    }

    // The stream directory begins with a 32-bit stream count. Its referenced
    // blocks are checked when the directory is parsed.
    if (NumDirectoryBytes < sizeof(Wire::U32) || NumDirectoryBytes > File.ByteCount) {
        return ParseStatus::InvalidFormat;
    }

    // All checks are good, now fill in the info and return success
    // We cant do *Info = *Msf7Header because they arent the same structs, if you didnt view the structs beforehand
    Info->BlockMapAddr = BlockMapAddr;
    Info->BlockSize = BlockSize;
    Info->FreeBlockMapBlock = FreeBlockMapBlock;
    Info->NumBlocks = NumBlocks;
    Info->NumDirectoryBytes = NumDirectoryBytes;
    return ParseStatus::Success;
}

ParseStatus ReadMsf7DirectoryBlockMap(
    FileView File,
    const Msf7SuperblockInfo& Header,
    Wire::U32* DirectoryBlocks,
    ViewSize DirectoryBlockCapacity,
    ViewSize* DirectoryBlockCount
) noexcept

/*++

    Routine Description:

        Reads the MSF 7.00 directory block map from File. Each map entry is a
        block number identifying one block of the stream directory. Validates
        those numbers and writes them to DirectoryBlocks. This routine does
        not read the directory blocks named by the map entries.

    Arguments:

        File - Entire readable PDB file and its actual byte count.

        Header - Metadata returned by ParseMsf7Superblock for this file.

        DirectoryBlocks - Caller owned array receiving validated block numbers.

        DirectoryBlockCapacity - Number of entries available in that array.

        DirectoryBlockCount - Receives the number of entries written on success,
                              or the required capacity on BufferTooSmall.

    Return Value:

        Success when all block numbers are validated and written.
        InvalidArgument for invalid inputs.
        BufferTooSmall when the array cannot hold every entry, 
        otherwise a status describing invalid or truncated file data.
        
        DirectoryBlocks must be ignored unless Success is returned.

--*/

{
    if (!File.Bytes || !DirectoryBlocks || !DirectoryBlockCount || !DirectoryBlockCapacity || !Header.BlockSize) {
        return ParseStatus::InvalidArgument;
    }

    // Calculate how many directory blocks are needed
    // Aligning up 1 block if there is a remainder
    ViewSize NeededBlocks = Header.NumDirectoryBytes / Header.BlockSize;

    // Check for remainder
    if (Header.NumDirectoryBytes % Header.BlockSize != 0) NeededBlocks++;

    // Comapre with the capacity of the blocks allocated by the caller
    if (DirectoryBlockCapacity < NeededBlocks) {
        // Not enough capacity in his array
        *DirectoryBlockCount = NeededBlocks;
        return ParseStatus::BufferTooSmall;
    }

    // Anti mult overflow, if this was x64 only then it wouldnt be necessary because UINT32_MAX^2 fits in a 64bit uint
    // but im making it a generic parser for all PDB files, so might as well includee 32bit windows. 
    if (Header.BlockMapAddr > File.ByteCount / Header.BlockSize) {
        return ParseStatus::InvalidFormat;
    }

    ViewSize StartingOffset = (ViewSize)Header.BlockMapAddr * Header.BlockSize;
    ViewSize Remaining = 0;

    if (StartingOffset < File.ByteCount) {
        // Anti underflow
        Remaining = File.ByteCount - StartingOffset;
    }

    // Validate the offset is inside of the file
    if (File.ByteCount <= StartingOffset) {
        // Nope, not inside of the file
        return ParseStatus::InvalidFormat;
    }

    if (NeededBlocks > Remaining / sizeof(Wire::U32)) {
        return ParseStatus::InvalidFormat;
    }

    // Read each little-endian block number without assuming U32 alignment.
    const Wire::U8* MapBytes = File.Bytes + StartingOffset;

    for (ViewSize i = 0; i < NeededBlocks; ++i) {
        // Entry[0-3] is the 4byte entry
        const Wire::U8* EntryBytes = MapBytes + i * sizeof(Wire::U32);

        // Decode each byte as little endian
        Wire::U32 Entry = ConstructToLittleEndian(EntryBytes);

        // The directory cannot occupy the superblock, a free-block-map block,
        // the block map itself, or a block beyond the file.
        if (!IsUsableMsf7BlockNumber(Entry, Header)) {
            return ParseStatus::InvalidFormat;
        }

        DirectoryBlocks[i] = Entry;
    }

    *DirectoryBlockCount = NeededBlocks;
    return ParseStatus::Success;
}

ParseStatus CopyMsf7StreamDirectory(
    FileView File,
    const Msf7SuperblockInfo& Header,
    const Wire::U32* DirectoryBlocks,
    ViewSize DirectoryBlockCount,
    Wire::U8* DirectoryBytes,
    ViewSize DirectoryCapacity
) noexcept

/*++

    Routine Description:

        Reconstructs the MSF 7.00 stream directory as a contiguous (contigious?) byte array
        from the physical blocks named in DirectoryBlocks. Copies exactly
        Header.NumDirectoryBytes bytes, including a partial final block. This
        routine copies the directory, it doesn't interpret stream entries or
        read the streams described by them.

    Arguments:

        File - Entire readable PDB file and its actual byte count.

        Header - Validated MSF 7.00 superblock metadata for File.

        DirectoryBlocks - Caller owned array of directory block numbers.

        DirectoryBlockCount - Number of entries in DirectoryBlocks, must equal the count implied by Header.NumDirectoryBytes.

        DirectoryBytes - Caller owned destination for the reconstructed bytes.

        DirectoryCapacity - Number of writable bytes in DirectoryBytes.

    Return Value:

        Success after copying the complete directory. 
        InvalidArgument for invalid inputs or an unexpected block count.
        BufferTooSmall when the destination cannot hold the directory 
        InvalidFormat when a directory block lies outside File.
        
        Ignore DirectoryBytes on failure.

--*/

{
    if (!File.Bytes || !File.ByteCount || !DirectoryBlocks || !DirectoryBytes || !DirectoryCapacity || !DirectoryBlockCount || !Header.BlockSize) {
        return ParseStatus::InvalidArgument;
    }

    // Make sure capacity is enough
    if (DirectoryCapacity < Header.NumDirectoryBytes) {
        // Caller did really not use the other functions above this one? Smh..
        return ParseStatus::BufferTooSmall;
    }

    // Make sure the caller gave the correct block count
    ViewSize CorrectBlockCount = Header.NumDirectoryBytes / Header.BlockSize;

    // If there is a remainder add one
    if (Header.NumDirectoryBytes % Header.BlockSize != 0) CorrectBlockCount++;

    if (DirectoryBlockCount != CorrectBlockCount) {
        // If you passed this if statement i hate you caller
        return ParseStatus::InvalidArgument;
    }

    // Each directory blocks arr entry is a physical block number
    // for the PDB file (which point to the streams)
    // Copy each block to the DirectoryBytes arr
    ViewSize Copied = 0;

    for (ViewSize i = 0; i < DirectoryBlockCount; i++) {
        // Grab the physical block number in the directory blocks
        const Wire::U32 DirectoryBlock = DirectoryBlocks[i];

        ViewSize SourceOffset = 0;
        if (!TryGetBlockStartOffset(
                DirectoryBlock, Header.BlockSize, File.ByteCount, &SourceOffset)) {
            return ParseStatus::InvalidFormat;
        }

        const Wire::U8* ByteStream = File.Bytes + SourceOffset;

        // Copy at most the BlockSize bytes OR the amount left in that block
        ViewSize Remaining = Header.NumDirectoryBytes - Copied;
        ViewSize ThisBlockBytes = Remaining < Header.BlockSize ? Remaining : Header.BlockSize;

        for (ViewSize j = 0; j < ThisBlockBytes; ++j) {
            DirectoryBytes[Copied + j] = ByteStream[j];
        }

        Copied += ThisBlockBytes;
    }

    // All copied! :)
    return ParseStatus::Success;
}

ParseStatus ParseMsf7StreamDirectory(
    const Wire::U8* DirectoryBytes,
    ViewSize DirectoryByteCount,
    const Msf7SuperblockInfo& Header,
    Msf7StreamInfo* Streams,
    ViewSize StreamCapacity,
    ViewSize* StreamCount
) noexcept

/*++

    Routine Description:

        Parser for the contiguous MSF 7.00 stream directory produced
        by CopyMsf7StreamDirectory. It will read the stream count, stream sizes,
        and each stream's physical block list, validate the complete directory,
        and describe each stream without copying stream contents. Blocklist
        offsets in Streams will refer to DirectoryBytes, so that buffer must
        remain alive while the descriptors are used.

    Arguments:

        DirectoryBytes - Contiguous stream directory bytes to parse.

        DirectoryByteCount - Number of readable bytes in DirectoryBytes expected to match Header.NumDirectoryBytes.

        Header - Validated MSF 7.00 superblock metadata for this directory.

        Streams - Caller owned array receiving stream descriptors. A null
                  pointer with zero StreamCapacity requests the required count.

        StreamCapacity - Number of descriptors available in Streams.

        StreamCount - Receives the number of Msf7StreamInfo elements required in BufferTooSmall, or the amount filled into the Streams arr if Success is returned.

    Return Value:

        Success only after the entire directory is validated
        BufferTooSmall when Streams lacks capacity, otherwise a status for
        invalid arguments or malformed directory data. 
        
        Ignore Streams unless Success is returned.

--*/

{
    if (!StreamCount || !DirectoryBytes || !DirectoryByteCount || !Header.NumDirectoryBytes || Header.NumDirectoryBytes != DirectoryByteCount || !Header.BlockSize) {
        return ParseStatus::InvalidArgument;
    }

    // If its a NULL stream but a valid stream capacity, its also invalid.
    // (vice versa too)
    if ((!Streams && StreamCapacity) || (Streams && !StreamCapacity)) {
        return ParseStatus::InvalidArgument;
    }

    // We need atleast 4 bytes to read
    if (DirectoryByteCount < 4) {
        return ParseStatus::TruncatedFile;
    }

    // The first 4 bytes of the directory is the number of streams.
    Wire::U32 NumStreams = ConstructToLittleEndian(DirectoryBytes);

    // The complete table must fit for the amount of streams
    // - 4 because of the 4 bytes taken to construct NumStreams
    // / 4 because each stream size is 4 bytes long
    if (NumStreams > (DirectoryByteCount - 4) / 4) {
        return ParseStatus::InvalidFormat;
    }

    // The block number lists begin after the stream count and all stream sizes.
    // Stream Directory is basically:
    // BYTES 0-3 = StreamCount U32
    // BYTES 4-NumStreams * 4 = 4 byte chunks of StreamSize U32
    // After allat - the streams logical block list
    const ViewSize BlockListStart = sizeof(Wire::U32) + (ViewSize)NumStreams * sizeof(Wire::U32);
    const ViewSize AvailableBlocks = (DirectoryByteCount - BlockListStart) / sizeof(Wire::U32);

    // Count the block number entries required by all streams
    ViewSize TotalBlocks = 0;

    for (ViewSize i = 0; i < NumStreams; i++) {
        Wire::U32 StreamSize = ConstructToLittleEndian(DirectoryBytes + 4 + (i * 4));

        // Empty and absent streams have no block number entries
        if (StreamSize == 0 || StreamSize == (Wire::U32)-1) {
            continue;
        }

        ViewSize StreamBlocks = StreamSize / Header.BlockSize;

        // A partially filled final block still needs one block number.
        if (StreamSize % Header.BlockSize != 0) StreamBlocks++;

        // Bound the total before adding, so it cannot exceed the directory or overflow.
        if (StreamBlocks > AvailableBlocks - TotalBlocks) {
            return ParseStatus::InvalidFormat;
        }

        TotalBlocks += StreamBlocks;
    }

    // Make sure we dont have any entries after the loop
    // that would mean there is another block added into the end
    // that the loop wasnt accounting for (becase NumStreams was wrong OR, the declared StreamSizes were wrong)
    ViewSize Remaining = DirectoryByteCount - BlockListStart;

    // % 4 to catch trailing bytes, since / 4 would discard them
    // dont we all love mathematics! (i dont)
    if (Remaining % 4 != 0 || Remaining / 4 != TotalBlocks) {
        // Not divisible by 4 (extra bytes
        return ParseStatus::InvalidFormat;
    }

    // Validate each physical block number before publishing stream descriptors.
    for (ViewSize i = 0; i < TotalBlocks; i++) {
        Wire::U32 BlockEntry = ConstructToLittleEndian((const Wire::U8*)(DirectoryBytes + BlockListStart + i * 4));

        if (!IsUsableMsf7BlockNumber(BlockEntry, Header)) {
            // Invalid block entry in one of the streams
            return ParseStatus::InvalidFormat;
        }
    }

    *StreamCount = NumStreams;

    if (!Streams || StreamCapacity < NumStreams) {
        // Caller either wants to know the capacity of the array (so he can create it with the correct one) (Streams == NULL)
        // Or the capacity he gave is not enough, and we would overflow it on fill (StreamCapacity < NumStreams)
        return ParseStatus::BufferTooSmall;
    }

    // Fill in the Streams array now
    ViewSize BlockListCursor = BlockListStart;

    for (ViewSize i = 0; i < NumStreams; i++) {
        Msf7StreamInfo Info;

        // This is basically exactly like the loop above (line 577), just that here we actually fill in
        // the array, instead of doing annoying but must have validation checks
        Info.ByteSize = ConstructToLittleEndian(DirectoryBytes + 4 + (i * 4));

        // Skip over empty/reserved ones
        if (Info.ByteSize == 0 || Info.ByteSize == (Wire::U32)-1) {
            Info.BlockCount = 0;
            Info.DirectoryBlockListByteOffset = 0;
            Streams[i] = Info;
            continue;
        }
        
        // A lot of Info. dereferences here (yes its a pointer to the stack struct)
        // but im sure the compiler will optimize this, right?
        ViewSize StreamBlocks = Info.ByteSize / Header.BlockSize;

        // A partially filled final block still needs one block number.
        if (Info.ByteSize % Header.BlockSize != 0) StreamBlocks++;

        Info.BlockCount = StreamBlocks;

        // The next entries in the directory belong to this stream.
        Info.DirectoryBlockListByteOffset = BlockListCursor;
        BlockListCursor += StreamBlocks * sizeof(Wire::U32);
        Streams[i] = Info;
    }

    // finally, i hate this function
    return ParseStatus::Success;
}

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
) noexcept

/*++

    Routine Description:

        Copies a requested byte range from one MSF 7.00 stream into a caller
        owned buffer. Stream byte offsets are resolved through the stream's
        block number list in DirectoryBytes, stream contents are read from
        File. The routine does not allocate memory.

    Arguments:

        File - Complete readable MSF file.

        Header - Validated MSF 7.00 superblock metadata for File.

        DirectoryBytes - Contiguous stream directory bytes that remain alive
                         while Stream is used.

        DirectoryByteCount - Number of readable bytes in DirectoryBytesm, must equal Header.NumDirectoryBytes.

        Stream - Descriptor produced by ParseMsf7StreamDirectory.

        StreamOffset - First byte to copy, relative to the start of Stream.

        BytesToCopy - Number of stream bytes requested.

        Destination - Non-null caller owned output buffer.

        DestinationCapacity - Number of writable bytes in Destination.

    Return Value:

        InvalidArgument for inconsistent inputs, an absent stream, or a range outside the stream. 
        BufferTooSmall if the output lacks capacity.

--*/

{
    if (!File.Bytes || !File.ByteCount || !DirectoryBytes || !Destination ||
        !DirectoryByteCount || !Header.BlockSize ||
        DirectoryByteCount != Header.NumDirectoryBytes ||
        Stream.ByteSize == static_cast<Wire::U32>(-1)) {
        return ParseStatus::InvalidArgument;
    }

    if (StreamOffset > Stream.ByteSize ||
        BytesToCopy > static_cast<ViewSize>(Stream.ByteSize) - StreamOffset) {
        return ParseStatus::InvalidArgument;
    }

    if (DestinationCapacity < BytesToCopy) {
        return ParseStatus::BufferTooSmall;
    }

    // Each logical stream block needs one four byte block number in the directory.
    if (Stream.BlockCount != BYTES_TO_BLOCKS(Stream.ByteSize, Header.BlockSize)) {
        return ParseStatus::InvalidFormat;
    }

    if (Stream.DirectoryBlockListByteOffset > DirectoryByteCount) {
        return ParseStatus::InvalidFormat;
    }

    const ViewSize BlockListBytesRemaining =
        DirectoryByteCount - Stream.DirectoryBlockListByteOffset;
    if (Stream.BlockCount > BlockListBytesRemaining / sizeof(Wire::U32)) {
        return ParseStatus::InvalidFormat;
    }

    // Begin copying the stream to the buffer
    ViewSize Copied = 0;

    while (Copied < BytesToCopy) {
        ViewSize LogicalOffset = StreamOffset + Copied;
        ViewSize LogicalBlockIndex = LogicalOffset / Header.BlockSize;
        ViewSize WithinBlock = LogicalOffset % Header.BlockSize;

        // Read from the stream's bytes to get which block number to read the bytes from
        // * sizeof(U32) because we need to convert entries to byte offset (LogicalBlockIndex counts block entries)
        Wire::U32 BlockNumber = ConstructToLittleEndian((const Wire::U8*)(DirectoryBytes + Stream.DirectoryBlockListByteOffset + LogicalBlockIndex * sizeof(Wire::U32)));

        // Get the offset to add to file start pointer
        ViewSize BlockOffset = 0;

        if (!IsUsableMsf7BlockNumber(BlockNumber, Header) || !TryGetBlockStartOffset(BlockNumber, Header.BlockSize, File.ByteCount, &BlockOffset)) {
            // Malformed block number
            return ParseStatus::InvalidFormat;
        }

        // Read the block bytes from the file
        // Start i from the place we are within the block
        for (ViewSize i = WithinBlock; i < Header.BlockSize && Copied < BytesToCopy; Copied++, i++) {
            Destination[Copied] = File.Bytes[BlockOffset + i];
        }
    }

    // i like writing this sentence of code
    return ParseStatus::Success;
}

} // namespace MSF
} // namespace MatanelPDB
