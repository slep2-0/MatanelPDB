// SPDX-License-Identifier: Apache-2.0

#include "PeImage.h"

namespace MatanelPDB {
namespace PEUtils {

// Consume a sequential byte range only when it fits. Failure leaves Remaining unchanged.
static inline bool TryConsume(ViewSize& Remaining, ViewSize ByteCount) noexcept
{
    if (ByteCount > Remaining) {
        return false;
    }

    Remaining -= ByteCount;
    return true;
}

ParseStatus
ParseDebugHeader(
    ImageView Image,
    HeaderInfo* Info
) noexcept

/*++

    Routine Description:

        Validates the PE headers in a bounded image view and returns the
        image size and debug directory location recorded in the headers.

    Arguments:

        Image - Bytes containing the PE headers and the number of readable bytes.

        Info - Receives header information only when parsing succeeds.

    Return Value:

        A parse status describing success or the reason the headers cannot
        be used.

    Notes:

        Routine does not operate on the RVAs! You must do so yourself.

--*/

{
    // Validate arguments and the minimum number of bytes needed for a DOS header.
    if (Info == nullptr || Image.Bytes == nullptr) {
        return ParseStatus::InvalidArgument;
    }

    ViewSize Remaining = Image.ByteCount;
    if (!TryConsume(Remaining, sizeof(Wire::DosHeader))) {
        return ParseStatus::TruncatedImage;
    }

    // Validate MZ header sig
    const Wire::DosHeader* DosHeader = (const Wire::DosHeader*)Image.Bytes;
    if (DosHeader->e_magic != Wire::DosSignature) {
        // Bad DOS, this is probably not a PE header
        return ParseStatus::InvalidFormat;
    }

    // Validate NT lfanew offset.
    Wire::I32 PEOffset = DosHeader->e_lfanew;
    if (PEOffset < 0 || PEOffset > Image.ByteCount) {
        return ParseStatus::InvalidFormat;
    }

    // Set remaining now from our PE header.
    Remaining = Image.ByteCount - PEOffset;

    // Attempt to consume 4 bytes for the header
    if (!TryConsume(Remaining, sizeof(Wire::PeSignature))) {
        return ParseStatus::TruncatedImage;
    }

    // Consumed, now validate this is an actual PE header
    const unsigned char* PESig = (const unsigned char*)Image.Bytes + PEOffset;
    if (PESig[0] != 'P' || PESig[1] != 'E' || PESig[2] != '\0' || PESig[3] != '\0') {
        return ParseStatus::InvalidFormat;
    }

    // Validate if we can read a whole coff header
    if (!TryConsume(Remaining, sizeof(Wire::CoffFileHeader))) {
        return ParseStatus::TruncatedImage;
    }

    // Good, directly after the sig is the coff header
    const Wire::CoffFileHeader* CoffHeader = (const Wire::CoffFileHeader*)(PESig + sizeof(Wire::PeSignature));

    // See if the NT header fits
    Wire::U16 SizeOpt = CoffHeader->SizeOfOptionalHeader;

    if (SizeOpt < sizeof(Wire::OptionalHeader64Prefix)) {
        return ParseStatus::InvalidFormat;
    }

    if (!TryConsume(Remaining, SizeOpt)) {
        return ParseStatus::TruncatedImage;
    }

    // Validate the PE32 Magic
    const Wire::OptionalHeader64Prefix* OptHeader = (const Wire::OptionalHeader64Prefix*)((const Wire::U8*)CoffHeader + sizeof(Wire::CoffFileHeader));
    if (OptHeader->Magic != Wire::Pe32PlusMagic ) {
        return ParseStatus::InvalidFormat;
    }

    // Validate a debug directory exists, in the OptionalHeader the debug directory
    // is entry 6 (entry 0 is there), so if there are 6 or less entries (no debug entry), reject
    if (OptHeader->NumberOfRvaAndSizes <= Wire::DebugDirectoryIndex) {
        return ParseStatus::InvalidFormat;
    }

    if (SizeOpt < sizeof(Wire::OptionalHeader64Prefix) + (Wire::DebugDirectoryIndex + 1) * sizeof(Wire::DataDirectory)) {
        // Header size is less than the amount of directories combined
        return ParseStatus::TruncatedImage;
    }

    const Wire::DataDirectory* DataDir = (const Wire::DataDirectory*)((const Wire::U8*)OptHeader + sizeof(Wire::OptionalHeader64Prefix) + Wire::DebugDirectoryIndex * sizeof(Wire::DataDirectory));

    // Validate the 3 ints before we return success
    if (OptHeader->SizeOfImage == 0 || DataDir->Size == 0 || DataDir->VirtualAddress == 0) {
        return ParseStatus::InvalidFormat;
    }

    if (DataDir->VirtualAddress >= OptHeader->SizeOfImage) {
        return ParseStatus::InvalidFormat;
    }

    if (DataDir->Size > OptHeader->SizeOfImage - DataDir->VirtualAddress) {
        // Data directory size is above the image itself
        return ParseStatus::InvalidFormat;
    }

    // VirtualAddress is actually an RVA.
    // Finally fill in all the fields and mov eax, 0; RET;
    Info->DebugDirectoryRva = DataDir->VirtualAddress;
    Info->DebugDirectorySize = DataDir->Size;
    Info->SizeOfImage = OptHeader->SizeOfImage;

    return ParseStatus::Success;
}

ParseStatus 
FindCodeViewDebugEntry(
    ImageView DebugDirectoryTable,
    Wire::DebugDirectory* Entry
) noexcept

// placeroutinedesc

{
    if (!Entry || !DebugDirectoryTable.Bytes) {
        return ParseStatus::InvalidArgument;
    }

    // Require the table to have atleast 1 entry, and a multiple of the struct so there wont be half structs
    if (DebugDirectoryTable.ByteCount < sizeof(Wire::DebugDirectory) || DebugDirectoryTable.ByteCount % sizeof(Wire::DebugDirectory) != 0) {
        return ParseStatus::InvalidFormat;
    }

    // Start iterating over the table until we found CodeView
    for (ViewSize i = 0; i < DebugDirectoryTable.ByteCount / sizeof(Wire::DebugDirectory); i++) {
        const Wire::DebugDirectory* Directory = (const Wire::DebugDirectory*)((const Wire::U8*)DebugDirectoryTable.Bytes + i * sizeof(Wire::DebugDirectory));

        // If this is codeview, we have found it
        if (Directory->Type == Wire::CodeViewDebugType) {
            *Entry = *Directory;
            return ParseStatus::Success;
        }
    }

    // Did not found the CodedView table
    return ParseStatus::NotFound;
}

}
}
