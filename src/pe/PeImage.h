#pragma once

// SPDX-License-Identifier: Apache-2.0

namespace MatanelPDB {
namespace PEUtils {

static_assert(sizeof(unsigned int) == 4, "PE fields require 32-bit unsigned int");

// cool trick below, decltype(sizeof(0)), is basically size_t
using ViewSize = decltype(sizeof(0));

// allat below is a Private PE layout, I basically want to run user mode tests as a self contained binary
// without putting in the wdm header or Windows.h header when both of them are supposed to run this
// sure I could guard with an ifdef, but you can just pretend like this sentence doesnt exist, and also because portability is good!
namespace Wire {

using U8 = unsigned char;
using U16 = unsigned short;
using U32 = unsigned int;
using U64 = unsigned long long;
using I32 = int;

static_assert(sizeof(U8) == 1 && sizeof(U16) == 2 && sizeof(U32) == 4 &&
              sizeof(U64) == 8 && sizeof(I32) == 4,
              "Unsupported PE field widths");

#pragma pack(push, 1)

struct DosHeader {
    U16 e_magic;
    U16 e_cblp;
    U16 e_cp;
    U16 e_crlc;
    U16 e_cparhdr;
    U16 e_minalloc;
    U16 e_maxalloc;
    U16 e_ss;
    U16 e_sp;
    U16 e_csum;
    U16 e_ip;
    U16 e_cs;
    U16 e_lfarlc;
    U16 e_ovno;
    U16 e_res[4];
    U16 e_oemid;
    U16 e_oeminfo;
    U16 e_res2[10];
    I32 e_lfanew;
};

struct CoffFileHeader {
    U16 Machine;
    U16 NumberOfSections;
    U32 TimeDateStamp;
    U32 PointerToSymbolTable;
    U32 NumberOfSymbols;
    U16 SizeOfOptionalHeader;
    U16 Characteristics;
};

// PE32+ fields before the variable-length data-directory array.
struct OptionalHeader64Prefix {
    U16 Magic;
    U8 MajorLinkerVersion;
    U8 MinorLinkerVersion;
    U32 SizeOfCode;
    U32 SizeOfInitializedData;
    U32 SizeOfUninitializedData;
    U32 AddressOfEntryPoint;
    U32 BaseOfCode;
    U64 ImageBase;
    U32 SectionAlignment;
    U32 FileAlignment;
    U16 MajorOperatingSystemVersion;
    U16 MinorOperatingSystemVersion;
    U16 MajorImageVersion;
    U16 MinorImageVersion;
    U16 MajorSubsystemVersion;
    U16 MinorSubsystemVersion;
    U32 Win32VersionValue;
    U32 SizeOfImage;
    U32 SizeOfHeaders;
    U32 CheckSum;
    U16 Subsystem;
    U16 DllCharacteristics;
    U64 SizeOfStackReserve;
    U64 SizeOfStackCommit;
    U64 SizeOfHeapReserve;
    U64 SizeOfHeapCommit;
    U32 LoaderFlags;
    U32 NumberOfRvaAndSizes;
};

struct DataDirectory {
    U32 VirtualAddress;
    U32 Size;
};

struct DebugDirectory {
    U32 Characteristics;
    U32 TimeDateStamp;
    U16 MajorVersion;
    U16 MinorVersion;
    U32 Type;
    U32 SizeOfData;
    U32 AddressOfRawData;
    U32 PointerToRawData;
};

#pragma pack(pop)

static_assert(sizeof(DosHeader) == 64, "Unexpected DOS header layout");
static_assert(sizeof(CoffFileHeader) == 20, "Unexpected COFF header layout");
static_assert(sizeof(OptionalHeader64Prefix) == 112, "Unexpected PE32+ prefix layout");
static_assert(sizeof(DataDirectory) == 8, "Unexpected data-directory layout");
static_assert(sizeof(DebugDirectory) == 28, "Unexpected debug-directory layout");

constexpr U16 DosSignature = 0x5A4D;
constexpr U32 PeSignature = 0x00004550;
constexpr U16 Pe32PlusMagic = 0x020B;
constexpr U32 DebugDirectoryIndex = 6;
constexpr U32 CodeViewDebugType = 2;

} // namespace (copper) Wire

struct ImageView {
    const unsigned char* Bytes;
    ViewSize ByteCount;
};

struct HeaderInfo {
    unsigned int SizeOfImage;
    unsigned int DebugDirectoryRva;
    unsigned int DebugDirectorySize;
};

enum class ParseStatus : unsigned char {
    Success,
    InvalidArgument,
    TruncatedImage,
    InvalidFormat,
    UnsupportedFormat,
    NotImplemented,
    NotFound
};

// Parses PE Debug header to return Rva and Size
ParseStatus ParseDebugHeader(ImageView Image, HeaderInfo* Info) noexcept;
ParseStatus FindCodeViewDebugEntry(ImageView DebugDirectoryTable, Wire::DebugDirectory* Entry) noexcept;

}
}
