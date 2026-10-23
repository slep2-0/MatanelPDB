// SPDX-License-Identifier: Apache-2.0
// Host-side smoke tests for the portable PE header parser.

#include "pe/PeImage.h"
#include "pe/Rsds.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

using namespace MatanelPDB::PEUtils;

namespace {

constexpr unsigned int NtOffset = 0x80;
constexpr unsigned int OptionalOffset = NtOffset + 4 + sizeof(Wire::CoffFileHeader);
constexpr unsigned int DebugEntryOffset = OptionalOffset + sizeof(Wire::OptionalHeader64Prefix)
    + Wire::DebugDirectoryIndex * sizeof(Wire::DataDirectory);

template <typename T>
void Put(unsigned char* bytes, unsigned int offset, const T& value)
{
    std::memcpy(bytes + offset, &value, sizeof(value));
}

bool Expect(const char* name, ImageView view, ParseStatus expected)
{
    HeaderInfo info = {};
    const ParseStatus actual = ParseDebugHeader(view, &info);
    if (actual != expected) {
        std::printf("FAIL %s: status %u, expected %u\n", name,
            static_cast<unsigned int>(actual), static_cast<unsigned int>(expected));
        return false;
    }
    if (actual == ParseStatus::Success &&
        (info.SizeOfImage != 0x1000 || info.DebugDirectoryRva != 0x400 ||
         info.DebugDirectorySize != sizeof(Wire::DebugDirectory))) {
        std::printf("FAIL %s: output fields do not match\n", name);
        return false;
    }
    std::printf("PASS %s\n", name);
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    unsigned char bytes[512] = {};
    Wire::DosHeader dos = {};
    dos.e_magic = Wire::DosSignature;
    dos.e_lfanew = NtOffset;
    Put(bytes, 0, dos);
    Put(bytes, NtOffset, Wire::PeSignature);

    Wire::CoffFileHeader coff = {};
    coff.SizeOfOptionalHeader = 0xF0;
    Put(bytes, NtOffset + 4, coff);

    Wire::OptionalHeader64Prefix optional = {};
    optional.Magic = Wire::Pe32PlusMagic;
    optional.SizeOfImage = 0x1000;
    optional.NumberOfRvaAndSizes = 16;
    Put(bytes, OptionalOffset, optional);

    Wire::DataDirectory debug = {};
    debug.VirtualAddress = 0x400;
    debug.Size = sizeof(Wire::DebugDirectory);
    Put(bytes, DebugEntryOffset, debug);

    bool passed = true;
    passed &= Expect("valid", {bytes, sizeof(bytes)}, ParseStatus::Success);
    passed &= Expect("short DOS header", {bytes, 63}, ParseStatus::TruncatedImage);
    passed &= Expect("short NT signature", {bytes, NtOffset + 3}, ParseStatus::TruncatedImage);

    bytes[0] = 0;
    passed &= Expect("bad DOS signature", {bytes, sizeof(bytes)}, ParseStatus::InvalidFormat);
    bytes[0] = 'M';

    dos.e_lfanew = -1;
    Put(bytes, 0, dos);
    passed &= Expect("negative NT offset", {bytes, sizeof(bytes)}, ParseStatus::InvalidFormat);
    dos.e_lfanew = NtOffset;
    Put(bytes, 0, dos);

    optional.NumberOfRvaAndSizes = 6;
    Put(bytes, OptionalOffset, optional);
    passed &= Expect("missing debug entry", {bytes, sizeof(bytes)}, ParseStatus::InvalidFormat);
    optional.NumberOfRvaAndSizes = 16;
    Put(bytes, OptionalOffset, optional);

    coff.SizeOfOptionalHeader = 167;
    Put(bytes, NtOffset + 4, coff);
    passed &= Expect("short optional directory", {bytes, sizeof(bytes)}, ParseStatus::TruncatedImage);
    coff.SizeOfOptionalHeader = 0xF0;
    Put(bytes, NtOffset + 4, coff);

    debug.Size = 0xD00;
    Put(bytes, DebugEntryOffset, debug);
    passed &= Expect("debug range past image", {bytes, sizeof(bytes)}, ParseStatus::InvalidFormat);
    debug.Size = sizeof(Wire::DebugDirectory);
    Put(bytes, DebugEntryOffset, debug);

    unsigned char debugTable[3 * sizeof(Wire::DebugDirectory)] = {};
    Wire::DebugDirectory codeView = {};
    codeView.Type = Wire::CodeViewDebugType;
    codeView.SizeOfData = 32;
    Put(debugTable, sizeof(Wire::DebugDirectory), codeView);

    Wire::DebugDirectory found = {};
    const ParseStatus foundStatus = FindCodeViewDebugEntry(
        {debugTable, sizeof(debugTable)}, &found);
    passed &= foundStatus == ParseStatus::Success &&
        found.Type == Wire::CodeViewDebugType && found.SizeOfData == 32;
    std::printf("%s CodeView in three-entry table\n", foundStatus == ParseStatus::Success &&
        found.Type == Wire::CodeViewDebugType && found.SizeOfData == 32 ? "PASS" : "FAIL");
    passed &= FindCodeViewDebugEntry({debugTable, 27}, &found) == ParseStatus::InvalidFormat;
    std::printf("%s partial debug entry\n",
        FindCodeViewDebugEntry({debugTable, 27}, &found) == ParseStatus::InvalidFormat ? "PASS" : "FAIL");
    codeView.Type = 0;
    Put(debugTable, sizeof(Wire::DebugDirectory), codeView);
    passed &= FindCodeViewDebugEntry({debugTable, sizeof(debugTable)}, &found) == ParseStatus::NotFound;
    std::printf("%s no CodeView entry\n",
        FindCodeViewDebugEntry({debugTable, sizeof(debugTable)}, &found) == ParseStatus::NotFound ? "PASS" : "FAIL");

    unsigned char rsds[37] = {};
    Wire::RsdsPrefix rsdsPrefix = {};
    std::memcpy(rsdsPrefix.Signature, Wire::RsdsSignature, sizeof(Wire::RsdsSignature));
    for (unsigned int i = 0; i < sizeof(rsdsPrefix.Guid); ++i) {
        rsdsPrefix.Guid[i] = static_cast<unsigned char>(i);
    }
    rsdsPrefix.Age = 3;
    Put(rsds, 0, rsdsPrefix);
    std::memcpy(rsds + sizeof(rsdsPrefix), "ntkrnlmp.pdb", 13);

    RsdsInfo identity = {};
    ParseStatus rsdsStatus = ParseRsds({rsds, sizeof(rsds)}, &identity);
    const bool validRsds = rsdsStatus == ParseStatus::Success && identity.Age == 3 &&
        identity.Guid[15] == 15 && identity.PdbNameLength == 12 &&
        std::memcmp(identity.PdbName, "ntkrnlmp.pdb", 12) == 0;
    passed &= validRsds;
    std::printf("%s valid RSDS\n", validRsds ? "PASS" : "FAIL");

    const bool shortRsds = ParseRsds({rsds, sizeof(Wire::RsdsPrefix)}, &identity)
        == ParseStatus::TruncatedImage;
    passed &= shortRsds;
    std::printf("%s short RSDS\n", shortRsds ? "PASS" : "FAIL");

    rsds[0] = 0;
    const bool badRsdsSignature = ParseRsds({rsds, sizeof(rsds)}, &identity)
        == ParseStatus::InvalidFormat;
    passed &= badRsdsSignature;
    std::printf("%s bad RSDS signature\n", badRsdsSignature ? "PASS" : "FAIL");
    rsds[0] = 'R';

    rsds[sizeof(rsds) - 1] = 'X';
    const bool missingNameTerminator = ParseRsds({rsds, sizeof(rsds)}, &identity)
        == ParseStatus::InvalidFormat;
    passed &= missingNameTerminator;
    std::printf("%s missing RSDS name terminator\n", missingNameTerminator ? "PASS" : "FAIL");
    rsds[sizeof(rsds) - 1] = 0;

    rsds[sizeof(rsdsPrefix)] = 0;
    const bool emptyName = ParseRsds({rsds, sizeof(rsdsPrefix) + 1}, &identity)
        == ParseStatus::InvalidFormat;
    passed &= emptyName;
    std::printf("%s empty RSDS name\n", emptyName ? "PASS" : "FAIL");
    rsds[sizeof(rsdsPrefix)] = 'n';

    if (argc > 1) {
        std::ifstream file(argv[1], std::ios::binary);
        std::vector<unsigned char> image((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        if (!file || image.empty()) {
            std::printf("FAIL open PE file\n");
            passed = false;
        } else {
            HeaderInfo info = {};
            const ParseStatus status = ParseDebugHeader({image.data(), image.size()}, &info);
            std::printf("real PE: status=%u image=0x%X debug RVA=0x%X size=0x%X\n",
                static_cast<unsigned int>(status), info.SizeOfImage,
                info.DebugDirectoryRva, info.DebugDirectorySize);
            passed &= status == ParseStatus::Success;
        }
    }

    return passed ? 0 : 1;
}
