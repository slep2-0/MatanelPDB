// SPDX-License-Identifier: Apache-2.0
// Standalone, non-PnP test driver. This file is not part of the public API.

#include "KernelImage.h"
#include "KernelSupport.h"
#include "pe/PeImage.h"
#include "pe/Rsds.h"

namespace {

constexpr ULONG DebugTablePoolTag = 'DPDM';
constexpr ULONG MaxDiagnosticDebugTableSize = 64 * 1024;
constexpr ULONG CodeViewPoolTag = 'CVPM';
constexpr ULONG MaxDiagnosticCodeViewSize = 4 * 1024;

VOID DiagnosticUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[MatanelPDB] diagnostic unloaded\n");
}

VOID InspectCodeViewPayload(
    const MatanelPDB::KernelUtils::LoadedImage& Image,
    const MatanelPDB::PEUtils::Wire::DebugDirectory& Entry)
{
    if (Entry.SizeOfData < 4 || Entry.SizeOfData > MaxDiagnosticCodeViewSize ||
        Entry.AddressOfRawData == 0 || Entry.AddressOfRawData >= Image.ImageSize ||
        Entry.SizeOfData > Image.ImageSize - Entry.AddressOfRawData) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] CodeView payload has no usable mapped-image range; file offset=0x%08X\n",
            Entry.PointerToRawData);
        return;
    }

    void* const payload = MatanelAlloc(
        MatanelPDB::KernelUtils::MATANEL_ALLOCATION::NonPaged,
        Entry.SizeOfData, CodeViewPoolTag);
    if (payload == nullptr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] CodeView payload allocation failed\n");
        return;
    }

    MM_COPY_ADDRESS source = {};
    source.VirtualAddress = static_cast<unsigned char*>(Image.ImageBase)
        + Entry.AddressOfRawData;
    SIZE_T copied = 0;
    const NTSTATUS copyStatus = MmCopyMemory(
        payload, source, Entry.SizeOfData, MM_COPY_MEMORY_VIRTUAL, &copied);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[MatanelPDB] CodeView payload copy status=0x%08X copied=%Iu/%u\n",
        static_cast<ULONG>(copyStatus), copied, Entry.SizeOfData);

    if (NT_SUCCESS(copyStatus) && copied == Entry.SizeOfData) {
        const unsigned char* const bytes = static_cast<const unsigned char*>(payload);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] CodeView first four bytes=%02X %02X %02X %02X\n",
            static_cast<unsigned int>(bytes[0]), static_cast<unsigned int>(bytes[1]),
            static_cast<unsigned int>(bytes[2]), static_cast<unsigned int>(bytes[3]));

        const MatanelPDB::PEUtils::ImageView payloadView = {bytes, copied};
        MatanelPDB::PEUtils::RsdsInfo identity = {};
        const MatanelPDB::PEUtils::ParseStatus parseStatus =
            MatanelPDB::PEUtils::ParseRsds(payloadView, &identity);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] ParseRsds status=%u\n",
            static_cast<unsigned int>(parseStatus));
        if (parseStatus == MatanelPDB::PEUtils::ParseStatus::Success) {
            GUID guid = {};
            RtlCopyMemory(&guid, identity.Guid, sizeof(guid));
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[MatanelPDB] PDB GUID=%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X age=%u\n",
                guid.Data1, static_cast<unsigned int>(guid.Data2),
                static_cast<unsigned int>(guid.Data3),
                static_cast<unsigned int>(guid.Data4[0]),
                static_cast<unsigned int>(guid.Data4[1]),
                static_cast<unsigned int>(guid.Data4[2]),
                static_cast<unsigned int>(guid.Data4[3]),
                static_cast<unsigned int>(guid.Data4[4]),
                static_cast<unsigned int>(guid.Data4[5]),
                static_cast<unsigned int>(guid.Data4[6]),
                static_cast<unsigned int>(guid.Data4[7]), identity.Age);
            if (identity.PdbNameLength > 0 && identity.PdbNameLength <= 256) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[MatanelPDB] PDB name=%s\n", identity.PdbName);
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[MatanelPDB] PDB name length=%Iu (not printed)\n",
                    identity.PdbNameLength);
            }
        }
    }

    ExFreePoolWithTag(payload, CodeViewPoolTag);
}

VOID InspectDebugDirectory(
    const MatanelPDB::KernelUtils::LoadedImage& Image,
    const MatanelPDB::PEUtils::HeaderInfo& Headers)
{
    if (Headers.DebugDirectorySize < sizeof(MatanelPDB::PEUtils::Wire::DebugDirectory) ||
        Headers.DebugDirectorySize > MaxDiagnosticDebugTableSize ||
        Headers.DebugDirectorySize % sizeof(MatanelPDB::PEUtils::Wire::DebugDirectory) != 0 ||
        Headers.DebugDirectoryRva >= Image.ImageSize ||
        Headers.DebugDirectorySize > Image.ImageSize - Headers.DebugDirectoryRva) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] debug table range/size rejected\n");
        return;
    }

    void* const table = MatanelAlloc(
        MatanelPDB::KernelUtils::MATANEL_ALLOCATION::NonPaged,
        Headers.DebugDirectorySize, DebugTablePoolTag);
    if (table == nullptr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] debug table allocation failed\n");
        return;
    }

    MM_COPY_ADDRESS source = {};
    source.VirtualAddress = static_cast<unsigned char*>(Image.ImageBase)
        + Headers.DebugDirectoryRva;
    SIZE_T copied = 0;
    const NTSTATUS copyStatus = MmCopyMemory(
        table, source, Headers.DebugDirectorySize, MM_COPY_MEMORY_VIRTUAL, &copied);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[MatanelPDB] debug table copy status=0x%08X copied=%Iu/%u\n",
        static_cast<ULONG>(copyStatus), copied, Headers.DebugDirectorySize);

    if (NT_SUCCESS(copyStatus) && copied == Headers.DebugDirectorySize) {
        const MatanelPDB::PEUtils::ImageView tableView = {
            static_cast<const unsigned char*>(table), copied
        };
        MatanelPDB::PEUtils::Wire::DebugDirectory entry = {};
        const MatanelPDB::PEUtils::ParseStatus findStatus =
            MatanelPDB::PEUtils::FindCodeViewDebugEntry(tableView, &entry);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] FindCodeViewDebugEntry status=%u\n",
            static_cast<unsigned int>(findStatus));
        if (findStatus == MatanelPDB::PEUtils::ParseStatus::Success) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[MatanelPDB] CodeView type=%u data size=0x%08X RVA=0x%08X file offset=0x%08X\n",
                entry.Type, entry.SizeOfData, entry.AddressOfRawData,
                entry.PointerToRawData);
            InspectCodeViewPayload(Image, entry);
        }
    }

    ExFreePoolWithTag(table, DebugTablePoolTag);
}

}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DiagnosticUnload;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[MatanelPDB] diagnostic loaded; querying ntoskrnl\n");

    MatanelPDB::KernelUtils::LoadedImage image = {};
    const NTSTATUS status = MatanelPDB::KernelUtils::GetNTOSKrnl(&image);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[MatanelPDB] GetNTOSKrnl status=0x%08X base=%p size=0x%08lX\n",
        static_cast<ULONG>(status), image.ImageBase, image.ImageSize);

    if (NT_SUCCESS(status)) {
        const MatanelPDB::PEUtils::ImageView view = {
            static_cast<const unsigned char*>(image.ImageBase),
            image.ImageSize
        };
        MatanelPDB::PEUtils::HeaderInfo headers = {};
        const MatanelPDB::PEUtils::ParseStatus parseStatus =
            MatanelPDB::PEUtils::ParseDebugHeader(view, &headers);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[MatanelPDB] ParseDebugHeader status=%u\n",
            static_cast<unsigned int>(parseStatus));
        if (parseStatus == MatanelPDB::PEUtils::ParseStatus::Success) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[MatanelPDB] PE size=0x%08X debug RVA=0x%08X size=0x%08X\n",
                headers.SizeOfImage, headers.DebugDirectoryRva,
                headers.DebugDirectorySize);
            InspectDebugDirectory(image, headers);
        }
    }

    // Keep the test driver loaded even when the query fails, so it can be
    // stopped normally after the status has been captured.
    return STATUS_SUCCESS;
}
