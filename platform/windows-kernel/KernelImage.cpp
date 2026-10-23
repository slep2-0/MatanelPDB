// SPDX-License-Identifier: Apache-2.0

#include "KernelSupport.h"
#include "KernelImage.h"
#include <ntddk.h>
#include <aux_klib.h>

namespace MatanelPDB {
namespace KernelUtils {

NTSTATUS 
GetNTOSKrnl(
    OUT LoadedImage* Image
) 

noexcept 

/*++

    Routine Description:

        Locates the currently loaded Windows kernel image and returns its
        image base and size.

    Arguments:

        [OUT] Image - Receives the loaded kernel image base and size. Both fields are cleared before module enumeration begins.

    Return Value:

        STATUS_SUCCESS if the kernel image is found, otherwise, an NTSTATUS
        describing the failure. 
        
    Notes:

        Requires PASSIVE_LEVEL

--*/

{
    ASSERT(Image);

    // Initialize both to zero
    Image->ImageBase = nullptr;
    Image->ImageSize = 0;

    // Initialize AuxKlib
    // Fun fact: AuxKlib is not an export from ntos like I thought it was at first
    // It's just a static library made by microsoft that makes ease of use for kernel enumeration
    // internally it would probably just call the Zw routines for stuff, and/or others.
    NTSTATUS Status = AuxKlibInitialize();
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Acquire the correct size needed 
    // Aux library understands this because QueryInfo being nullptr
    ULONG NeededBytes = 0;
    Status = AuxKlibQueryModuleInformation(&NeededBytes, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr);
    if (!NT_SUCCESS(Status)) return Status;

    // Allocate the needed bytes to contain all the modules in the system
    PAUX_MODULE_EXTENDED_INFO Info = (PAUX_MODULE_EXTENDED_INFO)MatanelAlloc(MATANEL_ALLOCATION::Paged, NeededBytes, MATANEL_AUX_QUERY_ALLOC_TAG);
    if (!Info) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Info is allocated from now on

    while (true) {
        // Fill the entries now, this is in a while loop so if the entries enlarge while our buffer is still the old size
        // we would retry with the new byte buffer
        Status = AuxKlibQueryModuleInformation(&NeededBytes, sizeof(AUX_MODULE_EXTENDED_INFO), Info);
        
        if (NT_SUCCESS(Status)) {
            break;
        }
        else if (Status == STATUS_BUFFER_TOO_SMALL) {
            // Entries resized between first call to this one, retry with a new buffer
            ExFreePoolWithTag(Info, MATANEL_AUX_QUERY_ALLOC_TAG);

            if (!NeededBytes || NeededBytes == MAXULONG) {
                // Invalid byte amount
                return STATUS_INTERNAL_ERROR;
            }

            // NeededBytes was updated from aux to new size
            Info = (PAUX_MODULE_EXTENDED_INFO)MatanelAlloc(MATANEL_ALLOCATION::Paged, NeededBytes, MATANEL_AUX_QUERY_ALLOC_TAG);
            if (!Info) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // Loop will retry with updated info and bytes.
        }
        else {
            // Bad status
            ExFreePoolWithTag(Info, MATANEL_AUX_QUERY_ALLOC_TAG);
            return Status;
        }
    }

    // Module information is now filled when we get here, find ntos through the allocated entries
    for (SIZE_T i = 0; i < NeededBytes / sizeof(AUX_MODULE_EXTENDED_INFO); i++) {

        // Compare the filename only, the offset and full name must fit inside
        // the fixed path buffer, including the filename's null terminator.
        constexpr char KernelName[] = "ntoskrnl.exe";
        const SIZE_T FileNameOffset = Info[i].FileNameOffset;
        const SIZE_T PathCapacity = sizeof(Info[i].FullPathName);
        if (FileNameOffset >= PathCapacity || sizeof(KernelName) > PathCapacity - FileNameOffset) {
            continue;
        }

        // Compare the filename with our beloved NT OS Kernel mostly architected by Dave N. Cutler
        if (RtlCompareMemory(Info[i].FullPathName + FileNameOffset, KernelName, sizeof(KernelName)) == sizeof(KernelName)) {
            // Found NTOS, fill in the image and stop.
            Image->ImageBase = Info[i].BasicInfo.ImageBase;
            Image->ImageSize = Info[i].ImageSize;
            break;
        }
    }

    // Free the information
    ExFreePoolWithTag(Info, MATANEL_AUX_QUERY_ALLOC_TAG);

    if (Image->ImageBase != nullptr) {
        // Ntos found
        return STATUS_SUCCESS;
    }
    else {
        // Ntos not found!!!!! la problema, probably with corruption / FileNameOffset out of bounds check skipping ntos
        return STATUS_NOT_FOUND;
    }
}

}
}
