#pragma once

// SPDX-License-Identifier: Apache-2.0
// Windows kernel image-discovery declarations used by the integration host.

#include <ntddk.h>

namespace MatanelPDB {
namespace KernelUtils {

struct LoadedImage {
    PVOID ImageBase;
    ULONG ImageSize;
};

NTSTATUS GetNTOSKrnl(_Out_ LoadedImage* Image) noexcept;

}
}
