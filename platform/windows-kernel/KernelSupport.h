#pragma once

// SPDX-License-Identifier: Apache-2.0
// Windows kernel allocation support for the integration adapter.

#include <ntddk.h>

namespace MatanelPDB {
namespace KernelUtils {

enum class MATANEL_ALLOCATION : POOL_FLAGS {
    Paged = POOL_FLAG_PAGED,
    NonPaged = POOL_FLAG_NON_PAGED
};

} // namespace KernelUtils
} // namespace MatanelPDB

// Both choices use non-executable pool on the project's x64 target.
#define MatanelAlloc(Allocation, Size, Tag) \
    ExAllocatePool2(static_cast<POOL_FLAGS>(Allocation), (Size), (Tag))

#define MATANEL_AUX_QUERY_ALLOC_TAG 'MATA' // Matanel Aux
