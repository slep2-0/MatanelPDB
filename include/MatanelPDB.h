#pragma once

// SPDX-License-Identifier: Apache-2.0
// Portable public API declarations belong here when their contracts are ready.
// Windows kernel integration helpers live under platform/windows-kernel/.

namespace MatanelPDB {
namespace PDB {

// Fixed stream indices in a PDB. MSF itself only assigns numeric stream IDs.
// This unscoped enum permits indexing a stream descriptor array directly.
enum FixedStreamIndex : unsigned int {
    INDEX_OLD_DIRECTORY = 0,
    INDEX_PDB_INFO = 1,
    INDEX_TPI = 2,
    INDEX_DBI = 3,
    INDEX_IPI = 4
};

} // namespace PDB
} // namespace MatanelPDB
