# MatanelPDB

MatanelPDB is a source-distributed C++ PDB parser under development. The parsing
core is intended to work in both user mode and Windows kernel mode. A separate
Windows kernel adapter currently locates the loaded kernel image; the diagnostic
driver exercises that adapter and the PE/RSDS parsers. The portable core includes
MSF 7 container and stream reading, PDB Info and DBI fixed header parsing, and
TPI header and individual record framing. MSF 2 parsing and TPI record indexing
remain unfinished.
There is no finished public symbol/type API or symbol-server downloader yet.

The repository is licensed under the [Apache License, Version 2.0](LICENSE).

## Repository layout

| Path | Purpose |
| --- | --- |
| `include/MatanelPDB.h` | Placeholder for the portable public API. No usable engine class is declared yet. |
| `src/pe/` | Portable PE, CodeView-entry, and RSDS parsing. |
| `src/msf/` | Portable MSF container parsing in progress. |
| `src/pdb/` | PDB Info, DBI and TPI parsing, with unfinished record indexing. |
| `platform/windows-kernel/` | Kernel-only image discovery and allocation support. Future networking and TLS integration belongs on this side. |
| `MatanelPDB.vcxproj` | Builds the portable source as a static library for compile checks. |
| `examples/diagnostic/` | Standalone driver that exercises kernel image discovery and the PE/RSDS path. It is an example, not the engine API. |
| `examples/driver/` | Preserved original KMDF template, excluded from the active solution. Its device interface and queue are unrelated to the engine API. |
| `tests/` | User-mode parser smoke tests; future location for fuzzing. |

The intended distribution is **header plus source**: consumers will add
`include/` to their include path and compile/link the needed files from `src/`.
Kernel consumers will also integrate the relevant files from
`platform/windows-kernel/`. The `.lib` emitted by the VS project is a development
build artifact, not a required prebuilt dependency. Including `MatanelPDB.h`
alone does not provide a working engine yet.

## Build

Open `MatanelPDB.slnx` in Visual Studio 2026 and build x64 Debug or Release.
The `MatanelPDB` project uses the regular C++ toolset for the portable source.
`MatanelPDBDiagnostic` uses the WDK kernel-mode toolset and links `Aux_Klib.lib`.

Restore the referenced WDK/SDK package versions before building the diagnostic:

```powershell
nuget restore packages.config -PackagesDirectory packages
```

The package directory and all build outputs are ignored by Git. The original template INF
is retained as reference material but is not part of the active host build;
the resulting driver binary is for development, not an installation package.

The source project disables C++ exceptions and RTTI, and treats compiler
warnings as errors. The diagnostic compiles the portable PE/RSDS source directly
alongside the kernel adapter. Its runtime output has been verified on one test
VM; a build alone does not prove support for other Windows versions.

Some functions deliberately return `NotImplemented`, including MSF 2 parsing
and `BuildTpiRecordIndex`. A successful build does not mean these features are
implemented or that the public query API is ready.

## Diagnostic driver

Build `MatanelPDBDiagnostic` for x64 Debug and copy only the resulting `.sys`
to a test VM. A solution build places it at `x64/Debug/MatanelPDBDiagnostic.sys`;
a direct project build places it at
`examples/diagnostic/x64/Debug/MatanelPDBDiagnostic.sys`. The driver prints its load,
the `GetNTOSKrnl` result, the PE header parse status and debug-directory RVA/size,
the bounded debug-table copy result, the CodeView entry's size and locations,
the CodeView payload copy result and first four bytes, and the parsed RSDS
status, GUID, age, and bounded PDB name,
and its unload through `DbgPrintEx`. Start DbgView as administrator with kernel capture enabled before
loading the driver. From an elevated VM command prompt, using the actual path
where the `.sys` was copied:

```cmd
sc.exe create MatanelPDBDiagnostic type= kernel start= demand binPath= "C:\Temp\MatanelPDBDiagnostic.sys"
sc.exe start MatanelPDBDiagnostic
sc.exe stop MatanelPDBDiagnostic
sc.exe delete MatanelPDBDiagnostic
```

The build embeds a development test signature. The VM must allow test-signed
drivers; this diagnostic is not a production-signed driver. It returns success
from `DriverEntry` even when the kernel image query fails so the status can be
captured and the test driver stopped normally.

## Planned boundaries

PE/PDB byte parsing should remain independent of WDF, networking, file I/O,
and kernel allocation APIs. A future engine instance should accept a bounded
PDB byte view for type queries and optionally bind a validated image view for
live symbol addresses. File acquisition, TLS, and symbol-server caching belong
in the kernel adapter, outside parser initialization. Downloaded PDB data is
untrusted: every offset, length, count, and allocation must be validated.

The initial image identity milestone has been demonstrated on one VM. The next
parser step is TPI record indexing, followed by type payload decoding and
symbol/type queries. Full image/PDB identity binding and network acquisition
remain unfinished.
