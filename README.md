# MatanelPDB

I'm building a self contained PDB parser in C++, with a Windows kernel side that
will download the matching PDB and use the same parser inside a driver.

Basically, I want to ask the PDB where something is instead of keeping a table
of offsets for every Windows build.

The parser is meant to work in both user mode and kernel mode. I'm writing the
parsing implementation myself to understand how PE, MSF, PDB and CodeView fit
together. This is still work in progress, the final symbol and type API is not
usable yet.

Licensed under [Apache 2.0](LICENSE).

## What I want it to do

Eventually, the kernel example should do this from a fresh start:

```text
Find the loaded ntoskrnl image
Read its CodeView RSDS identity
Use the PDB filename, GUID and Age to request the matching PDB
Download it from Microsoft's symbol server over authenticated HTTPS
Validate that it matches the image
Parse its symbols and types
Answer queries
```

These are examples of the queries I want, the final names and signatures can
still change. This is planned usage, not code you can compile against the
current public header:

```text
GetSymbolAddress("PsActiveProcessHead")
GetTypeSize("_EPROCESS")
GetMemberOffset("_EPROCESS", "Token")
GetMemberOffset("_KTHREAD", "PreviousMode")
GetEnumValue("SomeEnum", "SomeValue")
DescribeStruct("_EPROCESS")
DescribeEnum("SomeEnum")
```

`SomeEnum` and `SomeValue` are placeholders, availability depends on the PDB.
Type and enum queries should work with PDB bytes alone. A live symbol address
also needs a matching loaded image and its base address.

## Where it is right now

The code can identify the running kernel's PDB and read streams from a local
MSF 7 PDB. It can extract several stream headers and frame individual type
records. Decoding those records into useful structure and symbol queries is
the next part.

The kernel diagnostic currently exercises PE and RSDS parsing. The PDB parser
work has been exercised in host tests, the full PDB path is not wired into the
driver yet.

### Kernel image and PDB identity

**Now:** `GetNTOSKrnl` uses AuxKlib to find the loaded kernel image. The PE parser
finds its debug directory and CodeView entry, then `ParseRsds` extracts the PDB
filename, GUID and Age. This path has been demonstrated in a test VM.

**Example:** the diagnostic can print the identity of `ntkrnlmp.pdb` associated
with that loaded image. The Windows build number alone is not the lookup key.

**Next:** construct the symbol server request and validate the downloaded PDB
against that identity before exposing query results.

### MSF container and streams

**Now:** the MSF 7 reader parses the superblock, directory block map, stream
directory and stream block lists. It can copy a requested range from a stream,
including ranges that cross physical blocks in the file.

**Example:** read the first 56 bytes of TPI stream 2 even if the stream's blocks
are scattered around the PDB.

**Next:** build the higher level PDB readers on these bounded stream bytes.
MSF 2 signatures are recognized, its parser still returns `NotImplemented`.

### PDB Info and DBI

**Now:** `ParsePdbInfoHeader` extracts the fixed PDB Info header, including GUID
and Age. `ParseDbiHeader` reads the supported fixed DBI header and validates its
size fields. DBI gives us references to the symbol streams, it has an Age but
does not contain the PDB GUID.

**Example:** DBI tells us which stream holds the shared symbol records, then
the MSF reader can retrieve bytes from that stream.

**Next:** validate supported PDB Info versions, complete image identity binding,
and read the DBI data needed to resolve symbols. Header extraction by itself
does not prove that all referenced streams and substreams are valid.

### TPI type records

**Now:** `ParseTpiHeader` reads the supported header and checks its type range
and record byte count. `ParseTpiTypeRecord` validates one record's framing and
returns its kind, complete byte size and a bounded view of its payload.

**Example:** a record with `RecordLen = 14` occupies 16 bytes because the length
excludes its own two byte field. A kind of `0x1505` identifies an `LF_STRUCTURE`
record, its payload still needs decoding to get a name such as `_EPROCESS`.

**Next:** implement `BuildTpiRecordIndex`, which is currently a stub. It will
map each type index to a record location so other records can refer to it.

```text
Illustrative index, offsets are bytes from the start of the TPI stream

Type index    Stream offset    Record size
0x1000        56               16
0x1001        72               24
0x1002        96               ...
```

After indexing comes numeric value decoding, structure names and sizes, member
lists, enums, bitfields and complete definitions versus forward declarations.
The next useful result is reading `_EPROCESS` and its size from a local PDB.

### Symbols and the public API

**Now:** there is no finished symbol resolver or engine object. The public
header currently declares the fixed PDB stream indices.

**Next:** parse the needed symbol records, translate section offsets into RVAs,
and expose symbol, type, member and enum queries with defined ownership and
failure behavior. Missing data should return an error, never a guessed offset.

**Example:** `GetMemberOffset("_EPROCESS", "Token")` should find the type and
member in the supplied PDB. `GetSymbolAddress` should combine a resolved symbol
RVA with the base of an image that has been matched to that PDB.

### Kernel downloading

**Now:** networking, TLS and symbol server downloading are not implemented.

**Next:** download directly from the kernel over authenticated HTTPS, with
bounded responses, timeouts, cancellation and unload cleanup. The parser will
receive validated byte buffers through the same interface used by host tests.

**Example:** load the driver in a VM with no prepared PDB, download the correct
one, then print verified symbol and structure query results.

### Offline offset dumper, later

Once the main engine is working, I also want to export selected structures and
members into an ordered `.txt` file. It should include names, sizes, offsets,
bitfield information when needed, and the PDB identity the results came from.

```text
Illustrative output fields, the file format is not finalized

Type name       _EPROCESS
Type size       <size from this PDB>
Member name     Token
Member offset   <byte offset from this PDB>
```

The idea is that someone can write their own Python script to take only the
offsets or sizes they need and generate constants for their program. That
program can then use those constants offline without linking the parser.
The exported layouts still belong to the recorded image and PDB identity.
The user's Python integration script is their own part.

## How it is organized

| Path | What is there |
| --- | --- |
| `include/MatanelPDB.h` | Public API placeholder and fixed stream indices |
| `src/pe/` | PE debug directory, CodeView entry and RSDS parsing |
| `src/msf/` | MSF container and stream readers |
| `src/pdb/` | PDB Info, DBI and TPI parsing |
| `src/common/` | Small shared byte utilities |
| `platform/windows-kernel/` | Kernel image discovery and allocation support |
| `examples/diagnostic/` | The standalone diagnostic driver |
| `examples/driver/` | Original KMDF template, excluded from the active solution |
| `tests/` | Host PE and RSDS smoke test source |

The intended distribution is a header plus source files. Add `include/` to
your include path and compile the needed `src/` files. Kernel consumers will
also use the relevant platform files. Including `MatanelPDB.h` alone does not
give you a finished engine yet.

The portable parser should not depend on Windows headers, networking, file
handles or kernel allocators. It uses no STL, exceptions or RTTI. File access,
downloads and allocations belong to the host or platform integration.

## Building

Open `MatanelPDB.slnx` in Visual Studio 2026, select x64 and Debug or Release.
The portable project uses the regular C++ toolset, the diagnostic uses the
WDK kernel toolset and links `Aux_Klib.lib`.

Restore the SDK and WDK packages before building the diagnostic:

```powershell
nuget restore packages.config -PackagesDirectory packages
```

The `.lib` generated by the portable project is useful for development builds,
it is not a required prebuilt dependency for consumers. Generated binaries,
PDB files, packages, signing material and IDE state are excluded from Git.

A successful build does not mean the unfinished API or download path works.
The current kernel example targets x64 with the configured Windows 10 driver
toolset, broad Windows version support is still a goal that needs testing.

## Trying the diagnostic

Build `MatanelPDBDiagnostic` in x64 Debug and copy the resulting `.sys` to a
test VM. A solution build places it at `x64/Debug/MatanelPDBDiagnostic.sys`.
A direct project build places it under `examples/diagnostic/x64/Debug/`.

Start DbgView as administrator and enable kernel capture. The VM needs to
allow the driver's development test signature. In an elevated command prompt,
use the actual path where you copied the driver:

```cmd
sc.exe create MatanelPDBDiagnostic type= kernel start= demand binPath= "%TEMP%\MatanelPDBDiagnostic.sys"
sc.exe start MatanelPDBDiagnostic
sc.exe stop MatanelPDBDiagnostic
sc.exe delete MatanelPDBDiagnostic
```

It prints the kernel image query, PE debug data, CodeView payload and RSDS
identity. It stays loaded even if a query fails so the error can be captured
and the driver stopped normally. This example currently stops at image identity.

## Progress

Completed functions and milestones will be reviewed, checked and committed to
`master`. Each advancement will update this README with what works now, what
it enables next and a small example. Unfinished functions stay marked as such.

The current next function is [`BuildTpiRecordIndex`](src/pdb/Tpi.cpp).
