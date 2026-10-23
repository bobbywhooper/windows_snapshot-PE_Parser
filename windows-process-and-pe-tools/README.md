# Windows Process & PE Tools

Two small command-line tools for learning how Windows executables and running processes work. Both are read-only: they inspect, they never modify or inject.

| Tool | Language | What it does |
|------|----------|--------------|
| [`process-explorer`](process-explorer/) | C (Win32 API) | Lists running processes, finds a process by name, lists its loaded modules (EXE/DLLs) |
| [`pe-parser`](pe-parser/) | Python 3 | Parses a PE file (`.exe`/`.dll`) from raw bytes: headers, sections, imports, exports |

Neither tool depends on third-party libraries. The PE parser reads the file format by hand with `struct`, without `pefile`, to show how the format works.

## Repository layout

```
.
├── README.md
├── LICENSE
├── .gitignore
├── process-explorer/
│   └── snapshot.c
└── pe-parser/
    └── pe_parser.py
```

---

## 1. Process Explorer (`snapshot.c`)

Interactive menu built on the Tool Help API (`CreateToolhelp32Snapshot`).

```
========== Process Explorer ==========
1. List all processes
2. Find process by name
3. List loaded modules of a process
4. Exit
```

### Features

- **List processes:** PID and executable name from a point-in-time snapshot.
- **Find by name:** case-insensitive exact match on the executable name (e.g. `notepad.exe`). Shows PID and full image path via `OpenProcess` + `QueryFullProcessImageNameA`.
- **List modules:** name, path, base address and size of every module loaded in the process.
- Error handling returns a status enum and prints the Windows error code on failure.

### Build

Requires Windows and MinGW-w64 GCC.

```
cd process-explorer
gcc -Wall -Wextra -o process_explorer.exe snapshot.c
```

Run `process_explorer.exe` from a terminal. Use a 64-bit build on 64-bit Windows to enumerate both 64-bit and 32-bit modules.

### Notes

- Opening protected or system processes can fail with `ERROR_ACCESS_DENIED`. Running an elevated terminal helps for some, not all.
- `ERROR_PARTIAL_COPY` during module enumeration usually means a tool/target architecture mismatch.
- The source uses ANSI Tool Help structures. Do not compile with `-DUNICODE`/`-municode`, since `printf("%s")` would then print wide strings incorrectly.

### Known limitations

- Name lookup returns only the first matching process when several instances are running.
- Process and module data is a snapshot and can be stale by the time it prints.

---

## 2. PE Parser (`pe_parser.py`)

Reads a Windows PE file and prints its structure.

### What it parses

1. DOS header (`MZ`, `e_lfanew`)
2. PE signature
3. COFF header (machine type, section count, characteristics)
4. Optional header (PE32 and PE32+, entry point, image base, data directories)
5. Section table
6. RVA to file offset conversion
7. Import table (by name and by ordinal)
8. Export table (named exports, ordinals, RVAs, file offsets)

### Usage

Requires Python 3.8+.

```
python pe_parser.py <file.exe|file.dll>
```

Example:

```
python pe_parser.py C:\Windows\System32\notepad.exe
```

### Sample output

<!-- TODO: replace with real output from your machine, e.g. trimmed output for notepad.exe -->

```
(paste trimmed output here)
```

### Validation

<!-- TODO: after comparing against pefile or dumpbin, state what you checked, e.g.:
Output compared against `dumpbin /headers /imports /exports` on notepad.exe, kernel32.dll and a 32-bit executable. -->

### Known limitations

- Delay-load imports, bound imports, resources, relocations and TLS are not parsed.
- Export forwarders are displayed as normal RVAs.
- Only named exports are listed; ordinal-only exports are skipped.
- Truncated or deliberately malformed files may raise an unhandled `struct.error`. The tool is meant for well-formed files.

---

## Safety and scope

These tools only read data. Do not run them against files you are not authorized to analyze, and do not commit third-party or malware samples to this repository.

## License

MIT. See [LICENSE](LICENSE).
