# Parser and investigation design

The C# core uses random-access reads and streaming SHA-256. A bounded header/directory pass validates each declared stream extent. Supported stream types must be unique. Counts and strides must fit their declared metadata body and the shared item budget before loops allocate records. Nested memory, context, string, CodeView and miscellaneous locations are checked against the original file length. Strings are strict, bounded UTF-16LE.

The parser preserves unsigned virtual addresses and checks range-end overflow. File RVAs and virtual addresses have separate meanings: a Memory64 payload is located by the stream's BaseRva plus the sizes of preceding descriptors, rather than by interpreting a virtual address as a file offset. Thread stack descriptors can duplicate MemoryList coverage; both sources remain visible for address lookup.

For aggregate coverage, ranges are sorted and merged into a disjoint union. Cumulative byte counts allow coverage inside a requested module/region in logarithmic time using two prefix queries. A byte-set oracle independently exercises randomized overlaps, adjacency, gaps and queries. Full-range totals are computed before row limits.

Exception mapping returns all containing modules and an explicit captured-byte decision. It does not infer the instruction, unwind a stack, or assign blame. Memory region protection/type values are observations. Private/writable executable allocations are review gates because runtimes and JITs legitimately create them.

Comparison groups module basenames using ordinal case-insensitive comparison. Multiplicity on either side yields an ambiguous group; it never guesses one-to-one matches. Unique groups compare size/checksum/timestamp/RSDS identity metadata, then separate base relocations. Equal metadata is not byte identity, and a path change alone does not establish a changed binary.

Reports are rendered only after source digest rechecks. No source paths or raw memory are placed in the report; basename/identity fields are encoded by System.Text.Json and HTML-escaped before display. HTML uses native details elements, no JavaScript/external resources, and a restrictive CSP. Output creation is exclusive; POSIX files request mode 0600.

## Primary format references

- [Microsoft MINIDUMP_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header)
- [Microsoft MINIDUMP_MODULE](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_module)
- [Microsoft MINIDUMP_THREAD](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_thread)
- [Microsoft MINIDUMP_MEMORY64_LIST](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory64_list)
- [Microsoft MINIDUMP_MEMORY_INFO_LIST](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_info_list)
- [Microsoft MINIDUMP_EXCEPTION_STREAM](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_exception_stream)
- [Microsoft MiniDumpWriteDump](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)

The reader supports standard uncompressed little-endian metadata through flags 0x01ffffff. It rejects extended flags rather than guessing compressed/future layouts. Unknown stream bodies are outside semantic validation even when their physical extents fit.
