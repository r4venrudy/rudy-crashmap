# Report contracts v1

Schemas are `rudy-crashmap/inspection-v1`, `rudy-crashmap/location-v1`, and `rudy-crashmap/comparison-v1`; every report carries the tool version. Input identity includes byte length, SHA-256, header timestamp/flags and optional system metadata. Virtual addresses and address offsets are hexadecimal strings to preserve all 64 bits for JSON consumers. File offsets, sizes and counts are numeric and remain within declared resource budgets.

Inspection validation records the stable-source digest check, explicit unverified header-checksum status, and all unparsed stream types. Summary counts use the entire parsed metadata, independent of displayed rows. Distinct capture coverage is a union; uncaptured module bytes are summed over modules and can double-count overlapping modules. Zero regions is not proof that no executable allocations existed when a memory-info stream is absent. Check the directory's supported stream types before interpreting zero counts.

Exception data is null if no Exception stream exists. A recorded exception carries code, flags, thread identifier, virtual address, parameter count, thread-presence and byte-coverage decisions, and containing module offsets. Parameter values and context registers are omitted. Multiple module matches remain multiple matches.

Address lookup lists each containing capture descriptor with a matching physical file offset, every matching module, and matching region metadata. These are containment relations, not symbols or ownership assertions. A raw payload is never included.

Module comparison exposes before/after input identities, full change totals and a capped change list. Duplicate basenames produce an ambiguous event even when comparing a dump to itself; the changed gate remains conservative. Only pure relocation is excluded from the changed gate. Module path hashes identify original strings; no path is opened or authenticated.

Omission counters are explicit. Exit status 2 means a failure regardless of whether an I/O failure left part of a newly created report. Reports are neither signed attestations nor proof of logical/crash causality.
