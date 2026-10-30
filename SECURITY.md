# Security boundaries

Use authorized stable copies. The runtime parser opens one explicitly supplied file per input, reads bounded metadata with checked offsets, and compares whole-file SHA-256 before/after. It never opens paths found inside a dump, reads symbols, loads dump modules, attaches to a process, or exports raw memory. Input symlinks and directories are rejected. This does not sandbox special-file/path substitution races on an attacker-controlled filesystem.

Minidumps can contain credentials and private memory even when reports omit payloads. Real dump files are excluded from source and release artifacts. The only Windows capture code is in the test harness and starts its own disposable child; the test deletes its temporary capture. Release examples are independently invented bytes.

Reports retain basenames, path hashes, build metadata, virtual addresses and timestamps. These can be identifying. Full-path hashing is not anonymization against dictionary guesses. Unknown stream bodies and CPU contexts remain outside analysis, and the header checksum is not verified. Valid metadata is not authentic evidence or proof of benign/malicious behavior.

Recovery through a debugger, symbol servers, arbitrary process capture, kernel dump parsing, compressed encodings and live acquisition are outside this project. Prefer private GitHub vulnerability reporting for sensitive reports; provide the smallest synthetic reproducer rather than a real user's dump or credentials. A partial newly created report can remain if an output write fails.
