# Invented captures

`make_capture.py NEW_DIRECTORY` writes four synthetic MDMP containers and `expected.json`. It does not open or capture any running process.

The baseline contains two modules, one thread, an access-violation record inside a captured module page, overlapping thread-stack/memory descriptors, two Memory64 payload ranges, three memory-region descriptors, and an unknown extension stream. Captured memory has a 160-byte distinct union. The after capture changes one module's metadata, relocates another, and adds a third. Extra fixtures exercise duplicate basenames and HTML-hostile names.

The self-contained packages also include generated inspection/comparison HTML and JSON. `expected.json` contains independent field expectations and SHA-256 capture identities. The fake PDB path and memory marker must never appear in reports.
