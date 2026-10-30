Rudy CrashMap is a C#/.NET 10 offline user-mode Windows minidump investigation tool.

- Bounded parser for seven standard stream types, checked nested extents, strict UTF-16, and stable-input SHA-256 identities.
- Exception/module offsets, virtual-address-to-capture offsets, disjoint captured-memory coverage, and executable-region review gates.
- Module metadata comparisons with separate ASLR relocation and conservative duplicate-name handling.
- Versioned JSON, text, offline RUDY HTML, independent synthetic/coverage oracles, and a real owned-child DbgHelp regression on Windows.

Self-contained packages include runtime binaries, invented captures with expected metadata, example reports, documentation and runtime notices. Keep each complete bin directory. Linux x64 targets Ubuntu 24.04; Windows x64 targets Windows Server 2022 or compatible newer desktop Windows; macOS ARM64 builds on macOS 15. Older OS compatibility is unverified. The nupkg requires a .NET 10 runtime and can be installed from a local source; it is a release asset, not a claimed publication on nuget.org.

Verify SHA256SUMS.txt before extraction. Developer preview: analyze authorized stable copies. Unknown streams remain outside semantic coverage, the header checksum is unverified, and module/executable-memory observations do not prove malware or crash causality. Reports retain potentially identifying metadata despite omitting complete paths and raw payloads.
