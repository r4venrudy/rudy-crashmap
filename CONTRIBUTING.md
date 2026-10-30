# Contributing

Describe a concrete parser, coverage, interoperability, or reporting problem and include a minimal synthetic fixture. Keep C# as the runtime core and avoid third-party dependencies unless the functionality needs one. New parsing must bound counts and extents before allocation and preserve unknown coverage explicitly.

Run the native harness and independent Python CLI oracle in the README. Add tests for observable failures and a trusted oracle for successful behavior. Never commit real minidumps, credentials, machine-specific paths, generated reports, or release binaries. Keep preview limitations accurate and do not turn memory metadata into unsupported malware or causality claims.
