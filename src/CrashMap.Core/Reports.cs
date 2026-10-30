using System.Net;
using System.Text;
using System.Text.Json;

namespace Rudy.CrashMap;

public static class Reports
{
    public const string Version = "0.1.0-preview";
    public static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private static object Module(DumpModule m) => new { m.Name, address = Address.Hex(m.Address), m.Size, m.Checksum, m.Timestamp, m.PathSha256, m.PdbIdentity };
    private static object Memory(CapturedRange m) => new { address = Address.Hex(m.Address), m.Size, m.FileOffset, m.Source };
    private static object Identity(DumpSnapshot s) => new { s.Sha256, s.Bytes, s.Timestamp, flags = Address.Hex(s.Flags), s.System };
    private static object[] ModuleAt(DumpSnapshot s, ulong address, int rows) => s.Modules.Where(m => Address.Contains(m.Address, m.Size, address)).Take(rows).Select(m => (object)new { module = Module(m), offset = Address.Hex(address - m.Address) }).ToArray();
    public static object Inspect(DumpSnapshot s, int rows)
    {
        var coverage = new CoverageIndex(s.Memory.Select(m => (m.Address, m.Size)));
        var moduleCoverage = new CoverageIndex(s.Modules.Select(m => (m.Address, (ulong)m.Size)));
        var committed = s.Regions.Where(r => r.State == 0x1000).ToArray();
        var executable = committed.Where(r => (r.Protect & 0xf0) != 0).ToArray();
        var privateExecutable = executable.Where(r => r.Type == 0x20000).ToArray();
        var writableExecutable = executable.Where(r => (r.Protect & 0xc0) != 0).ToArray();
        var missingModuleBytes = s.Modules.Sum(m => (long)((ulong)m.Size - coverage.Covered(m.Address, m.Size)));
        return new
        {
            schema = "rudy-crashmap/inspection-v1", version = Version, input = Identity(s),
            validation = new { stableSource = true, supportedStreamsChecked = true, headerChecksum = "not-verified", skippedStreamTypes = s.Streams.Where(st => !IsSupported(st.Type)).Select(st => st.Type).Distinct().Order().ToArray() },
            summary = new { streams = s.Streams.Count, modules = s.Modules.Count, threads = s.Threads.Count, captureDescriptors = s.Memory.Count, memoryRegions = s.Regions.Count, distinctCapturedBytes = coverage.Bytes, disjointCapturedRanges = coverage.DisjointRanges, uncapturedModuleBytesSummed = missingModuleBytes, executableRegions = executable.Length, privateExecutableRegions = privateExecutable.Length, writableExecutableRegions = writableExecutable.Length },
            exception = s.Exception is null ? null : new { s.Exception.ThreadId, code = Address.Hex(s.Exception.Code), s.Exception.Flags, address = Address.Hex(s.Exception.Address), s.Exception.ParameterCount, threadPresent = s.Threads.Any(t => t.Id == s.Exception.ThreadId), captured = coverage.Covered(s.Exception.Address, s.Exception.Address == ulong.MaxValue ? 0UL : 1UL) != 0, modules = ModuleAt(s, s.Exception.Address, rows) },
            streams = s.Streams.Take(rows).Select(st => new { st.Type, st.Size, st.Rva, supported = IsSupported(st.Type) }).ToArray(),
            modules = s.Modules.Take(rows).Select(m => new { module = Module(m), capturedBytes = coverage.Covered(m.Address, m.Size) }).ToArray(),
            threads = s.Threads.Take(rows).Select(t => new { t.Id, stackAddress = Address.Hex(t.StackAddress), t.StackSize, t.ContextSize, capturedStackBytes = coverage.Covered(t.StackAddress, t.StackSize) }).ToArray(),
            memory = s.Memory.Take(rows).Select(Memory).ToArray(),
            regions = s.Regions.Take(rows).Select(r => new { address = Address.Hex(r.Address), r.Size, r.State, r.Protect, r.Type, capturedBytes = coverage.Covered(r.Address, r.Size), moduleBytes = moduleCoverage.Covered(r.Address, r.Size) }).ToArray(),
            omitted = new { streams = Math.Max(0, s.Streams.Count - rows), modules = Math.Max(0, s.Modules.Count - rows), threads = Math.Max(0, s.Threads.Count - rows), memory = Math.Max(0, s.Memory.Count - rows), regions = Math.Max(0, s.Regions.Count - rows) },
            interpretation = "Capture coverage is not memory integrity. Private or writable executable regions can be legitimate JIT/runtime allocations. Context blobs are range-checked, not decoded or unwound."
        };
    }
    public static object Locate(DumpSnapshot s, ulong address, int rows)
    {
        var modules = s.Modules.Where(m => Address.Contains(m.Address, m.Size, address)).ToArray();
        var memory = s.Memory.Where(m => Address.Contains(m.Address, m.Size, address)).ToArray();
        var regions = s.Regions.Where(r => Address.Contains(r.Address, r.Size, address)).ToArray();
        return new
        {
            schema = "rudy-crashmap/location-v1", version = Version, input = Identity(s), address = Address.Hex(address),
            summary = new { modules = modules.Length, captureDescriptors = memory.Length, memoryRegions = regions.Length },
            modules = ModuleAt(s, address, rows),
            captures = memory.Take(rows).Select(m => new { source = Memory(m), matchingFileOffset = checked(m.FileOffset + address - m.Address) }).ToArray(),
            regions = regions.Take(rows).Select(r => new { address = Address.Hex(r.Address), r.Size, r.State, r.Protect, r.Type }).ToArray(),
            omitted = new { modules = Math.Max(0, modules.Length - rows), captures = Math.Max(0, memory.Length - rows), regions = Math.Max(0, regions.Length - rows) },
            interpretation = "All overlapping matches are returned up to the display limit; no single owner is guessed. No raw memory bytes are exported."
        };
    }
    public static object Diff(DumpSnapshot before, DumpSnapshot after, IReadOnlyList<ModuleChange> changes, int rows) => new
    {
        schema = "rudy-crashmap/comparison-v1", version = Version, before = Identity(before), after = Identity(after),
        summary = new { added = changes.Count(c => c.Kind == "added"), removed = changes.Count(c => c.Kind == "removed"), metadataChanged = changes.Count(c => c.Kind == "metadata-changed"), relocated = changes.Count(c => c.Kind == "relocated"), ambiguous = changes.Count(c => c.Kind == "ambiguous"), changed = changes.Any(c => c.Kind != "relocated"), omittedChanges = Math.Max(0, changes.Count - rows) },
        changes = changes.Take(rows).Select(c => new { c.Kind, c.Name, c.BeforeCount, c.AfterCount, before = c.Before is null ? null : Module(c.Before), after = c.After is null ? null : Module(c.After) }).ToArray(),
        interpretation = "Basenames are grouping hints. Repeated names remain ambiguous; metadata equality is not proof that binaries match. ASLR relocation alone does not reach the changed gate. This compares module metadata, not process memory contents."
    };
    public static bool IsSupported(uint type) => type is 3 or 4 or 5 or 6 or 7 or 9 or 16;
    public static string Render(object report, string format)
    {
        string json = JsonSerializer.Serialize(report, JsonOptions);
        if (System.Text.Encoding.UTF8.GetByteCount(json) > 16 * 1024 * 1024) throw new InvalidDataException("Rendered report exceeds the 16 MiB budget.");
        if (format == "json") return json + "\n";
        if (format == "text") return "Rudy CrashMap / offline minidump evidence\n" + json + "\n";
        using var document = JsonDocument.Parse(json); var root = document.RootElement;
        string schema = root.GetProperty("schema").GetString()!;
        var summary = root.GetProperty("summary");
        (string Key, string Label)[] fields = schema.Contains("inspection", StringComparison.Ordinal)
            ? [("modules", "Loaded modules"), ("threads", "Threads"), ("distinctCapturedBytes", "Distinct captured bytes"), ("privateExecutableRegions", "Private executable regions")]
            : schema.Contains("comparison", StringComparison.Ordinal)
                ? [("added", "Added modules"), ("removed", "Removed modules"), ("metadataChanged", "Metadata changes"), ("relocated", "Relocations")]
                : [("modules", "Module matches"), ("captureDescriptors", "Capture matches"), ("memoryRegions", "Region matches")];
        string cards = "<div class=\"cards\">" + string.Concat(fields.Select(f => "<div class=\"card\"><span>" + f.Label + "</span><strong>" + WebUtility.HtmlEncode(summary.GetProperty(f.Key).ToString()) + "</strong></div>")) + "</div>";
        var table = new StringBuilder();
        if (schema.Contains("inspection", StringComparison.Ordinal))
        {
            table.Append("<h2>Module coverage</h2><div class=\"scroll\"><table><tr><th>Module</th><th>Base address</th><th>Image bytes</th><th>Captured bytes</th></tr>");
            foreach (var row in root.GetProperty("modules").EnumerateArray())
            {
                var m = row.GetProperty("module");
                table.Append("<tr><td>" + WebUtility.HtmlEncode(m.GetProperty("name").GetString()) + "</td><td><code>" + m.GetProperty("address").GetString() + "</code></td><td>" + m.GetProperty("size") + "</td><td>" + row.GetProperty("capturedBytes") + "</td></tr>");
            }
            table.Append("</table></div><p>Omitted module rows: " + root.GetProperty("omitted").GetProperty("modules") + ". Totals cover the full parsed metadata.</p>");
        }
        else if (schema.Contains("comparison", StringComparison.Ordinal))
        {
            table.Append("<h2>Module changes</h2><div class=\"scroll\"><table><tr><th>Module</th><th>Observation</th><th>Before matches</th><th>After matches</th></tr>");
            foreach (var row in root.GetProperty("changes").EnumerateArray())
                table.Append("<tr><td>" + WebUtility.HtmlEncode(row.GetProperty("name").GetString()) + "</td><td>" + row.GetProperty("kind").GetString() + "</td><td>" + row.GetProperty("beforeCount") + "</td><td>" + row.GetProperty("afterCount") + "</td></tr>");
            table.Append("</table></div>");
        }
        return "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>Rudy CrashMap / investigation</title><style>" +
            ":root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#090f17;color:#eaf3ff;font:15px/1.65 system-ui,sans-serif}main{max-width:1120px;margin:40px auto;padding:24px}header{border-left:4px solid #55e0b6;background:linear-gradient(110deg,#101e2b,#0b121c);padding:24px 30px}small{font:12px monospace;color:#55e0b6;letter-spacing:2px}h1{font-size:clamp(38px,6vw,64px);line-height:1.1;letter-spacing:-2px;margin:18px 0}h2{margin-top:30px}p,footer{color:#9db0c5}.cards{display:flex;flex-wrap:wrap;gap:16px;margin:28px 0}.card{flex:1;min-width:185px;background:#101b28;border:1px solid #2a3c52;border-radius:10px;padding:20px}.card span{color:#9db0c5;font-size:13px}.card strong{display:block;color:#55e0b6;font-size:32px;margin-top:8px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:12px;border-bottom:1px solid #26384b}th{color:#9db0c5}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101b28;border:1px solid #2a3c52;border-radius:10px;padding:22px;font:13px/1.65 ui-monospace,monospace;max-height:660px;overflow:auto}details{padding:16px 20px;border:1px solid #2a3c52;border-radius:10px;margin:24px 0}summary{cursor:pointer;font-weight:650}.notice{border-left:3px solid #d6aa72;padding:14px 20px;background:#251f18;color:#edc797}footer{font-size:13px;border-top:1px solid #26384b;margin-top:32px;padding-top:20px}</style><main><header><small>RUDY SYSTEMS / CRASH FORENSICS</small><h1>Rudy CrashMap</h1><p>Map the fault. Measure the capture. Follow the module changes.</p></header>" +
            cards + table + "<p class=\"notice\">Offline metadata investigation. A mapped module is not a causal verdict; executable private memory can belong to a legitimate runtime. Missing streams and uncaptured bytes remain unknown.</p><details><summary>Structured evidence</summary><pre>" +
            WebUtility.HtmlEncode(json) + "</pre></details><footer>C# / .NET 10 / developer preview " + Version + ". No symbols downloaded, no dump code loaded, no raw memory or complete module/PDB paths exported. Source files are read only and checked again after parsing.</footer></main></html>";
    }
}
