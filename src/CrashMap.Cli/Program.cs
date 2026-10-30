using System.Globalization;
using System.Text;
using Rudy.CrashMap;

try { return Run(args); }
catch (Exception e) when (e is InvalidDataException or ArgumentException or OverflowException or FormatException)
{ Console.Error.WriteLine("crashmap: " + (e is InvalidDataException ? e.Message : "Invalid command or numeric value. Use --help.")); return 2; }
catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
{ Console.Error.WriteLine("crashmap: Cannot read or create the requested file."); return 2; }

static int Run(string[] args)
{
    if (args.Length == 1 && args[0] == "--version") { Console.WriteLine("crashmap " + Reports.Version); return 0; }
    if (args.Length == 1 && args[0] == "--help")
    {
        Console.WriteLine("Rudy CrashMap / offline Windows minidump investigations\ncrashmap inspect CAPTURE.dmp [--fail-on private-executable]\ncrashmap locate CAPTURE.dmp --address HEX\ncrashmap diff BEFORE.dmp AFTER.dmp [--fail-on changed]\nCommon: --format json|text|html --output NEW_FILE --rows 1..1000\n        --max-input-mib 1..4096 --max-items 1..1000000\nNo process attachment, code loading, symbols, stack unwinding, or raw-memory export."); return 0;
    }
    if (args.Length < 2 || args[0] is not ("inspect" or "locate" or "diff")) throw new ArgumentException();
    string command = args[0]; int firstOption = command == "diff" ? 3 : 2;
    if (args.Length < firstOption || args.Take(firstOption).Skip(1).Any(a => a.StartsWith("--", StringComparison.Ordinal))) throw new ArgumentException();
    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    for (int i = firstOption; i < args.Length; i += 2)
    {
        if (i + 1 == args.Length || args[i] is not ("--address" or "--format" or "--output" or "--rows" or "--max-input-mib" or "--max-items" or "--fail-on") || !options.TryAdd(args[i], args[i + 1])) throw new ArgumentException();
    }
    string format = options.GetValueOrDefault("--format", "text"); if (format is not ("text" or "json" or "html")) throw new ArgumentException();
    int Number(string key, int fallback, int max)
    {
        if (!options.TryGetValue(key, out var raw)) return fallback;
        if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out int n) || n < 1 || n > max) throw new ArgumentException(); return n;
    }
    int rows = Number("--rows", 100, 1000);
    var limits = new Limits { MaxBytes = (long)Number("--max-input-mib", 512, 4096) * 1024 * 1024, MaxItems = Number("--max-items", 100_000, 1_000_000) };
    string? gate = options.GetValueOrDefault("--fail-on");
    if (command == "locate" ? gate is not null || !options.ContainsKey("--address") : options.ContainsKey("--address")) throw new ArgumentException();
    if (command == "inspect" && gate is not (null or "private-executable") || command == "diff" && gate is not (null or "changed")) throw new ArgumentException();
    var before = DumpReader.Read(args[1], limits); object report; bool reached = false;
    if (command == "inspect")
    {
        if (gate is not null && !before.Streams.Any(s => s.Type == 16))
            throw new InvalidDataException("Private-executable review requires a MemoryInfoList stream.");
        report = Reports.Inspect(before, rows);
        reached = gate is not null && before.Regions.Any(r => r.State == 0x1000 && r.Type == 0x20000 && (r.Protect & 0xf0) != 0);
    }
    else if (command == "locate")
    {
        string raw = options["--address"]; if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) raw = raw[2..];
        if (raw.Length is < 1 or > 16 || !ulong.TryParse(raw, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ulong address)) throw new ArgumentException();
        report = Reports.Locate(before, address, rows);
    }
    else
    {
        var after = DumpReader.Read(args[2], limits); var changes = ModuleDiff.Compare(before, after); report = Reports.Diff(before, after, changes, rows);
        reached = gate is not null && changes.Any(c => c.Kind != "relocated");
    }
    string rendered = Reports.Render(report, format);
    if (Encoding.UTF8.GetByteCount(rendered) > 16 * 1024 * 1024) throw new InvalidDataException("Rendered report exceeds the 16 MiB budget.");
    if (options.TryGetValue("--output", out string? output))
    {
        var create = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) create.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var stream = new FileStream(output, create); using var writer = new StreamWriter(stream, new UTF8Encoding(false)); writer.Write(rendered);
    }
    else Console.Write(rendered);
    return reached ? 1 : 0;
}
