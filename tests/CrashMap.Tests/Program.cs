using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Rudy.CrashMap;

if (args is ["--capture-child"]) { Console.WriteLine("ready"); Console.ReadLine(); return 0; }
int assertions = 0;
void Check(bool condition, string message) { assertions++; if (!condition) throw new Exception(message); }
var random = new Random(4129);
for (int trial = 0; trial < 400; trial++)
{
    var ranges = Enumerable.Range(0, random.Next(0, 20)).Select(_ => ((ulong)random.Next(0, 120), (ulong)random.Next(0, 30))).ToArray();
    var index = new CoverageIndex(ranges);
    var bytes = new HashSet<ulong>(ranges.SelectMany(r => Enumerable.Range(0, (int)r.Item2).Select(i => r.Item1 + (ulong)i)));
    Check(index.Bytes == (ulong)bytes.Count, "Union coverage differs from independent byte-set oracle");
    for (int query = 0; query < 10; query++)
    {
        ulong start = (ulong)random.Next(0, 150), size = (ulong)random.Next(0, 30);
        Check(index.Covered(start, size) == (ulong)bytes.Count(b => b >= start && b - start < size), "Coverage query differs from independent oracle");
    }
}
Check(Address.Contains(ulong.MaxValue - 1, 1, ulong.MaxValue - 1), "High address containment");
Check(!Address.Contains(0, 0, 0), "Empty range containment");
try { Address.End(ulong.MaxValue, 1); throw new Exception("Overflow accepted"); } catch (InvalidDataException) { assertions++; }
var high = new CoverageIndex([(ulong.MaxValue - 10, 10UL)]);
Check(high.Covered(ulong.MaxValue - 5, 5) == 5, "Coverage above signed 64-bit range");
Check(high.Covered(0, 10) == 0, "Disjoint low address coverage");
var temp = Path.Combine(Path.GetTempPath(), "crashmap-native-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
try
{
    string invalid = Path.Combine(temp, "invalid.dmp"); File.WriteAllBytes(invalid, new byte[64]);
    try { DumpReader.Read(invalid); throw new Exception("Bad signature accepted"); } catch (InvalidDataException) { assertions++; }
    try { DumpReader.Read(invalid, new Limits { MaxItems = 0 }); throw new Exception("Zero budget accepted"); } catch (InvalidDataException) { assertions++; }
    if (OperatingSystem.IsWindows())
    {
        // DbgHelp reads only this test's own short-lived child, never an existing user process.
        var start = new ProcessStartInfo(Environment.ProcessPath!) { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(Environment.ProcessPath!).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        start.ArgumentList.Add("--capture-child");
        using var child = Process.Start(start)!;
        try
        {
            Check(child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20)).Result == "ready", "Owned child is ready");
            string dump = Path.Combine(temp, "owned-child.dmp");
            using (var file = new FileStream(dump, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                Check(Native.MiniDumpWriteDump(child.Handle, (uint)child.Id, file.SafeFileHandle.DangerousGetHandle(), 0x1800, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero), "DbgHelp capture failed: " + Marshal.GetLastWin32Error());
            var parsed = DumpReader.Read(dump);
            Check(parsed.System?.ArchitectureName == "amd64" || parsed.System?.ArchitectureName == "arm64", "Actual DbgHelp system stream");
            Check(parsed.Modules.Count > 0 && parsed.Threads.Count > 0, "Actual DbgHelp modules and threads");
            Check(parsed.Regions.Count > 0, "Actual DbgHelp memory-info stream");
            using var report = JsonDocument.Parse(Reports.Render(Reports.Inspect(parsed, 10), "json"));
            Check(report.RootElement.GetProperty("summary").GetProperty("modules").GetInt32() == parsed.Modules.Count, "Native dump report counts");
            Console.WriteLine("Real Windows DbgHelp oracle passed; temporary dump remains private and is deleted.");
        }
        finally { if (!child.HasExited) { child.StandardInput.WriteLine(); if (!child.WaitForExit(5000)) child.Kill(entireProcessTree: true); } }
    }
    else Console.WriteLine("Windows DbgHelp oracle: not applicable on this OS; synthetic format and coverage oracles run.");
}
finally { Directory.Delete(temp, true); }
Console.WriteLine($"CrashMap core assertions passed: {assertions}");
return 0;

internal static class Native
{
    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MiniDumpWriteDump(IntPtr process, uint id, IntPtr file, uint type, IntPtr exception, IntPtr user, IntPtr callback);
}
