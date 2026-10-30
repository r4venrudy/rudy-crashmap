namespace Rudy.CrashMap;

public sealed record DumpStream(uint Type, uint Size, uint Rva);
public sealed record DumpSystem(ushort Architecture, string ArchitectureName, byte Processors, uint Major, uint Minor, uint Build);
public sealed record DumpModule(ulong Address, uint Size, uint Checksum, uint Timestamp, string Name, string PathSha256, string? PdbIdentity);
public sealed record CapturedRange(ulong Address, ulong Size, ulong FileOffset, string Source);
public sealed record DumpThread(uint Id, ulong StackAddress, uint StackSize, uint ContextSize);
public sealed record MemoryRegion(ulong Address, ulong Size, uint State, uint Protect, uint Type);
public sealed record DumpException(uint ThreadId, uint Code, uint Flags, ulong Address, uint ParameterCount);
public sealed record DumpSnapshot(string Sha256, long Bytes, uint Timestamp, ulong Flags, DumpSystem? System,
    IReadOnlyList<DumpStream> Streams, IReadOnlyList<DumpModule> Modules, IReadOnlyList<DumpThread> Threads,
    IReadOnlyList<CapturedRange> Memory, IReadOnlyList<MemoryRegion> Regions, DumpException? Exception);
public sealed record ModuleChange(string Kind, string Name, int BeforeCount, int AfterCount, DumpModule? Before, DumpModule? After);

public sealed class Limits
{
    public long MaxBytes { get; init; } = 512L * 1024 * 1024;
    public int MaxItems { get; init; } = 100_000;
    internal void Validate()
    {
        if (MaxBytes < 32 || MaxBytes > 4L * 1024 * 1024 * 1024 || MaxItems < 1 || MaxItems > 1_000_000)
            throw new InvalidDataException("Input limits are outside supported bounds.");
    }
}

public static class Address
{
    public static ulong End(ulong start, ulong size)
    {
        if (size > ulong.MaxValue - start) throw new InvalidDataException("Virtual address range overflows 64 bits.");
        return start + size;
    }
    public static bool Contains(ulong start, ulong size, ulong address) => address >= start && address - start < size;
    public static string Hex(ulong value) => "0x" + value.ToString("x16", System.Globalization.CultureInfo.InvariantCulture);
}

// Sorted disjoint unions and cumulative sizes give O(log n) coverage queries.
public sealed class CoverageIndex
{
    private readonly (ulong Start, ulong End)[] ranges;
    private readonly ulong[] prefix;
    public int DisjointRanges => ranges.Length;
    public ulong Bytes => prefix[^1];
    public CoverageIndex(IEnumerable<(ulong Start, ulong Size)> input)
    {
        var ordered = input.Where(r => r.Size != 0).Select(r => (r.Start, End: Address.End(r.Start, r.Size))).OrderBy(r => r.Start).ThenBy(r => r.End);
        var merged = new List<(ulong Start, ulong End)>();
        foreach (var r in ordered)
        {
            if (merged.Count == 0 || r.Start > merged[^1].End) merged.Add(r);
            else merged[^1] = (merged[^1].Start, Math.Max(r.End, merged[^1].End));
        }
        ranges = merged.ToArray(); prefix = new ulong[ranges.Length + 1];
        for (int i = 0; i < ranges.Length; i++) prefix[i + 1] = checked(prefix[i] + ranges[i].End - ranges[i].Start);
    }
    private ulong Before(ulong address)
    {
        int lo = 0, hi = ranges.Length;
        while (lo < hi) { int mid = lo + (hi - lo) / 2; if (ranges[mid].Start < address) lo = mid + 1; else hi = mid; }
        if (lo == 0) return 0;
        var range = ranges[lo - 1];
        return prefix[lo - 1] + Math.Min(address, range.End) - range.Start;
    }
    public ulong Covered(ulong start, ulong size) => Before(Address.End(start, size)) - Before(start);
}

public static class ModuleDiff
{
    // Basenames are a grouping hint, never proof of file identity. Duplicate names stay ambiguous.
    public static IReadOnlyList<ModuleChange> Compare(DumpSnapshot before, DumpSnapshot after)
    {
        var a = before.Modules.GroupBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);
        var b = after.Modules.GroupBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);
        var result = new List<ModuleChange>();
        foreach (var key in a.Keys.Union(b.Keys, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
        {
            var left = a.GetValueOrDefault(key) ?? []; var right = b.GetValueOrDefault(key) ?? [];
            if (left.Length > 1 || right.Length > 1) result.Add(new("ambiguous", key, left.Length, right.Length, null, null));
            else if (left.Length == 0) result.Add(new("added", key, 0, 1, null, right[0]));
            else if (right.Length == 0) result.Add(new("removed", key, 1, 0, left[0], null));
            else if ((left[0].Size, left[0].Checksum, left[0].Timestamp, left[0].PdbIdentity) != (right[0].Size, right[0].Checksum, right[0].Timestamp, right[0].PdbIdentity))
                result.Add(new("metadata-changed", key, 1, 1, left[0], right[0]));
            else if (left[0].Address != right[0].Address) result.Add(new("relocated", key, 1, 1, left[0], right[0]));
        }
        return result;
    }
}
