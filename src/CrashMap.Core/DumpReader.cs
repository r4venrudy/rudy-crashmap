using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Rudy.CrashMap;

public static class DumpReader
{
    private static readonly HashSet<uint> Known = [3, 4, 5, 6, 7, 9, 16];
    public static DumpSnapshot Read(string path, Limits? limits = null)
    {
        limits ??= new(); limits.Validate();
        using var input = new Input(path, limits);
        var header = input.Read(0, 32);
        if (U32(header, 0) != 0x504d444d || (U32(header, 4) & 0xffff) != 0xa793)
            throw new InvalidDataException("Unsupported minidump signature or version.");
        if ((U64(header, 24) & ~0x01ffffffUL) != 0)
            throw new InvalidDataException("Unsupported extended minidump flags; compressed or future encodings are not inferred.");
        uint count = U32(header, 8), directory = U32(header, 12);
        if (count > 256) throw new InvalidDataException("Stream directory exceeds 256 entries.");
        var entries = input.Read(directory, checked((int)count * 12));
        var streams = new List<DumpStream>(); var byType = new Dictionary<uint, DumpStream>();
        for (int i = 0; i < count; i++)
        {
            var stream = new DumpStream(U32(entries, i * 12), U32(entries, i * 12 + 4), U32(entries, i * 12 + 8));
            input.Check(stream.Rva, stream.Size);
            if (Known.Contains(stream.Type) && !byType.TryAdd(stream.Type, stream)) throw new InvalidDataException("Duplicate supported stream type is ambiguous.");
            streams.Add(stream);
        }
        var modules = new List<DumpModule>(); var threads = new List<DumpThread>(); var memory = new List<CapturedRange>(); var regions = new List<MemoryRegion>();
        DumpSystem? system = null; DumpException? exception = null;
        int items = 0;
        void Budget(ulong n)
        {
            if (n > (ulong)(limits.MaxItems - items)) throw new InvalidDataException("Metadata item budget exceeded.");
            items += (int)n;
        }
        byte[] Body(uint type, int minimum)
        {
            var stream = byType[type];
            if (stream.Size < minimum || stream.Size > 16 * 1024 * 1024) throw new InvalidDataException("Supported stream has invalid metadata size.");
            return input.Read(stream.Rva, checked((int)stream.Size));
        }
        if (byType.ContainsKey(7))
        {
            var b = Body(7, 56); ushort arch = U16(b, 0);
            system = new(arch, arch switch { 0 => "x86", 9 => "amd64", 12 => "arm64", 5 => "arm", _ => "unknown" }, b[6], U32(b, 8), U32(b, 12), U32(b, 16));
            uint csd = U32(b, 24); if (csd != 0) input.String(csd); // Validate, but do not expose host strings.
        }
        if (byType.ContainsKey(4))
        {
            var b = Body(4, 4); uint n = U32(b, 0); Budget(n); RequireArray(b, 4, n, 108);
            for (int i = 0; i < n; i++)
            {
                int o = 4 + i * 108; ulong start = U64(b, o); uint size = U32(b, o + 8); Address.End(start, size);
                string fullName = input.String(U32(b, o + 20));
                string name = fullName.Replace('\\', '/').Split('/')[^1];
                if (string.IsNullOrWhiteSpace(name)) name = "unnamed-module";
                string pathHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(fullName)));
                uint cvSize = U32(b, o + 76), cvRva = U32(b, o + 80);
                input.Check(cvRva, cvSize); input.Check(U32(b, o + 88), U32(b, o + 84));
                string? pdb = null;
                if (cvSize >= 24)
                {
                    var cv = input.Read(cvRva, 24);
                    if (U32(cv, 0) == 0x53445352) pdb = new Guid(cv.AsSpan(4, 16)).ToString("N") + "-" + U32(cv, 20).ToString(System.Globalization.CultureInfo.InvariantCulture);
                }
                modules.Add(new(start, size, U32(b, o + 12), U32(b, o + 16), name, pathHash, pdb));
            }
        }
        if (byType.ContainsKey(3))
        {
            var b = Body(3, 4); uint n = U32(b, 0); Budget(n); RequireArray(b, 4, n, 48); var ids = new HashSet<uint>();
            for (int i = 0; i < n; i++)
            {
                int o = 4 + i * 48; uint id = U32(b, o); if (!ids.Add(id)) throw new InvalidDataException("Duplicate thread identifier.");
                ulong start = U64(b, o + 24); uint size = U32(b, o + 32), rva = U32(b, o + 36), context = U32(b, o + 40);
                Address.End(start, size); input.Check(rva, size); input.Check(U32(b, o + 44), context);
                threads.Add(new(id, start, size, context));
                if (size != 0) { Budget(1); memory.Add(new(start, size, rva, "thread-stack")); }
            }
        }
        if (byType.ContainsKey(5))
        {
            var b = Body(5, 4); uint n = U32(b, 0); Budget(n); RequireArray(b, 4, n, 16);
            for (int i = 0; i < n; i++)
            {
                int o = 4 + i * 16; ulong start = U64(b, o); uint size = U32(b, o + 8), rva = U32(b, o + 12);
                Address.End(start, size); input.Check(rva, size); memory.Add(new(start, size, rva, "memory-list"));
            }
        }
        if (byType.ContainsKey(9))
        {
            var b = Body(9, 16); ulong n = U64(b, 0), offset = U64(b, 8); Budget(n); RequireArray(b, 16, n, 16);
            for (int i = 0; (ulong)i < n; i++)
            {
                int o = 16 + i * 16; ulong start = U64(b, o), size = U64(b, o + 8);
                Address.End(start, size); input.Check(offset, size); memory.Add(new(start, size, offset, "memory64-list"));
                offset = checked(offset + size);
            }
        }
        if (byType.ContainsKey(16))
        {
            var b = Body(16, 16); uint headerSize = U32(b, 0), entrySize = U32(b, 4); ulong n = U64(b, 8); Budget(n);
            if (headerSize < 16 || entrySize < 48) throw new InvalidDataException("Memory-info stride is too short.");
            RequireArray(b, headerSize, n, entrySize);
            for (int i = 0; (ulong)i < n; i++)
            {
                int o = checked((int)(headerSize + (ulong)i * entrySize)); ulong start = U64(b, o), size = U64(b, o + 24); Address.End(start, size);
                regions.Add(new(start, size, U32(b, o + 32), U32(b, o + 36), U32(b, o + 40)));
            }
        }
        if (byType.ContainsKey(6))
        {
            var b = Body(6, 168); uint n = U32(b, 32);
            if (n > 15) throw new InvalidDataException("Exception parameter count exceeds the format limit.");
            input.Check(U32(b, 164), U32(b, 160));
            exception = new(U32(b, 0), U32(b, 8), U32(b, 12), U64(b, 24), n);
        }
        input.Recheck();
        return new(input.Sha256, input.Length, U32(header, 20), U64(header, 24), system, streams,
            modules.OrderBy(m => m.Address).ThenBy(m => m.Name, StringComparer.Ordinal).ToArray(),
            threads.OrderBy(t => t.Id).ToArray(), memory.OrderBy(m => m.Address).ThenBy(m => m.FileOffset).ToArray(), regions.OrderBy(r => r.Address).ToArray(), exception);
    }
    private static void RequireArray(byte[] bytes, ulong header, ulong count, ulong stride)
    {
        if (header > (ulong)bytes.Length || stride == 0 || count > ((ulong)bytes.Length - header) / stride)
            throw new InvalidDataException("Stream count or stride exceeds its declared extent.");
    }
    private static ushort U16(byte[] b, int p) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p, 2));
    private static uint U32(byte[] b, int p) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p, 4));
    private static ulong U64(byte[] b, int p) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(p, 8));

    private sealed class Input : IDisposable
    {
        private readonly FileStream stream;
        private int decodedStringBytes;
        public long Length { get; }
        public string Sha256 { get; }
        public Input(string path, Limits limits)
        {
            if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new InvalidDataException("Input must be a regular file rather than a directory or symbolic link.");
            long announcedLength = new FileInfo(path).Length;
            if (announcedLength < 32 || announcedLength > limits.MaxBytes)
                throw new InvalidDataException("Input is truncated or exceeds the byte budget.");
            stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.RandomAccess);
            try
            {
                Length = stream.Length;
                if (Length < 32 || Length > limits.MaxBytes) throw new InvalidDataException("Input is truncated or exceeds the byte budget.");
                Sha256 = Hash();
            }
            catch { stream.Dispose(); throw; }
        }
        public void Check(ulong offset, ulong size)
        {
            if (offset > (ulong)Length || size > (ulong)Length - offset) throw new InvalidDataException("A file range lies outside the captured input.");
        }
        public byte[] Read(ulong offset, int length)
        {
            Check(offset, (ulong)length); var bytes = new byte[length]; int read = 0;
            while (read < length)
            {
                int n = RandomAccess.Read(stream.SafeFileHandle, bytes.AsSpan(read), checked((long)offset + read));
                if (n == 0) throw new InvalidDataException("Input changed or ended during parsing.");
                read += n;
            }
            return bytes;
        }
        public string String(uint rva)
        {
            uint size = U32(Read(rva, 4), 0);
            if (size > 8192 || (size & 1) != 0) throw new InvalidDataException("Minidump string exceeds its UTF-16 budget or has odd byte length.");
            if (size > 16 * 1024 * 1024 - decodedStringBytes) throw new InvalidDataException("Aggregate decoded string budget exceeds 16 MiB.");
            decodedStringBytes += (int)size;
            try { return new UnicodeEncoding(false, false, true).GetString(Read((ulong)rva + 4, (int)size)); }
            catch (DecoderFallbackException) { throw new InvalidDataException("Invalid UTF-16 minidump string."); }
        }
        private string Hash()
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = new byte[65536]; long offset = 0;
            while (offset < Length)
            {
                int n = RandomAccess.Read(stream.SafeFileHandle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, Length - offset)), offset);
                if (n == 0) throw new InvalidDataException("Input changed while hashing.");
                hash.AppendData(buffer, 0, n); offset += n;
            }
            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        public void Recheck() { if (stream.Length != Length || Hash() != Sha256) throw new InvalidDataException("Input changed during analysis."); }
        public void Dispose() => stream.Dispose();
    }
}
