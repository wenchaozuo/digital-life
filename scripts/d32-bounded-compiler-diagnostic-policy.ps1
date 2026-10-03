# Pure policy helpers for the D32 bounded compiler diagnostic.
# This file defines functions only; it never imports modules or launches processes.

$script:D32BoundedCompilerDiagnosticAuthorityType = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_AUTHORITY_V1'
$script:D32BoundedCompilerDiagnosticResultType = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_V1'
$script:D32BoundedCompilerDiagnosticGateAuthority = 'NONE'
$script:D32BoundedCompilerDiagnosticStatuses = @('COMPLETED_DIAGNOSTIC', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED')
$script:D32BoundedCompilerDiagnosticMaxCargoMilliseconds = 1200000
$script:D32BoundedCompilerDiagnosticMaxLaunchMilliseconds = 1800000
$script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds = 120000
$script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds = 60000
$script:D32BoundedCompilerDiagnosticCaptureLimitBytes = 268435456
$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes = 536870912
$script:D32BoundedCompilerDiagnosticRegistryArchiveLimitBytes = 268435456
$script:D32BoundedCompilerDiagnosticSampleSidecarLimitBytes = 67108864
$script:D32BoundedCompilerDiagnosticGitQueryTimeoutMilliseconds = 5000
$script:D32BoundedCompilerDiagnosticGitJoinGraceMilliseconds = 5000
$script:D32BoundedCompilerDiagnosticGitPipeJoinMilliseconds = 5000

function Initialize-D32BoundedCompilerDiagnosticGitPackType {
    if ('D32BoundedGitPackReaderV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

public sealed class D32BoundedGitObjectV1
{
    public string Type { get; internal set; }
    public string Oid { get; internal set; }
    public byte[] Data { get; internal set; }
    internal int Reservation { get; set; }
    internal D32BoundedGitPackReaderV1 Owner { get; set; }
}

public sealed class D32BoundedGitTreeEntryV1
{
    public string Name { get; internal set; }
    public string Mode { get; internal set; }
    public string Kind { get; internal set; }
    public string Oid { get; internal set; }
    internal byte[] NameBytes { get; set; }
}

public sealed class D32BoundedGitPackReaderV1
{
    // The preparation census found a largest approved pack just below 256 MiB.
    // Keep the parser below that observed format ceiling so whole-pack hashing
    // remains bounded without buffering the pack in managed memory.
    private const long MaxPackBytes = 256L * 1024L * 1024L;
    private const long MaxObjectBytes = 64L * 1024L * 1024L;
    private const long MaxWorkingBytes = 512L * 1024L * 1024L;
    private const long MaxExpandedBytes = 32L * 1024L * 1024L * 1024L;
    private const long MaxElapsedMilliseconds = 300000L;
    private const int MaxObjectCount = 500000;
    private const int HashBufferSize = 65536;
    private readonly Stream _pack;
    private byte[] _index;
    private byte[] _oids;
    private uint[] _crcs;
    private long[] _offsets;
    private long[] _sortedOffsets;
    private Dictionary<long, int> _indexByOffset;
    private readonly Stopwatch _timer;
    private readonly long _maxElapsedMilliseconds;
    private readonly long _maxWorkingBytes;
    private readonly long _packLength;
    private readonly int _objectCount;
    private readonly long _retainedEstimate;
    private long _workingBytes;
    private long _peakWorkingBytes;
    private long _expandedBytes;
    private int _resolvedCount;
    private bool _disposed;
    private static readonly uint[] CrcTable = MakeCrcTable();

    public int ObjectCount { get { return _objectCount; } }
    public long PackBytes { get { return _packLength; } }
    public long PeakWorkingBytes { get { return _peakWorkingBytes; } }
    public long ExpandedBytes { get { return _expandedBytes; } }

    public D32BoundedGitPackReaderV1(Stream pack, byte[] indexBytes, string expectedPackId)
        : this(pack, indexBytes, expectedPackId, MaxElapsedMilliseconds, MaxWorkingBytes)
    {
    }

    public D32BoundedGitPackReaderV1(Stream pack, byte[] indexBytes, string expectedPackId, long maximumElapsedMilliseconds)
        : this(pack, indexBytes, expectedPackId, maximumElapsedMilliseconds, MaxWorkingBytes)
    {
    }

    public D32BoundedGitPackReaderV1(Stream pack, byte[] indexBytes, string expectedPackId, long maximumElapsedMilliseconds, long maximumWorkingBytes)
    {
        if (pack == null || indexBytes == null || !pack.CanRead || !pack.CanSeek) throw new InvalidDataException("Git pack/index stream is not readable and seekable");
        if (expectedPackId == null || expectedPackId.Length != 40 || !IsLowerHex(expectedPackId)) throw new InvalidDataException("Git pack filename SHA-1 is malformed");
        if (maximumElapsedMilliseconds <= 0) throw new InvalidDataException("Git source proof has no remaining reserved time");
        if (maximumWorkingBytes <= 0 || maximumWorkingBytes > MaxWorkingBytes) throw new InvalidDataException("Git verifier buffer cap is invalid or exceeds 512 MiB");
        _maxElapsedMilliseconds = Math.Min(MaxElapsedMilliseconds, maximumElapsedMilliseconds);
        _maxWorkingBytes = maximumWorkingBytes;
        _pack = pack;
        _index = indexBytes;
        _packLength = pack.Length;
        _timer = Stopwatch.StartNew();
        if (_packLength < 32 || _packLength > MaxPackBytes || _index.Length < 1072 || _index.Length > 64 * 1024 * 1024) throw new InvalidDataException("Git pack/index exceeds fixed size bounds");
        if (ReadU32(_index, 0) != 0xff744f63U || ReadU32(_index, 4) != 2U) throw new InvalidDataException("Only SHA-1 Git index v2 is supported");
        byte[] indexDigest = Sha1(_index, 0, _index.Length - 20);
        if (!FixedTimeEqual(indexDigest, Slice(_index, _index.Length - 20, 20))) throw new InvalidDataException("Git index checksum mismatch");
        byte[] indexPackDigest = Slice(_index, _index.Length - 40, 20);
        uint count = ReadU32(_index, 8 + 255 * 4);
        if (count == 0 || count > MaxObjectCount) throw new InvalidDataException("Git pack object count is outside the fixed limit");
        _objectCount = checked((int)count);
        long oidStart = 8L + 256L * 4L;
        long crcStart = oidStart + 20L * count;
        long offsetStart = crcStart + 4L * count;
        long largeStart = offsetStart + 4L * count;
        long minimumLength = largeStart + 40L;
        if (minimumLength > _index.Length || ((_index.Length - minimumLength) % 8L) != 0) throw new InvalidDataException("Git index v2 has an invalid length");
        int largeOffsetCount = checked((int)((_index.Length - minimumLength) / 8L));
        if (largeOffsetCount > _objectCount) throw new InvalidDataException("Git index large-offset table exceeds its object count");
        _oids = new byte[checked((int)(20L * count))];
        _crcs = new uint[checked((int)count)];
        _offsets = new long[checked((int)count)];
        _indexByOffset = new Dictionary<long, int>(checked((int)count));
        _retainedEstimate = checked((long)_index.Length + (long)count * 256L + HashBufferSize);
        if (_retainedEstimate > _maxWorkingBytes) throw new InvalidDataException("Git pack index working set exceeds its fixed verifier buffer cap");
        _workingBytes = _retainedEstimate;
        _peakWorkingBytes = _workingBytes;
        uint priorFanout = 0;
        for (int i = 0; i < 256; i++) {
            uint current = ReadU32(_index, 8 + i * 4);
            if (current < priorFanout) throw new InvalidDataException("Git index fanout is not monotonic");
            priorFanout = current;
        }
        if (priorFanout != count) throw new InvalidDataException("Git index fanout count differs from object table");
        uint[] firstByteCounts = new uint[256];
        byte[] priorOid = null;
        for (int i = 0; i < _objectCount; i++) {
            int dest = i * 20;
            Buffer.BlockCopy(_index, checked((int)(oidStart + (long)i * 20L)), _oids, dest, 20);
            byte[] oid = Slice(_oids, dest, 20);
            if (priorOid != null && CompareBytes(priorOid, oid) >= 0) throw new InvalidDataException("Git index object IDs are not strictly sorted");
            priorOid = oid;
            firstByteCounts[oid[0]]++;
            _crcs[i] = ReadU32(_index, checked((int)(crcStart + (long)i * 4L)));
        }
        uint cumulative = 0;
        for (int i = 0; i < 256; i++) {
            cumulative += firstByteCounts[i];
            if (ReadU32(_index, 8 + i * 4) != cumulative) throw new InvalidDataException("Git index fanout does not match the object ID table");
        }
        bool[] largeSlots = new bool[largeOffsetCount];
        for (int i = 0; i < _objectCount; i++) {
            uint raw = ReadU32(_index, checked((int)(offsetStart + (long)i * 4L)));
            long offset;
            if ((raw & 0x80000000U) != 0) {
                uint slot = raw & 0x7fffffffU;
                if (slot >= largeOffsetCount || largeSlots[slot]) throw new InvalidDataException("Git index large-offset table reference is invalid or duplicated");
                largeSlots[slot] = true;
                ulong large = ReadU64(_index, checked((int)(largeStart + (long)slot * 8L)));
                if (large > Int64.MaxValue) throw new InvalidDataException("Git pack offset exceeds supported range");
                offset = (long)large;
            } else offset = raw;
            if (offset < 12 || offset >= _packLength - 20 || !_indexByOffset.TryAdd(offset, i)) throw new InvalidDataException("Git index contains an invalid or duplicate pack offset");
            _offsets[i] = offset;
        }
        for (int i = 0; i < largeSlots.Length; i++) if (!largeSlots[i]) throw new InvalidDataException("Git index has an unreferenced large-offset slot");
        _sortedOffsets = (long[])_offsets.Clone();
        Array.Sort(_sortedOffsets);
        if (_sortedOffsets.Length == 0 || _sortedOffsets[0] != 12L) throw new InvalidDataException("Git pack does not begin with its first indexed object at byte 12");
        for (int i = 0; i < _sortedOffsets.Length; i++) {
            long next = i + 1 < _sortedOffsets.Length ? _sortedOffsets[i + 1] : _packLength - 20L;
            long recordLength = next - _sortedOffsets[i];
            if (recordLength <= 0 || recordLength > MaxObjectBytes) throw new InvalidDataException("Git packed object record boundary exceeds the fixed 64 MiB cap");
        }
        VerifyPack(indexPackDigest, expectedPackId);
    }

    public D32BoundedGitObjectV1 Resolve(string oidHex)
    {
        EnsureLive();
        if (oidHex == null || oidHex.Length != 40 || !IsLowerHex(oidHex)) throw new InvalidDataException("Git object ID is malformed");
        byte[] oid = HexToBytes(oidHex);
        int index = FindOid(oid);
        if (index < 0) throw new InvalidDataException("Locked Git object is absent from the exact pinned pack index");
        return ResolveIndex(index, 0, new HashSet<int>());
    }

    public void Release(D32BoundedGitObjectV1 value)
    {
        if (value == null || value.Owner != this || value.Data == null) throw new InvalidDataException("Git object buffer release is invalid or duplicated");
        ReleaseBytes(value.Reservation);
        value.Data = null;
        value.Owner = null;
    }

    public static string CommitTreeOid(byte[] body)
    {
        if (body == null || body.Length == 0 || body.Length > 1024 * 1024) throw new InvalidDataException("Git commit body is empty or exceeds 1 MiB");
        int end = Array.IndexOf(body, (byte)10);
        if (end <= 5) throw new InvalidDataException("Git commit has no first tree line");
        string first = Encoding.ASCII.GetString(body, 0, end);
        if (!first.StartsWith("tree ", StringComparison.Ordinal) || first.Length != 45 || !IsLowerHex(first.Substring(5))) throw new InvalidDataException("Git commit first header is not a SHA-1 tree reference");
        int cursor = end + 1;
        bool blank = false;
        while (cursor < body.Length) {
            int lineEnd = Array.IndexOf(body, (byte)10, cursor);
            if (lineEnd < 0) throw new InvalidDataException("Git commit header is not LF-terminated");
            if (lineEnd == cursor) { blank = true; break; }
            string line = Encoding.ASCII.GetString(body, cursor, lineEnd - cursor);
            if (line.StartsWith("tree ", StringComparison.Ordinal)) throw new InvalidDataException("Git commit has a duplicate tree header");
            if (line.StartsWith("parent ", StringComparison.Ordinal) && (line.Length != 47 || !IsLowerHex(line.Substring(7)))) throw new InvalidDataException("Git commit parent header is malformed");
            cursor = lineEnd + 1;
        }
        if (!blank) throw new InvalidDataException("Git commit has no header/body separator");
        return first.Substring(5);
    }

    public static D32BoundedGitTreeEntryV1[] ParseTree(byte[] body)
    {
        if (body == null || body.Length > MaxObjectBytes) throw new InvalidDataException("Git tree body exceeds the fixed object bound");
        List<D32BoundedGitTreeEntryV1> result = new List<D32BoundedGitTreeEntryV1>();
        HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        byte[] previous = null;
        bool previousTree = false;
        int cursor = 0;
        UTF8Encoding strictUtf8 = new UTF8Encoding(false, true);
        while (cursor < body.Length) {
            if (result.Count >= 100000) throw new InvalidDataException("Git tree entry count exceeds the fixed 100000 limit");
            int modeStart = cursor;
            while (cursor < body.Length && body[cursor] != 32) cursor++;
            if (cursor == modeStart || cursor >= body.Length) throw new InvalidDataException("Git tree mode separator is malformed");
            string mode = Encoding.ASCII.GetString(body, modeStart, cursor - modeStart);
            for (int i = 0; i < mode.Length; i++) if (mode[i] < '0' || mode[i] > '7') throw new InvalidDataException("Git tree mode is not octal");
            cursor++;
            int nameStart = cursor;
            while (cursor < body.Length && body[cursor] != 0) cursor++;
            if (cursor == nameStart || cursor >= body.Length) throw new InvalidDataException("Git tree name is empty or unterminated");
            byte[] nameBytes = Slice(body, nameStart, cursor - nameStart);
            string name;
            try { name = strictUtf8.GetString(nameBytes); } catch { throw new InvalidDataException("Git tree name is not strict UTF-8"); }
            if (!IsSafeTreeName(name) || !names.Add(name)) throw new InvalidDataException("Git tree name is unsafe or case-colliding on Windows");
            cursor++;
            if (body.Length - cursor < 20) throw new InvalidDataException("Git tree object ID is truncated");
            string oid = BytesToHex(body, cursor, 20);
            cursor += 20;
            string kind;
            if (mode == "40000") kind = "tree";
            else if (mode == "100644" || mode == "100755") kind = "blob";
            else if (mode == "120000") kind = "symlink";
            else if (mode == "160000") kind = "gitlink";
            else throw new InvalidDataException("Git tree mode is unsupported");
            if (previous != null && CompareTreeNames(previous, previousTree, nameBytes, kind == "tree") >= 0) throw new InvalidDataException("Git tree entries are not in canonical Git order");
            previous = nameBytes;
            previousTree = kind == "tree";
            result.Add(new D32BoundedGitTreeEntryV1 { Name = name, Mode = mode, Kind = kind, Oid = oid, NameBytes = nameBytes });
        }
        return result.ToArray();
    }

    public static uint ComputeCrc32(byte[] bytes, int offset, int count)
    {
        if (bytes == null || offset < 0 || count < 0 || offset > bytes.Length - count) throw new InvalidDataException("CRC input bounds are invalid");
        uint crc = 0xffffffffU;
        for (int i = offset; i < offset + count; i++) crc = CrcTable[(crc ^ bytes[i]) & 0xffU] ^ (crc >> 8);
        return crc ^ 0xffffffffU;
    }

    private D32BoundedGitObjectV1 ResolveIndex(int index, int depth, HashSet<int> active)
    {
        CheckDeadline();
        if (depth > 32 || index < 0 || index >= _objectCount || !active.Add(index)) throw new InvalidDataException("Git delta chain is cyclic or exceeds depth 32");
        if (++_resolvedCount > MaxObjectCount) throw new InvalidDataException("Git object resolution count exceeds 500000");
        D32BoundedGitObjectV1 baseObject = null;
        byte[] entryBytes = null;
        byte[] inflated = null;
        byte[] output = null;
        long entryBudget = 0;
        long inflatedBudget = 0;
        long outputBudget = 0;
        bool outputReturned = false;
        try {
            long start = _offsets[index];
            long next = NextOffset(start);
            int entryLength = checked((int)(next - start));
            if (entryLength <= 0 || entryLength > MaxObjectBytes) throw new InvalidDataException("Git pack entry boundary is invalid or exceeds 64 MiB");
            Reserve(entryLength);
            entryBudget = entryLength;
            entryBytes = new byte[entryLength];
            _pack.Position = start;
            ReadExactly(_pack, entryBytes, 0, entryLength);
            if (ComputeCrc32(entryBytes, 0, entryLength) != _crcs[index]) throw new InvalidDataException("Git pack entry CRC differs from its v2 index record");
            int cursor = 0;
            int first = entryBytes[cursor++];
            int type = (first >> 4) & 7;
            long declaredSize = first & 15;
            int shift = 4;
            int current = first;
            int guard = 0;
            while ((current & 128) != 0) {
                if (cursor >= entryBytes.Length || shift >= 63 || ++guard > 9) throw new InvalidDataException("Git pack object header size varint is malformed");
                current = entryBytes[cursor++];
                declaredSize |= ((long)(current & 127)) << shift;
                shift += 7;
            }
            if (declaredSize < 0 || declaredSize > MaxObjectBytes) throw new InvalidDataException("Git pack object declared size exceeds 64 MiB");
            int baseIndex = -1;
            if (type == 6) {
                if (cursor >= entryBytes.Length) throw new InvalidDataException("Git OFS_DELTA base distance is truncated");
                int b = entryBytes[cursor++];
                long distance = b & 127;
                int ofsGuard = 0;
                while ((b & 128) != 0) {
                    if (cursor >= entryBytes.Length || ++ofsGuard > 9) throw new InvalidDataException("Git OFS_DELTA distance is malformed");
                    b = entryBytes[cursor++];
                    if (distance > (Int64.MaxValue >> 7)) throw new InvalidDataException("Git OFS_DELTA distance overflows");
                    distance = ((distance + 1) << 7) | (long)(b & 127);
                }
                long baseOffset = start - distance;
                if (distance <= 0 || baseOffset >= start || !_indexByOffset.TryGetValue(baseOffset, out baseIndex)) throw new InvalidDataException("Git OFS_DELTA base offset is not indexed");
            } else if (type == 7) {
                if (entryBytes.Length - cursor < 20) throw new InvalidDataException("Git REF_DELTA base object ID is truncated");
                byte[] baseOid = Slice(entryBytes, cursor, 20);
                cursor += 20;
                baseIndex = FindOid(baseOid);
                if (baseIndex < 0) throw new InvalidDataException("Git REF_DELTA base is absent from the exact locked repository pack");
            } else if (type < 1 || type > 4) throw new InvalidDataException("Git pack object type is reserved or unsupported");
            int compressedLength = entryBytes.Length - cursor;
            if (compressedLength <= 0 || compressedLength > MaxObjectBytes) throw new InvalidDataException("Git compressed object range is empty or exceeds 64 MiB");
            int declared = checked((int)declaredSize);
            Reserve(declared);
            inflatedBudget = declared;
            inflated = InflateExact(entryBytes, cursor, compressedLength, declared);
            ReleaseBytes(entryLength);
            entryBudget = 0;
            entryBytes = null;
            _expandedBytes = checked(_expandedBytes + declared);
            if (_expandedBytes > MaxExpandedBytes) throw new InvalidDataException("Git object decompression exceeds 32 GiB aggregate");
            if (type == 6 || type == 7) {
                baseObject = ResolveIndex(baseIndex, depth + 1, active);
                long resultLength = DeltaResultLength(inflated, baseObject.Data.Length);
                if (resultLength < 0 || resultLength > MaxObjectBytes) throw new InvalidDataException("Git delta result exceeds 64 MiB");
                Reserve(checked((int)resultLength));
                outputBudget = resultLength;
                output = ApplyDelta(baseObject.Data, inflated, (int)resultLength);
                ReleaseBytes(declared);
                inflatedBudget = 0;
                inflated = null;
                string resolvedType = baseObject.Type;
                Release(baseObject);
                baseObject = null;
                _expandedBytes = checked(_expandedBytes + resultLength);
                if (_expandedBytes > MaxExpandedBytes) throw new InvalidDataException("Git reconstructed object bytes exceed 32 GiB aggregate");
                return CreateVerifiedObject(index, resolvedType, output, ref outputReturned);
            }
            D32BoundedGitObjectV1 verified = CreateVerifiedObject(index, TypeName(type), inflated, ref outputReturned);
            inflatedBudget = 0;
            inflated = null;
            return verified;
        }
        finally {
            if (entryBytes != null) ReleaseBytes(entryBytes.Length); else if (entryBudget > 0) ReleaseBytes(entryBudget);
            if (inflated != null) ReleaseBytes(inflated.Length); else if (inflatedBudget > 0) ReleaseBytes(inflatedBudget);
            if (baseObject != null) Release(baseObject);
            if (output != null && !outputReturned) ReleaseBytes(output.Length); else if (output == null && outputBudget > 0 && !outputReturned) ReleaseBytes(outputBudget);
            active.Remove(index);
        }
    }
    private D32BoundedGitObjectV1 CreateVerifiedObject(int index, string type, byte[] data, ref bool returned)
    {
        byte[] digest = HashGitObject(type, data);
        if (!FixedTimeEqual(digest, Slice(_oids, index * 20, 20))) throw new InvalidDataException("Git object body SHA-1 does not match its indexed object ID");
        string oid = BytesToHex(_oids, index * 20, 20);
        returned = true;
        return new D32BoundedGitObjectV1 { Type = type, Oid = oid, Data = data, Reservation = data.Length, Owner = this };
    }

    private long DeltaResultLength(byte[] delta, int baseLength)
    {
        int cursor = 0;
        long sourceLength = ReadDeltaVarint(delta, ref cursor);
        long resultLength = ReadDeltaVarint(delta, ref cursor);
        if (sourceLength != baseLength || resultLength > MaxObjectBytes) throw new InvalidDataException("Git delta source/result length is invalid");
        return resultLength;
    }

    private byte[] ApplyDelta(byte[] baseData, byte[] delta, int resultLength)
    {
        int cursor = 0;
        long sourceLength = ReadDeltaVarint(delta, ref cursor);
        long encodedResultLength = ReadDeltaVarint(delta, ref cursor);
        if (sourceLength != baseData.Length || encodedResultLength != resultLength) throw new InvalidDataException("Git delta header lengths do not match their base/result buffers");
        byte[] result = new byte[resultLength];
        int written = 0;
        while (cursor < delta.Length) {
            int instruction = delta[cursor++];
            if ((instruction & 128) != 0) {
                long offset = 0;
                long size = 0;
                int optionalBytes = 0;
                if ((instruction & 1) != 0) optionalBytes++;
                if ((instruction & 2) != 0) optionalBytes++;
                if ((instruction & 4) != 0) optionalBytes++;
                if ((instruction & 8) != 0) optionalBytes++;
                if ((instruction & 16) != 0) optionalBytes++;
                if ((instruction & 32) != 0) optionalBytes++;
                if ((instruction & 64) != 0) optionalBytes++;
                if (cursor > delta.Length - optionalBytes) throw new InvalidDataException("Git delta copy instruction is truncated");
                if ((instruction & 1) != 0) offset |= delta[cursor++];
                if ((instruction & 2) != 0) offset |= (long)delta[cursor++] << 8;
                if ((instruction & 4) != 0) offset |= (long)delta[cursor++] << 16;
                if ((instruction & 8) != 0) offset |= (long)delta[cursor++] << 24;
                if ((instruction & 16) != 0) size |= delta[cursor++];
                if ((instruction & 32) != 0) size |= (long)delta[cursor++] << 8;
                if ((instruction & 64) != 0) size |= (long)delta[cursor++] << 16;
                if (size == 0) size = 65536;
                if (offset < 0 || size < 0 || offset > baseData.Length - size || written > result.Length - size) throw new InvalidDataException("Git delta copy instruction is out of bounds");
                Buffer.BlockCopy(baseData, checked((int)offset), result, written, checked((int)size));
                written += checked((int)size);
            } else {
                int insert = instruction & 127;
                if (insert == 0 || cursor > delta.Length - insert || written > result.Length - insert) throw new InvalidDataException("Git delta insert instruction is empty or out of bounds");
                Buffer.BlockCopy(delta, cursor, result, written, insert);
                cursor += insert;
                written += insert;
            }
        }
        if (written != result.Length) throw new InvalidDataException("Git delta did not produce its declared result length");
        return result;
    }

    private long ReadDeltaVarint(byte[] data, ref int cursor)
    {
        long value = 0;
        int shift = 0;
        int guard = 0;
        int b;
        do {
            if (cursor >= data.Length || shift >= 63 || ++guard > 9) throw new InvalidDataException("Git delta length varint is malformed");
            b = data[cursor++];
            value |= (long)(b & 127) << shift;
            shift += 7;
        } while ((b & 128) != 0);
        return value;
    }

    private byte[] InflateExact(byte[] source, int offset, int length, int expectedSize)
    {
        Reserve(HashBufferSize);
        try {
            byte[] output = new byte[expectedSize];
            using (MemoryStream input = new MemoryStream(source, offset, length, false, true))
            using (ZLibStream inflater = new ZLibStream(input, CompressionMode.Decompress, true)) {
                int cursor = 0;
                while (cursor < output.Length) {
                    CheckDeadline();
                    int read = inflater.Read(output, cursor, output.Length - cursor);
                    if (read <= 0) throw new InvalidDataException("Git zlib stream is truncated before its declared object size");
                    cursor += read;
                }
                if (inflater.ReadByte() != -1) throw new InvalidDataException("Git zlib stream exceeds its declared object size");
            }
            return output;
        } catch { throw; }
        finally { ReleaseBytes(HashBufferSize); }
    }

    private long NextOffset(long offset)
    {
        int index = Array.BinarySearch(_sortedOffsets, offset);
        if (index < 0) throw new InvalidDataException("Git indexed object offset is not in its sorted offset table");
        return index + 1 < _sortedOffsets.Length ? _sortedOffsets[index + 1] : _packLength - 20L;
    }

    private int FindOid(byte[] oid)
    {
        int low = 0, high = _objectCount - 1;
        while (low <= high) {
            int mid = low + ((high - low) >> 1);
            int compare = CompareBytes(_oids, mid * 20, oid, 0, 20);
            if (compare == 0) return mid;
            if (compare < 0) low = mid + 1; else high = mid - 1;
        }
        return -1;
    }

    private void VerifyPack(byte[] indexPackDigest, string expectedPackId)
    {
        byte[] header = new byte[12];
        _pack.Position = 0;
        ReadExactly(_pack, header, 0, header.Length);
        if (Encoding.ASCII.GetString(header, 0, 4) != "PACK" || ReadU32(header, 4) != 2U || ReadU32(header, 8) != (uint)_objectCount) throw new InvalidDataException("Git pack header/version/object count differs from its v2 index");
        byte[] trailer = new byte[20];
        _pack.Position = _packLength - 20L;
        ReadExactly(_pack, trailer, 0, 20);
        byte[] digest = HashStreamPrefix(_pack, _packLength - 20L);
        if (!FixedTimeEqual(digest, trailer) || !FixedTimeEqual(indexPackDigest, trailer) || BytesToHex(trailer, 0, 20) != expectedPackId) throw new InvalidDataException("Git pack trailer, index pack checksum, or filename SHA-1 mismatch");
        _pack.Position = 0;
    }

    private byte[] HashStreamPrefix(Stream stream, long count)
    {
        byte[] buffer = new byte[HashBufferSize];
        long original = stream.Position;
        try {
            stream.Position = 0;
            using (SHA1 sha = SHA1.Create()) {
                long remaining = count;
                while (remaining > 0) {
                    CheckDeadline();
                    int take = (int)Math.Min((long)buffer.Length, remaining);
                    int read = stream.Read(buffer, 0, take);
                    if (read <= 0) throw new InvalidDataException("Git pack ended during streaming checksum");
                    sha.TransformBlock(buffer, 0, read, buffer, 0);
                    remaining -= read;
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return sha.Hash;
            }
        } finally { stream.Position = original; }
    }

    private byte[] HashGitObject(string type, byte[] body)
    {
        byte[] prefix = Encoding.ASCII.GetBytes(type + " " + body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\0");
        using (SHA1 sha = SHA1.Create()) {
            sha.TransformBlock(prefix, 0, prefix.Length, prefix, 0);
            sha.TransformBlock(body, 0, body.Length, body, 0);
            sha.TransformFinalBlock(new byte[0], 0, 0);
            return sha.Hash;
        }
    }

    private void Reserve(long count)
    {
        if (count < 0 || _workingBytes > _maxWorkingBytes - count) throw new InvalidDataException("Git verifier-managed buffers exceed their fixed cap");
        _workingBytes += count;
        if (_workingBytes > _peakWorkingBytes) _peakWorkingBytes = _workingBytes;
    }

    private void ReleaseBytes(long count)
    {
        if (count < 0 || count > _workingBytes - _retainedEstimate) throw new InvalidDataException("Git verifier-managed buffer accounting underflow");
        _workingBytes -= count;
    }

    private void CheckDeadline()
    {
        if (_timer.ElapsedMilliseconds > _maxElapsedMilliseconds) throw new InvalidDataException("Git source proof exceeded its remaining 300-second budget");
    }

    private void EnsureLive() { if (_disposed) throw new ObjectDisposedException("D32BoundedGitPackReaderV1"); CheckDeadline(); }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_indexByOffset != null) _indexByOffset.Clear();
        _index = null;
        _oids = null;
        _crcs = null;
        _offsets = null;
        _sortedOffsets = null;
    }

    private static uint[] MakeCrcTable()
    {
        uint[] table = new uint[256];
        for (uint n = 0; n < 256; n++) {
            uint c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xedb88320U ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }

    private static byte[] Sha1(byte[] bytes, int offset, int count)
    {
        using (SHA1 sha = SHA1.Create()) return sha.ComputeHash(bytes, offset, count);
    }

    private static uint ReadU32(byte[] bytes, int offset)
    {
        if (offset < 0 || offset > bytes.Length - 4) throw new InvalidDataException("Git binary field is truncated");
        return ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3];
    }

    private static ulong ReadU64(byte[] bytes, int offset)
    {
        if (offset < 0 || offset > bytes.Length - 8) throw new InvalidDataException("Git binary field is truncated");
        ulong result = 0;
        for (int i = 0; i < 8; i++) result = (result << 8) | bytes[offset + i];
        return result;
    }

    private static byte[] Slice(byte[] bytes, int offset, int count)
    {
        if (offset < 0 || count < 0 || offset > bytes.Length - count) throw new InvalidDataException("Git binary slice exceeds its buffer");
        byte[] result = new byte[count];
        Buffer.BlockCopy(bytes, offset, result, 0, count);
        return result;
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        while (count > 0) {
            int read = stream.Read(buffer, offset, count);
            if (read <= 0) throw new InvalidDataException("Git pack/index input is truncated");
            offset += read;
            count -= read;
        }
    }

    private static int CompareBytes(byte[] left, byte[] right) { return CompareBytes(left, 0, right, 0, Math.Min(left.Length, right.Length)); }

    private static int CompareBytes(byte[] left, int lo, byte[] right, int ro, int count)
    {
        for (int i = 0; i < count; i++) if (left[lo + i] != right[ro + i]) return left[lo + i] < right[ro + i] ? -1 : 1;
        return 0;
    }

    private static string TypeName(int type)
    {
        switch (type) { case 1: return "commit"; case 2: return "tree"; case 3: return "blob"; case 4: return "tag"; default: throw new InvalidDataException("Git object type is unsupported"); }
    }

    private static bool FixedTimeEqual(byte[] left, byte[] right)
    {
        if (left == null || right == null || left.Length != right.Length) return false;
        int diff = 0;
        for (int i = 0; i < left.Length; i++) diff |= left[i] ^ right[i];
        return diff == 0;
    }

    private static bool IsLowerHex(string value)
    {
        if (value == null) return false;
        for (int i = 0; i < value.Length; i++) if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
        return true;
    }

    private static byte[] HexToBytes(string hex)
    {
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++) result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return result;
    }

    private static string BytesToHex(byte[] bytes, int offset, int count)
    {
        StringBuilder result = new StringBuilder(count * 2);
        for (int i = 0; i < count; i++) result.Append(bytes[offset + i].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        return result.ToString();
    }

    private static bool IsSafeTreeName(string name)
    {
        if (String.IsNullOrEmpty(name) || name == "." || name == ".." || name.EndsWith(".", StringComparison.Ordinal) || name.EndsWith(" ", StringComparison.Ordinal) ||
            !String.Equals(name, name.Normalize(NormalizationForm.FormC), StringComparison.Ordinal)) return false;
        for (int i = 0; i < name.Length; i++) if (name[i] < 32 || name[i] == 127 || "\\/:*?\"<>|".IndexOf(name[i]) >= 0) return false;
        string stem = name.Split('.')[0];
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)) return false;
        for (int i = 1; i <= 9; i++) if (stem.Equals("COM" + i, StringComparison.OrdinalIgnoreCase) || stem.Equals("LPT" + i, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static int CompareTreeNames(byte[] left, bool leftTree, byte[] right, bool rightTree)
    {
        int limit = Math.Max(left.Length, right.Length);
        for (int i = 0; i <= limit; i++) {
            int a = i < left.Length ? left[i] : (leftTree ? 47 : 0);
            int b = i < right.Length ? right[i] : (rightTree ? 47 : 0);
            if (a != b) return a < b ? -1 : 1;
        }
        return 0;
    }
}
'@
}

function Get-D32BoundedCompilerDiagnosticFixedArgv {
    return @('test', '--manifest-path', 'vita-agent/Cargo.toml', '--all-targets', '--locked', '--offline',
        '--features', 'd32-a-test-helper', '--jobs', '4', '--no-run', '--message-format=json', '-vv')
}

function Test-D32BoundedCompilerDiagnosticExactProperties {
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string[]]$Expected)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [Array] -or $Object -is [ValueType]) { return $false }
    $actual = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $Object.PSObject.Properties) { [void]$actual.Add([string]$property.Name) }
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if (-not $actual.Contains($name)) { return $false } }
    return $true
}

function Test-D32BoundedCompilerDiagnosticInteger {
    param([AllowNull()][object]$Value, [switch]$Positive)
    $isInteger = $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]
    if (-not $isInteger) { return $false }
    if ($Positive) { return ([Int64]$Value -gt 0) }
    return ([Int64]$Value -ge 0)
}

function Get-D32BoundedCompilerDiagnosticGlobalWriterCensus {
    param([Parameter(Mandatory = $true)][scriptblock]$ProcessProbe)
    try { $probeResult = & $ProcessProbe }
    catch { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: Win32_Process target-writer census failed' }
    if ($null -eq $probeResult) { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census returned no verifiable result' }
    $processes = @($probeResult)
    if ($processes.Count -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census returned an empty, unverifiable result' }

    $writerNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('cargo.exe', 'rustc.exe', 'cl.exe', 'link.exe', 'build-script-build.exe')) { [void]$writerNames.Add($name) }
    $targetWriters = [System.Collections.Generic.List[string]]::new()
    foreach ($process in $processes) {
        $nameProperty = if ($null -eq $process) { $null } else { $process.PSObject.Properties['Name'] }
        $processIdProperty = if ($null -eq $process) { $null } else { $process.PSObject.Properties['ProcessId'] }
        if ($null -eq $nameProperty -or $null -eq $processIdProperty -or $nameProperty.Value -isnot [string] -or
            [String]::IsNullOrWhiteSpace([string]$nameProperty.Value) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger -Value $processIdProperty.Value)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census contains an incomplete process identity'
        }
        $processName = [string]$nameProperty.Value
        $processId = [Int64]$processIdProperty.Value

        # Match the frozen Phase 0 census exceptions exactly; all other malformed
        # reserved identities fail closed instead of being treated as ordinary rows.
        if ($processId -eq 0 -or $processName -ceq 'System Idle Process') {
            $parentProperty = $process.PSObject.Properties['ParentProcessId']
            if ($processId -ne 0 -or $processName -cne 'System Idle Process' -or $null -eq $parentProperty -or
                -not (Test-D32BoundedCompilerDiagnosticInteger -Value $parentProperty.Value) -or [Int64]$parentProperty.Value -ne 0) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: PID-zero row is not the exact Windows System Idle Process identity'
            }
            continue
        }
        if ($processId -eq 4 -or $processName -ceq 'System') {
            $parentProperty = $process.PSObject.Properties['ParentProcessId']
            if ($processId -ne 4 -or $processName -cne 'System' -or $null -eq $parentProperty -or
                -not (Test-D32BoundedCompilerDiagnosticInteger -Value $parentProperty.Value) -or [Int64]$parentProperty.Value -ne 0) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: PID-four row is not the exact Windows System process identity'
            }
            continue
        }
        if ($processId -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census contains an incomplete process identity' }
        if ($writerNames.Contains($processName)) {
            $targetWriters.Add("${processName} PID=${processId}: active build-class process cannot be excluded from candidate target trees")
        }
    }
    return [PSCustomObject]@{
        process_count = [Int64]$processes.Count
        competing_target_writer_count = [Int64]$targetWriters.Count
        target_writer_check = 'Win32-CIM-active-build-process-census'
        competing_target_writers = @($targetWriters.ToArray())
    }
}

function Assert-D32BoundedCompilerDiagnosticNoGlobalWriter {
    param([Parameter(Mandatory = $true)][scriptblock]$ProcessProbe)
    $census = Get-D32BoundedCompilerDiagnosticGlobalWriterCensus -ProcessProbe $ProcessProbe
    if ([Int64]$census.competing_target_writer_count -gt 0) {
        throw ('D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: competing target writer exists: ' + (@($census.competing_target_writers) -join '; '))
    }
    return $census
}

function Test-D32BoundedCompilerDiagnosticFixedArgv {
    param([AllowNull()][object]$Arguments)
    if ($Arguments -isnot [Array] -or $Arguments.Count -ne (Get-D32BoundedCompilerDiagnosticFixedArgv).Count) { return $false }
    $expected = @(Get-D32BoundedCompilerDiagnosticFixedArgv)
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($Arguments[$index] -isnot [string] -or [string]$Arguments[$index] -cne $expected[$index]) { return $false }
    }
    return $true
}

function Assert-D32BoundedCompilerDiagnosticBudget {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Budget)
    $fields = @('cargo_timeout_ms', 'owned_launch_timeout_ms', 'cleanup_reserve_ms', 'persist_reserve_ms', 'sample_period_ms', 'raw_capture_limit_bytes', 'cargo_jobs')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Budget -Expected $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.cargo_timeout_ms -Positive) -or [Int64]$Budget.cargo_timeout_ms -ne $script:D32BoundedCompilerDiagnosticMaxCargoMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.owned_launch_timeout_ms -Positive) -or [Int64]$Budget.owned_launch_timeout_ms -ne $script:D32BoundedCompilerDiagnosticMaxLaunchMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.cleanup_reserve_ms -Positive) -or [Int64]$Budget.cleanup_reserve_ms -lt $script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.persist_reserve_ms -Positive) -or [Int64]$Budget.persist_reserve_ms -lt $script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.sample_period_ms -Positive) -or [Int64]$Budget.sample_period_ms -ne 10000 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.raw_capture_limit_bytes -Positive) -or [Int64]$Budget.raw_capture_limit_bytes -ne $script:D32BoundedCompilerDiagnosticCaptureLimitBytes -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.cargo_jobs -Positive) -or [Int64]$Budget.cargo_jobs -ne 4 -or
        ([Int64]$Budget.cargo_timeout_ms + [Int64]$Budget.cleanup_reserve_ms + [Int64]$Budget.persist_reserve_ms) -gt [Int64]$Budget.owned_launch_timeout_ms) {
        throw 'D32_BOUNDED_DIAGNOSTIC_BUDGET_BLOCKED: exact Cargo/launch ceilings, reserved cleanup/persist time, sample cadence, capture cap, and jobs are mandatory'
    }
    return $true
}

function Assert-D32BoundedCompilerDiagnosticStatus {
    param([Parameter(Mandatory = $true)][string]$Status)
    if ($script:D32BoundedCompilerDiagnosticStatuses -cnotcontains $Status) {
        throw 'D32_BOUNDED_DIAGNOSTIC_STATUS_BLOCKED: diagnostic status is outside the four non-PASS outcomes'
    }
    return $Status
}

function Test-D32BoundedCompilerDiagnosticFormalReject {
    param([AllowNull()][object]$Record)
    if ($null -eq $Record) { return $true }
    return ($Record.record_type -isnot [string] -or [string]$Record.record_type -cne 'D32_PHASE0_MATRIX_RECORD_V8' -or
        $Record.gate_authority -isnot [string] -or [string]$Record.gate_authority -cne 'PHASE0' -or
        $Record.status -isnot [string] -or [string]$Record.status -cne 'PASS')
}

function Test-D32BoundedCompilerDiagnosticCanonicalPath {
    param([AllowNull()][object]$Value)
    if ($Value -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$Value) -or -not [IO.Path]::IsPathRooted([string]$Value)) { return $false }
    try { return [IO.Path]::GetFullPath([string]$Value).TrimEnd('\', '/') -ceq ([string]$Value).TrimEnd('\', '/') }
    catch { return $false }
}

function Test-D32BoundedCompilerDiagnosticWithin {
    param([string]$Child, [string]$Parent)
    try {
        $childFull = [IO.Path]::GetFullPath($Child).TrimEnd('\', '/')
        $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
        return $childFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
            $childFull.StartsWith($parentFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Test-D32BoundedCompilerDiagnosticIdentityPair {
    param([AllowNull()][object]$Object, [string]$VolumeName = 'volume_serial_hex', [string]$FileIdName = 'file_id_hex')
    if ($null -eq $Object -or $Object.PSObject.Properties[$VolumeName] -eq $null -or $Object.PSObject.Properties[$FileIdName] -eq $null) { return $false }
    return ([string]$Object.$VolumeName -cmatch '^[0-9a-f]{16}$' -and [string]$Object.$FileIdName -cmatch '^[0-9a-f]{32}$')
}

function Test-D32BoundedCompilerDiagnosticFileReferenceShape {
    param([AllowNull()][object]$Reference)
    return ((Test-D32BoundedCompilerDiagnosticExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -and
        (Test-D32BoundedCompilerDiagnosticCanonicalPath $Reference.path) -and
        (Test-D32BoundedCompilerDiagnosticInteger $Reference.bytes -Positive) -and
        [string]$Reference.sha256 -cmatch '^[0-9a-f]{64}$' -and (Test-D32BoundedCompilerDiagnosticIdentityPair $Reference))
}

function Test-D32BoundedCompilerDiagnosticGitQueryList {
    param([AllowNull()][object]$Queries)
    $expectedRows = [System.Collections.Generic.List[object]]::new()
    $expectedRows.Add([string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'))
    $expectedRows.Add([string[]]@('status', '--porcelain=v1', '--untracked-files=all'))
    $expectedRows.Add([string[]]@('ls-files', '-v', '-z'))
    $expectedRows.Add([string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'))
    $expectedRows.Add([string[]]@('status', '--porcelain=v1', '--untracked-files=all'))
    $expected = $expectedRows.ToArray()
    if ($Queries -isnot [Array] -or $Queries.Count -ne $expected.Count) { return $false }
    for ($i = 0; $i -lt $expected.Count; $i++) {
        if ($Queries[$i] -isnot [Array] -or $Queries[$i].Count -ne $expected[$i].Count) { return $false }
        for ($j = 0; $j -lt $expected[$i].Count; $j++) {
            if ($Queries[$i][$j] -isnot [string] -or [string]$Queries[$i][$j] -cne [string]$expected[$i][$j]) { return $false }
        }
    }
    return $true
}

function Test-D32BoundedCompilerDiagnosticFixedGitQuery {
    param([AllowNull()][object]$Arguments)
    if ($Arguments -isnot [Array]) { return $false }
    $allowed = [object[]]::new(3)
    $allowed[0] = [string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}')
    $allowed[1] = [string[]]@('status', '--porcelain=v1', '--untracked-files=all')
    $allowed[2] = [string[]]@('ls-files', '-v', '-z')
    foreach ($candidate in $allowed) {
        if ($Arguments.Count -ne $candidate.Count) { continue }
        $matches = $true
        for ($index = 0; $index -lt $candidate.Count; $index++) {
            if ($Arguments[$index] -isnot [string] -or [string]$Arguments[$index] -cne $candidate[$index]) { $matches = $false; break }
        }
        if ($matches) { return $true }
    }
    return $false
}

function Test-D32BoundedCompilerDiagnosticHistoricalReplay {
    param([AllowNull()][object]$SourceClosure)
    return ($null -ne $SourceClosure -and
        [string]$SourceClosure.HistoricalFetchCompletion -ceq 'NOT_RETAINED' -and
        [string]$SourceClosure.HistoricalAttemptState -ceq 'BLOCKED' -and
        [string]$SourceClosure.HistoricalGateAuthority -ceq 'NONE')
}

function Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks {
    param(
        [Parameter(Mandatory = $true)][long]$NowTicks,
        [Parameter(Mandatory = $true)][long]$StopwatchFrequency,
        [Parameter(Mandatory = $true)][long]$OverallDeadlineTicks,
        [Parameter(Mandatory = $true)][long]$CleanupReserveMilliseconds,
        [Parameter(Mandatory = $true)][long]$PersistReserveMilliseconds
    )
    if ($NowTicks -le 0 -or $StopwatchFrequency -le 0 -or $OverallDeadlineTicks -le 0 -or
        $CleanupReserveMilliseconds -lt $script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds -or
        $PersistReserveMilliseconds -lt $script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds) {
        throw 'D32_BOUNDED_DIAGNOSTIC_BUDGET_BLOCKED: stop-drain deadline inputs are invalid or below their retained reserves'
    }
    $drainTicks = $NowTicks + [Int64](30L * $StopwatchFrequency)
    $cargoStopBoundary = $OverallDeadlineTicks - [Int64]($CleanupReserveMilliseconds * $StopwatchFrequency / 1000L) -
        [Int64]($PersistReserveMilliseconds * $StopwatchFrequency / 1000L)
    return [Math]::Max($NowTicks, [Math]::Min($drainTicks, $cargoStopBoundary))
}

function Test-D32BoundedCompilerDiagnosticAuthorityShape {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$ToolchainProfileSha256,
        [Parameter(Mandatory = $true)][string]$ModuleAuthorityPath,
        [Parameter(Mandatory = $true)][string]$ModuleAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$PinnedGitPath,
        [Parameter(Mandatory = $true)][string]$PinnedGitSha256,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedEnvironment
    )
    $top = @('schema_version', 'record_type', 'gate_authority', 'candidate_sha', 'source_repo', 'repository_identity',
        'toolchain_profile', 'module_authority', 'pinned_git', 'command', 'child_environment', 'git_queries', 'cargo_home', 'dependency_origin',
        'target', 'output', 'resource_budget', 'source_pins', 'image_grants', 'issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Document -Expected $top) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [int]$Document.schema_version -ne 1 -or
        $Document.record_type -isnot [string] -or $Document.record_type -cne $script:D32BoundedCompilerDiagnosticAuthorityType -or
        $Document.gate_authority -isnot [string] -or $Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or $Document.candidate_sha -cne $ExpectedCandidateSha -or $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$Document.source_repo), [IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Document.repository_identity -Expected @('volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticGitQueryList $Document.git_queries)) { return $false }

    $profile = $Document.toolchain_profile
    $module = $Document.module_authority
    $git = $Document.pinned_git
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $profile @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $module @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $git @('path', 'sha256')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$profile.path), [IO.Path]::GetFullPath($ToolchainProfilePath)) -or
        [string]$profile.sha256 -cne $ToolchainProfileSha256 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$module.path), [IO.Path]::GetFullPath($ModuleAuthorityPath)) -or
        [string]$module.sha256 -cne $ModuleAuthoritySha256 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$git.path), [IO.Path]::GetFullPath($PinnedGitPath)) -or
        [string]$git.sha256 -cne $PinnedGitSha256 -or
        $ToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ModuleAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or $PinnedGitSha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }

    $command = $Document.command
    $targetPath = [IO.Path]::Combine([IO.Path]::GetFullPath($Repository), 'vita-agent', 'target')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $command @('argv', 'working_directory', 'manifest_path', 'target_directory')) -or
        -not (Test-D32BoundedCompilerDiagnosticFixedArgv $command.argv) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$command.working_directory), [IO.Path]::GetFullPath($Repository)) -or
        [string]$command.manifest_path -cne 'vita-agent/Cargo.toml' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$command.target_directory), $targetPath)) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactEnvironment -Environment $Document.child_environment -Expected $ExpectedEnvironment)) { return $false }

    $cargoHome = $Document.cargo_home
    $origin = $Document.dependency_origin
    $cargoFields = @('path', 'volume_serial_hex', 'file_id_hex')
    $originFields = @('path', 'volume_serial_hex', 'file_id_hex', 'owner_record', 'blocked_diagnostic', 'protoc_run_grant', 'fetch_records', 'manifest_refs', 'registry_archive_root', 'registry_source_root', 'git_database_root', 'git_checkout_root', 'registry_archives', 'git_source_authority')
    $requiredOrigin = 'E:\d32\inv7\r\c'
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $cargoHome $cargoFields) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin $originFields) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$cargoHome.path, $requiredOrigin) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.path, $requiredOrigin) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $cargoHome) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin) -or
        [string]$cargoHome.volume_serial_hex -cne [string]$origin.volume_serial_hex -or [string]$cargoHome.file_id_hex -cne [string]$origin.file_id_hex -or
        $origin.fetch_records -isnot [Array] -or $origin.fetch_records.Count -gt 3 -or
        $origin.manifest_refs -isnot [Array] -or $origin.manifest_refs.Count -ne 6 -or
        $origin.registry_archives -isnot [Array] -or $origin.registry_archives.Count -eq 0 -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.owner_record) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.blocked_diagnostic) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.protoc_run_grant) -or
        ($null -ne $origin.git_source_authority -and -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.git_source_authority)) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.registry_archive_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.registry_archive_root) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.registry_source_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.registry_source_root) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.git_database_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.git_database_root) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.git_checkout_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.git_checkout_root)) { return $false }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.registry_archive_root.path, (Join-Path $requiredOrigin 'registry/cache/index.crates.io-1949cf8c6b5b557f')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.registry_source_root.path, (Join-Path $requiredOrigin 'registry/src/index.crates.io-1949cf8c6b5b557f')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.git_database_root.path, (Join-Path $requiredOrigin 'git/db')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.git_checkout_root.path, (Join-Path $requiredOrigin 'git/checkouts'))) { return $false }
    foreach ($reference in $origin.fetch_records) { if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false } }
    foreach ($reference in $origin.manifest_refs) { if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false } }

    $target = $Document.target
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $target @('path', 'volume_serial_hex', 'file_id_hex', 'source_sha256', 'build_owner_mode')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$target.path), $targetPath) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $target) -or
        [string]$target.source_sha256 -cne $ExpectedCandidateSha -or
        [string]$target.build_owner_mode -cne 'EXCLUSIVE_INTEGRATION_BUILD_OWNER') { return $false }

    $output = $Document.output
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $output @('root_path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex', 'temp_path', 'run_id')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.root_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.temp_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.root_path), [string]$output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$output.temp_path, [IO.Path]::Combine([string]$output.root_path, 'temp')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $output 'parent_volume_serial_hex' 'parent_file_id_hex') -or
        [string]$output.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.root_path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.root_path $requiredOrigin) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.root_path $cargoHome.path)) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.image_grants @('vctip', 'protoc'))) { return $false }
    foreach ($image in @($Document.image_grants.vctip, $Document.image_grants.protoc)) {
        if ($null -ne $image -and (-not (Test-D32BoundedCompilerDiagnosticExactProperties $image @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $image.path) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $image.bytes -Positive) -or
            [string]$image.sha256 -cnotmatch '^[0-9a-f]{64}$' -or -not (Test-D32BoundedCompilerDiagnosticIdentityPair $image))) { return $false }
    }
    if ($Document.source_pins -isnot [Array] -or $Document.source_pins.Count -ne 6) { return $false }
    $seenPins = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pin in $Document.source_pins) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin $pin.path $Repository) -or -not $seenPins.Add([string]$pin.path)) { return $false }
    }
    try { $null = [DateTimeOffset]::Parse([string]$Document.issued_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $false }
    try { Assert-D32BoundedCompilerDiagnosticBudget -Budget $Document.resource_budget | Out-Null }
    catch { return $false }
    return $true
}

function Test-D32BoundedCompilerDiagnosticFetchEvidenceComplete {
    param([AllowNull()][object]$FetchRecords)
    if ($FetchRecords -isnot [Array] -or $FetchRecords.Count -ne 3) { return $false }
    foreach ($reference in $FetchRecords) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false }
    }
    return $true
}

function Test-D32BoundedCompilerDiagnosticExactEnvironment {
    param(
        [AllowNull()][object]$Environment,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Expected
    )
    if ($null -eq $Environment -or $Environment -is [string] -or $Environment -is [Array]) { return $false }
    $actual = [System.Collections.Generic.List[object]]::new()
    if ($Environment -is [System.Collections.IDictionary]) {
        foreach ($key in $Environment.Keys) { $actual.Add([PSCustomObject]@{ Name = [string]$key; Value = $Environment[$key] }) }
    }
    else { foreach ($property in $Environment.PSObject.Properties) { $actual.Add($property) } }
    if ($actual.Count -ne $Expected.Count) { return $false }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($property in $actual) {
        $name = [string]$property.Name
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or -not $seen.Add($name) -or -not $Expected.Contains($name)) { return $false }
        if ($property.Value -isnot [string] -or [string]$property.Value -cne [string]$Expected[$name] -or
            [string]$property.Value -match '[\r\n\x00]' -or [string]$property.Value -match '(?i)https?://[^/@\s]+:[^/@\s]+@' -or
            $name -match '(?i)(token|password|secret|credential|authorization|api.?key)') { return $false }
    }
    foreach ($forbidden in @('HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_TARGET_DIR', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
        if ($seen.Contains($forbidden)) { return $false }
    }
    return $true
}

function Test-D32BoundedCompilerDiagnosticCanStart {
    param([AllowNull()][object]$RemainingMilliseconds, [AllowNull()][object]$Budget)
    $cleanupReserve = $script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds
    $persistReserve = $script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds
    if ($null -ne $Budget) {
        try {
            Assert-D32BoundedCompilerDiagnosticBudget -Budget $Budget | Out-Null
            $cleanupReserve = [Int64]$Budget.cleanup_reserve_ms
            $persistReserve = [Int64]$Budget.persist_reserve_ms
        }
        catch { return $false }
    }
    return (Test-D32BoundedCompilerDiagnosticInteger $RemainingMilliseconds) -and
        [Int64]$RemainingMilliseconds -ge ($script:D32BoundedCompilerDiagnosticMaxCargoMilliseconds + $cleanupReserve + $persistReserve)
}

function Test-D32BoundedCompilerDiagnosticResourceStop {
    param(
        [AllowNull()][object]$Sample,
        [Parameter(Mandatory = $true)][bool]$MetricsReliable,
        [Parameter(Mandatory = $true)][bool]$AdmissionSucceeded,
        [Parameter(Mandatory = $true)][bool]$CaptureLimitReached,
        [Parameter(Mandatory = $true)][bool]$DeadlineReached
    )
    if (-not $AdmissionSucceeded -or -not $MetricsReliable -or $CaptureLimitReached -or $DeadlineReached) { return $true }
    if ($null -eq $Sample -or $Sample.Reliable -isnot [bool] -or -not [bool]$Sample.Reliable) { return $true }
    return ([Int64]$Sample.AvailablePhysicalBytes -lt (4L * 1024L * 1024L * 1024L) -or
        [Int64]$Sample.CommitHeadroomBytes -lt (2L * 1024L * 1024L * 1024L))
}

function Test-D32BoundedCompilerDiagnosticCleanupVerified {
    param([AllowNull()][object]$Cleanup)
    if ($null -eq $Cleanup) { return $false }
    return ([bool]$Cleanup.DebuggerThreadExited -and [bool]$Cleanup.DebuggerThreadJoined -and
        [bool]$Cleanup.RetainedProcessHandlesSignaled -and [bool]$Cleanup.DebuggerAssociationQueryVerified -and
        [bool]$Cleanup.DebuggerAssociationAbsent -and [bool]$Cleanup.JobActiveProcessCountVerified -and
        [uint32]$Cleanup.JobActiveProcessCount -eq 0 -and [bool]$Cleanup.JobCloseSucceeded -and [bool]$Cleanup.CleanupSucceeded)
}

function Get-D32BoundedCompilerDiagnosticSamplingSummary {
    param([Parameter(Mandatory = $true)][object[]]$Samples, [Parameter(Mandatory = $true)][object[]]$RustcRecords,
        [Parameter(Mandatory = $true)][long]$StopwatchFrequency, [Parameter(Mandatory = $true)][bool]$Complete,
        [Parameter(Mandatory = $true)][string]$StopReason)
    $processes = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $minimumAvailable = [Int64]::MaxValue
    $minimumCommit = [Int64]::MaxValue
    $maximumCommitUsed = [Int64]0
    $maximumSystemCommitPeak = [Int64]0
    $maximumSystemCommitLimit = [Int64]0
    $totalPhysical = [Int64]0
    $maximumGapTicks = [Int64]0
    for ($i = 0; $i -lt $Samples.Count; $i++) {
        $sample = $Samples[$i]
        $minimumAvailable = [Math]::Min($minimumAvailable, [Int64]$sample.available_physical_bytes)
        $minimumCommit = [Math]::Min($minimumCommit, [Int64]$sample.commit_headroom_bytes)
        $maximumCommitUsed = [Math]::Max($maximumCommitUsed, [Int64]$sample.commit_used_bytes)
        $maximumSystemCommitPeak = [Math]::Max($maximumSystemCommitPeak, [Int64]$sample.system_commit_peak_bytes)
        $maximumSystemCommitLimit = [Math]::Max($maximumSystemCommitLimit, [Int64]$sample.commit_limit_bytes)
        $totalPhysical = [Math]::Max($totalPhysical, [Int64]$sample.total_physical_bytes)
        if ($i -gt 0) { $maximumGapTicks = [Math]::Max($maximumGapTicks, [Int64]$sample.stopwatch_ticks - [Int64]$Samples[$i - 1].stopwatch_ticks) }
        foreach ($process in $sample.processes) {
            $key = ([uint32]$process.process_id).ToString([Globalization.CultureInfo]::InvariantCulture) + '|' + [Int64]$process.creation_filetime
            if (-not $processes.ContainsKey($key)) {
                $processes.Add($key, [ordered]@{
                    process_id = [uint32]$process.process_id; creation_filetime = [Int64]$process.creation_filetime
                    image_path = [string]$process.image_path; observed_sample_count = [Int64]0
                    first_user_time_100ns = $null; last_user_time_100ns = $null; first_kernel_time_100ns = $null; last_kernel_time_100ns = $null
                    observed_private_peak_bytes = [Int64]0; observed_working_set_peak_bytes = [Int64]0; memory_sample_count = [Int64]0
                })
            }
            $row = $processes[$key]
            $row.observed_sample_count++
            if ($null -eq $row.first_user_time_100ns) { $row.first_user_time_100ns = [Int64]$process.user_time_100ns; $row.first_kernel_time_100ns = [Int64]$process.kernel_time_100ns }
            $row.last_user_time_100ns = [Int64]$process.user_time_100ns
            $row.last_kernel_time_100ns = [Int64]$process.kernel_time_100ns
            if ([bool]$process.memory_verified) {
                $row.memory_sample_count++
                $row.observed_private_peak_bytes = [Math]::Max([Int64]$row.observed_private_peak_bytes, [Int64]$process.private_bytes)
                $row.observed_working_set_peak_bytes = [Math]::Max([Int64]$row.observed_working_set_peak_bytes, [Int64]$process.working_set_bytes)
            }
        }
    }
    $rustcRows = [System.Collections.Generic.List[object]]::new()
    foreach ($rustc in $RustcRecords) {
        $key = ([uint32]$rustc.ProcessId).ToString([Globalization.CultureInfo]::InvariantCulture) + '|' + [Int64]$rustc.CreationFileTime
        $matched = $null
        [void]$processes.TryGetValue($key, [ref]$matched)
        $rustcRows.Add([ordered]@{
            process_id = [uint32]$rustc.ProcessId
            creation_filetime = [Int64]$rustc.CreationFileTime
            parent_process_id = [uint32]$rustc.ParentProcessId
            parent_creation_filetime = [Int64]$rustc.ParentCreationFileTime
            image_path = [string]$rustc.ImagePath
            sampled = ($null -ne $matched)
            sampled_count = if ($null -ne $matched) { [Int64]$matched.observed_sample_count } else { 0L }
            observed_private_peak_bytes = if ($null -ne $matched) { [Int64]$matched.observed_private_peak_bytes } else { $null }
            observed_working_set_peak_bytes = if ($null -ne $matched) { [Int64]$matched.observed_working_set_peak_bytes } else { $null }
            memory_sample_count = if ($null -ne $matched) { [Int64]$matched.memory_sample_count } else { 0L }
            sampled_user_cpu_delta_100ns = if ($null -ne $matched -and $null -ne $matched.first_user_time_100ns) { [Math]::Max(0L, [Int64]$matched.last_user_time_100ns - [Int64]$matched.first_user_time_100ns) } else { $null }
            sampled_kernel_cpu_delta_100ns = if ($null -ne $matched -and $null -ne $matched.first_kernel_time_100ns) { [Math]::Max(0L, [Int64]$matched.last_kernel_time_100ns - [Int64]$matched.first_kernel_time_100ns) } else { $null }
        })
    }
    return [ordered]@{
        sample_count = [Int64]$Samples.Count
        sampling_complete = $Complete
        sampling_stop_reason = $StopReason
        maximum_sample_gap_ticks = $maximumGapTicks
        maximum_sample_gap_milliseconds = if ($StopwatchFrequency -gt 0) { [Int64][Math]::Ceiling($maximumGapTicks * 1000.0 / $StopwatchFrequency) } else { $null }
        maximum_sample_gap_at_or_below_10000ms = ($StopwatchFrequency -gt 0 -and $maximumGapTicks -le ([Int64]$StopwatchFrequency * 10))
        minimum_available_physical_bytes = if ($Samples.Count -gt 0) { $minimumAvailable } else { $null }
        minimum_commit_headroom_bytes = if ($Samples.Count -gt 0) { $minimumCommit } else { $null }
        maximum_observed_commit_used_bytes = if ($Samples.Count -gt 0) { $maximumCommitUsed } else { $null }
        maximum_observed_system_commit_peak_bytes = if ($Samples.Count -gt 0) { $maximumSystemCommitPeak } else { $null }
        maximum_observed_system_commit_limit_bytes = if ($Samples.Count -gt 0) { $maximumSystemCommitLimit } else { $null }
        maximum_observed_total_physical_bytes = if ($Samples.Count -gt 0) { $totalPhysical } else { $null }
        retained_process_identities = @($processes.Values)
        rustc_process_count = [Int64]$RustcRecords.Count
        rustc_processes = @($rustcRows.ToArray())
        rustc_processes_all_sampled = ($RustcRecords.Count -eq 0 -or @($rustcRows | Where-Object { -not $_.sampled }).Count -eq 0)
        private_peak_label = 'maximum observed 10-second sampled PrivateUsage; not a lifetime peak'
    }
}

function Test-D32BoundedCompilerDiagnosticTestBinaryNotStarted {
    param([AllowNull()][object[]]$CreatedProcessPaths, [AllowNull()][object[]]$ExecutableArtifactPaths, [Parameter(Mandatory = $true)][string]$TargetRoot)
    $dependencyExecutableRoot = Join-Path (Join-Path $TargetRoot 'debug') 'deps'
    foreach ($artifact in $ExecutableArtifactPaths) {
        if ($artifact -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$artifact)) { return $false }
        try { if (-not (Test-D32BoundedCompilerDiagnosticWithin -Child ([IO.Path]::GetFullPath([string]$artifact)) -Parent $TargetRoot)) { return $false } }
        catch { return $false }
        foreach ($created in $CreatedProcessPaths) {
            if ($created -isnot [string]) { return $false }
            try {
                $createdFull = [IO.Path]::GetFullPath([string]$created)
                $artifactFull = [IO.Path]::GetFullPath([string]$artifact)
                if ($createdFull.Equals($artifactFull, [StringComparison]::OrdinalIgnoreCase) -or
                    (Test-D32BoundedCompilerDiagnosticWithin -Child $createdFull -Parent $dependencyExecutableRoot)) { return $false }
            }
            catch { return $false }
        }
    }
    return $true
}

function Get-D32BoundedCompilerDiagnosticLockSources {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$LockText)
    $packages = [System.Collections.Generic.List[object]]::new()
    $current = $null
    foreach ($line in ($LockText -split '\r?\n')) {
        if ($line -cmatch '^\[\[package\]\]$') {
            if ($null -ne $current) { $packages.Add([PSCustomObject]$current) }
            $current = [ordered]@{ name = $null; version = $null; source = $null; checksum = $null }
            continue
        }
        if ($null -eq $current) { continue }
        if ($line -cmatch '^name\s*=\s*"([^"]+)"\s*$') { if ($null -ne $current.name) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: duplicate Cargo.lock package name field' }; $current.name = [string]$Matches[1]; continue }
        if ($line -cmatch '^version\s*=\s*"([^"]+)"\s*$') { if ($null -ne $current.version) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: duplicate Cargo.lock package version field' }; $current.version = [string]$Matches[1]; continue }
        if ($line -cmatch '^source\s*=\s*"([^"]+)"\s*$') { if ($null -ne $current.source) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: duplicate Cargo.lock package source field' }; $current.source = [string]$Matches[1]; continue }
        if ($line -cmatch '^checksum\s*=\s*"([^"]+)"\s*$') { if ($null -ne $current.checksum) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: duplicate Cargo.lock package checksum field' }; $current.checksum = [string]$Matches[1]; continue }
    }
    if ($null -ne $current) { $packages.Add([PSCustomObject]$current) }
    foreach ($package in $packages) {
        if ([String]::IsNullOrWhiteSpace([string]$package.name) -or [string]$package.name -notmatch '^[A-Za-z0-9_-]+$' -or
            [String]::IsNullOrWhiteSpace([string]$package.version) -or [string]$package.version -notmatch '^[0-9A-Za-z.+_-]+$') {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: Cargo.lock package identity is malformed'
        }
        if ($null -ne $package.source -and [string]$package.source -like 'registry+*') {
            if ([string]$package.checksum -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: locked registry package lacks its exact SHA-256 checksum' }
            $package | Add-Member -NotePropertyName source_kind -NotePropertyValue 'registry'
        }
        elseif ($null -ne $package.source -and [string]$package.source -like 'git+*') {
            if ([string]$package.source -notmatch '#([0-9a-f]{40})$') { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: locked Git package does not end in an immutable full commit' }
            if ([string]$package.checksum -ne '') { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: locked Git package must not carry a registry checksum' }
            $package | Add-Member -NotePropertyName source_kind -NotePropertyValue 'git'
            $package | Add-Member -NotePropertyName commit -NotePropertyValue ([string]$Matches[1])
        }
        elseif ($null -eq $package.source -and $null -eq $package.checksum) {
            $package | Add-Member -NotePropertyName source_kind -NotePropertyValue 'workspace'
        }
        else { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: Cargo.lock source kind is unsupported or incomplete' }
    }
    return @($packages.ToArray())
}

function Get-D32BoundedCompilerDiagnosticSourcePlan {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$LockText)
    $maxLockCharacters = 8388608
    $maxLockedPackages = 2048
    $maxRegistryPackages = 1536
    $maxGitSources = 16
    if ($LockText.Length -le 0 -or $LockText.Length -gt $maxLockCharacters) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: lock input is empty or exceeds its fixed 8 MiB text bound'
    }
    $packages = @(Get-D32BoundedCompilerDiagnosticLockSources -LockText $LockText)
    if ($packages.Count -eq 0 -or $packages.Count -gt $maxLockedPackages) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: locked package inventory is empty or exceeds its fixed 2048-entry bound'
    }
    $cargoHome = 'E:\d32\inv7\r\c'
    $registryIndex = 'index.crates.io-1949cf8c6b5b557f'
    $registryCache = Join-Path $cargoHome ('registry/cache/' + $registryIndex)
    $registrySource = Join-Path $cargoHome ('registry/src/' + $registryIndex)
    $registryRows = [System.Collections.Generic.List[object]]::new()
    $gitBySource = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $packageKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pathKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($package in $packages) {
        if ($package.source_kind -ceq 'registry') {
            if ([string]$package.source -cne 'registry+https://github.com/rust-lang/crates.io-index') {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: non-crates.io registry source is outside the approved finite origin'
            }
            $key = [string]$package.name + "`0" + [string]$package.version
            if (-not $packageKeys.Add($key)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate locked registry name/version tuple'
            }
            $archiveName = [string]$package.name + '-' + [string]$package.version + '.crate'
            $sourceName = [string]$package.name + '-' + [string]$package.version
            $archivePath = [IO.Path]::GetFullPath((Join-Path $registryCache $archiveName))
            $sourcePath = [IO.Path]::GetFullPath((Join-Path $registrySource $sourceName))
            if (-not $pathKeys.Add($archivePath) -or -not $pathKeys.Add($sourcePath)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: case-insensitive registry path collision'
            }
            $registryRows.Add([PSCustomObject][ordered]@{
                name = [string]$package.name
                version = [string]$package.version
                checksum = [string]$package.checksum
                source = [string]$package.source
                archive_path = $archivePath
                extracted_source_path = $sourcePath
            })
            continue
        }
        if ($package.source_kind -ceq 'git') {
            $source = [string]$package.source
            $match = [regex]::Match($source, '^git\+(https://[^?#@\s]+(?:\?[^#\r\n]+)?)#([0-9a-f]{40})$')
            if (-not $match.Success -or [string]$match.Groups[2].Value -cne [string]$package.commit) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source must be an immutable HTTPS URL plus the same full lowercase 40-hex lock commit'
            }
            $url = [string]$match.Groups[1].Value
            $parsedUrl = $null
            if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$parsedUrl) -or
                $parsedUrl.Scheme -cne 'https' -or [String]::IsNullOrEmpty($parsedUrl.Host) -or -not [String]::IsNullOrEmpty($parsedUrl.UserInfo)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source URL is not an absolute credential-free HTTPS URL'
            }
            $query = if ($url.Contains('?')) { $url.Substring($url.IndexOf('?') + 1) } else { '' }
            if ($query -notmatch '(?:^|&)rev=' + [regex]::Escape([string]$package.commit) + '(?:&|$)') {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source query does not pin the exact lock commit with rev='
            }
            if (-not $gitBySource.ContainsKey($source)) {
                $gitBySource.Add($source, [PSCustomObject][ordered]@{
                    source = $source
                    url = $url
                    commit = [string]$package.commit
                    database_root = [IO.Path]::GetFullPath((Join-Path $cargoHome 'git/db'))
                    checkout_root = [IO.Path]::GetFullPath((Join-Path $cargoHome 'git/checkouts'))
                })
            }
            continue
        }
        if ($package.source_kind -cne 'workspace') {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: lock contains an unapproved source kind'
        }
    }
    if ($registryRows.Count -gt $maxRegistryPackages -or $gitBySource.Count -gt $maxGitSources) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: registry or Git source tuple count exceeds its fixed finite bound'
    }
    $registryRows.Sort([System.Comparison[object]]{ param($left, $right) [StringComparer]::Ordinal.Compare(([string]$left.name + "`0" + [string]$left.version), ([string]$right.name + "`0" + [string]$right.version)) })
    $gitRows = [System.Collections.Generic.List[object]]::new()
    foreach ($source in @($gitBySource.Keys | Sort-Object -CaseSensitive)) { $gitRows.Add($gitBySource[$source]) }
    $registryCanonical = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $registryRows) { $registryCanonical.Add(('registry' + "`t" + $row.name + "`t" + $row.version + "`t" + $row.checksum)) }
    $gitCanonical = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $gitRows) { $gitCanonical.Add(('git' + "`t" + $row.url + "`t" + $row.commit)) }
    $utf8 = [Text.UTF8Encoding]::new($false)
    $registryDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(($registryCanonical -join "`n") + "`n"))).ToLowerInvariant()
    $gitDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(($gitCanonical -join "`n") + "`n"))).ToLowerInvariant()
    $lockDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($LockText))).ToLowerInvariant()
    return [PSCustomObject][ordered]@{
        schema_version = 1
        record_type = 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V1'
        gate_authority = 'NONE'
        verification_status = 'NOT_RUN'
        cargo_home = $cargoHome
        lock_bytes = [Int64]$utf8.GetByteCount($LockText)
        lock_sha256 = $lockDigest
        locked_package_count = [Int64]$packages.Count
        registry_package_count = [Int64]$registryRows.Count
        registry_tuple_sha256 = $registryDigest
        registry_archive_root = [IO.Path]::GetFullPath($registryCache)
        registry_source_root = [IO.Path]::GetFullPath($registrySource)
        registry_packages = @($registryRows.ToArray())
        git_source_count = [Int64]$gitRows.Count
        git_tuple_sha256 = $gitDigest
        git_sources = @($gitRows.ToArray())
        verifier_managed_buffer_cap_bytes = [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes
        source_proof_status = 'NOT_VERIFIED'
    }
}

function Read-D32BoundedCompilerDiagnosticStreamExact {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream, [Parameter(Mandatory = $true)][int]$Count)
    if ($Count -lt 0 -or $Count -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: invalid bounded read length' }
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: truncated tar stream' }
        $offset += $read
    }
    return ,$buffer
}

function Get-D32BoundedCompilerDiagnosticTarText {
    param([Parameter(Mandatory = $true)][byte[]]$Header, [Parameter(Mandatory = $true)][int]$Offset, [Parameter(Mandatory = $true)][int]$Length)
    $end = $Offset + $Length
    $zero = $end
    for ($index = $Offset; $index -lt $end; $index++) { if ($Header[$index] -eq 0) { $zero = $index; break } }
    for ($index = $zero; $index -lt $end; $index++) {
        if ($Header[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar text field has nonzero bytes after terminator' }
    }
    try { return [Text.UTF8Encoding]::new($false, $true).GetString($Header, $Offset, $zero - $Offset) }
    catch { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar path is not strict UTF-8' }
}

function Get-D32BoundedCompilerDiagnosticTarOctal {
    param([Parameter(Mandatory = $true)][byte[]]$Header, [Parameter(Mandatory = $true)][int]$Offset, [Parameter(Mandatory = $true)][int]$Length)
    if ($Length -lt 1 -or $Length -gt 16 -or ($Header[$Offset] -band 0x80) -ne 0) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field is unsupported or out of bounds'
    }
    $end = $Offset + $Length
    $text = [Text.Encoding]::ASCII.GetString($Header, $Offset, $Length).Trim([char[]]@([char]0, [char]32))
    if ($text.Length -eq 0) { return 0L }
    if ($text -cnotmatch '^[0-7]+$') { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field is not strict octal' }
    try { return [Convert]::ToInt64($text, 8) }
    catch { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field overflows its bound' }
}

function Test-D32BoundedCompilerDiagnosticTarPath {
    param([AllowNull()][string]$Path)
    if ($null -eq $Path -or [String]::IsNullOrEmpty($Path) -or $Path.Length -gt 4096 -or
        $Path -match '[\\:\x00-\x1f\x7f<>"|?*]' -or $Path.StartsWith('/') -or $Path.StartsWith('\') -or
        $Path.Normalize([Text.NormalizationForm]::FormC) -cne $Path) { return $false }
    foreach ($segment in $Path.Split('/')) {
        if ([String]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..' -or
            $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
            $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') { return $false }
    }
    return $true
}

function Get-D32BoundedCompilerDiagnosticCrateArchiveInventory {
    param(
        [Parameter(Mandatory = $true)][byte[]]$CompressedBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedArchiveSha256,
        [long]$MaximumCompressedBytes = 268435456L,
        [long]$MaximumExpandedBytes = 1073741824L,
        [long]$MaximumMemberBytes = 134217728L,
        [int]$MaximumMembers = 10000
    )
    if ($CompressedBytes.Length -le 0 -or [Int64]$CompressedBytes.Length -gt $MaximumCompressedBytes -or
        $ExpectedArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedPackageRoot -cnotmatch '^[A-Za-z0-9_-]+-[0-9A-Za-z.+_-]+$' -or
        $MaximumExpandedBytes -le 0 -or $MaximumMemberBytes -le 0 -or $MaximumMembers -le 0 -or $MaximumMembers -gt 10000) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive bytes, expected package identity, or finite parser bound is invalid'
    }
    $archiveSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($CompressedBytes)).ToLowerInvariant()
    if ($archiveSha -cne $ExpectedArchiveSha256) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: compressed registry archive SHA-256 differs from Cargo.lock checksum' }
    $compressed = [IO.MemoryStream]::new($CompressedBytes, $false)
    $gzip = $null
    try {
        $gzip = [IO.Compression.GZipStream]::new($compressed, [IO.Compression.CompressionMode]::Decompress, $true)
        $expected = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        $rawNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $rawMemberCount = 0
        $expandedBytes = [Int64]0
        $rootPrefix = $ExpectedPackageRoot + '/'
        $rootSeen = $false
        $ended = $false
        while (-not $ended) {
            $header = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count 512
            $expandedBytes += 512
            if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling' }
            $allZero = $true
            for ($index = 0; $index -lt 512; $index++) { if ($header[$index] -ne 0) { $allZero = $false; break } }
            if ($allZero) {
                $second = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count 512
                $expandedBytes += 512
                for ($index = 0; $index -lt 512; $index++) { if ($second[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar terminator is not two complete zero blocks' } }
                while (($read = $gzip.Read($header, 0, 512)) -gt 0) {
                    $expandedBytes += $read
                    if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: trailing archive data exceeds its fixed byte ceiling' }
                    for ($index = 0; $index -lt $read; $index++) { if ($header[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: nonzero data follows the tar terminator' } }
                }
                $ended = $true
                continue
            }
            $rawMemberCount++
            if ($rawMemberCount -gt $MaximumMembers) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member count exceeds its fixed ceiling' }
            $checksum = Get-D32BoundedCompilerDiagnosticTarOctal -Header $header -Offset 148 -Length 8
            $actualChecksum = [Int64]0
            for ($index = 0; $index -lt 512; $index++) {
                $actualChecksum += if ($index -ge 148 -and $index -lt 156) { 32 } else { [Int64]$header[$index] }
            }
            if ($actualChecksum -ne $checksum -or
                [Text.Encoding]::ASCII.GetString($header, 257, 6) -cne "ustar`0" -or
                [Text.Encoding]::ASCII.GetString($header, 263, 2) -cne '00') {
                throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: header checksum or strict USTAR format validation failed'
            }
            $name = Get-D32BoundedCompilerDiagnosticTarText -Header $header -Offset 0 -Length 100
            $prefix = Get-D32BoundedCompilerDiagnosticTarText -Header $header -Offset 345 -Length 155
            $fullName = if ([String]::IsNullOrEmpty($prefix)) { $name } else { $prefix + '/' + $name }
            $typeFlag = [char]$header[156]
            $size = Get-D32BoundedCompilerDiagnosticTarOctal -Header $header -Offset 124 -Length 12
            $isDirectory = $typeFlag -ceq '5'
            $isRegular = $typeFlag -ceq '0' -or [int]$typeFlag -eq 0
            if (-not $isDirectory -and -not $isRegular) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: links, extended headers, sparse files, and special tar entries are unsupported' }
            if ($isDirectory -and $size -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar directory entry has nonzero data' }
            if ($size -lt 0 -or $size -gt $MaximumMemberBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar member exceeds its fixed byte ceiling' }
            if ($isDirectory -and $fullName.EndsWith('/')) { $fullName = $fullName.Substring(0, $fullName.Length - 1) }
            if ($fullName -ceq $ExpectedPackageRoot) {
                if (-not $isDirectory -or $rootSeen -or -not $rawNames.Add($fullName)) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: package root header is duplicated or not a directory' }
                $rootSeen = $true
            }
            else {
                if (-not $fullName.StartsWith($rootPrefix, [StringComparison]::Ordinal) -or
                    -not (Test-D32BoundedCompilerDiagnosticTarPath $fullName) -or -not $rawNames.Add($fullName)) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member path escaped, aliased, collided, or duplicated'
                }
                $relative = $fullName.Substring($rootPrefix.Length)
                if ($isDirectory) { $relative = $relative.TrimEnd('/') }
                if ([String]::IsNullOrEmpty($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: empty non-root member path is invalid' }
                $segments = $relative.Split('/')
                $parentPath = ''
                for ($segmentIndex = 0; $segmentIndex -lt ($segments.Count - 1); $segmentIndex++) {
                    $parentPath = if ([String]::IsNullOrEmpty($parentPath)) { $segments[$segmentIndex] } else { $parentPath + '/' + $segments[$segmentIndex] }
                    if ($expected.ContainsKey($parentPath)) {
                        if ([string]$expected[$parentPath].kind -cne 'directory' -or [string]$expected[$parentPath].path -cne $parentPath) {
                            throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member has a case collision or a file used as a directory'
                        }
                    }
                    else { $expected.Add($parentPath, [PSCustomObject]@{ path = $parentPath; kind = 'directory'; bytes = 0L; sha256 = $null }) }
                }
                if ($expected.ContainsKey($relative)) {
                    if (-not $isDirectory -or [string]$expected[$relative].kind -cne 'directory' -or [string]$expected[$relative].path -cne $relative) {
                        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive contains a duplicate member or case/type collision'
                    }
                    # A previously inferred parent directory may receive its one explicit USTAR directory record.
                }
                elseif ($isDirectory) { $expected.Add($relative, [PSCustomObject]@{ path = $relative; kind = 'directory'; bytes = 0L; sha256 = $null }) }
                else {
                    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
                    try {
                        $remaining = [Int64]$size
                        $buffer = [byte[]]::new(65536)
                        while ($remaining -gt 0) {
                            $take = [int][Math]::Min([Int64]$buffer.Length, $remaining)
                            $read = $gzip.Read($buffer, 0, $take)
                            if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: truncated file member data' }
                            $hash.AppendData($buffer, 0, $read)
                            $remaining -= $read
                        }
                        $fileSha = [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
                    }
                    finally { $hash.Dispose() }
                    $expandedBytes += [Int64]$size
                    if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling' }
                    $padding = [int]((512 - ($size % 512)) % 512)
                    if ($padding -gt 0) {
                        $pad = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count $padding
                        for ($index = 0; $index -lt $pad.Length; $index++) { if ($pad[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: nonzero file padding is unsupported' } }
                        $expandedBytes += $padding
                    }
                    $expected.Add($relative, [PSCustomObject]@{ path = $relative; kind = 'file'; bytes = [Int64]$size; sha256 = $fileSha })
                    continue
                }
            }
            $paddingSize = [int]((512 - ($size % 512)) % 512)
            if ($size -gt 0) {
                $discard = [byte[]]::new(65536)
                $remaining = [Int64]$size
                while ($remaining -gt 0) {
                    $read = $gzip.Read($discard, 0, [int][Math]::Min([Int64]$discard.Length, $remaining))
                    if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: truncated unsupported member data' }
                    $remaining -= $read
                }
                $expandedBytes += [Int64]$size
            }
            if ($paddingSize -gt 0) {
                $pad = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count $paddingSize
                for ($index = 0; $index -lt $pad.Length; $index++) { if ($pad[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: nonzero tar padding is unsupported' } }
                $expandedBytes += $paddingSize
            }
            if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling' }
        }
        if ($expected.Count -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member inventory is empty' }
        $paths = [string[]]@($expected.Keys)
        [Array]::Sort($paths, [StringComparer]::Ordinal)
        $rows = [System.Collections.Generic.List[object]]::new()
        $canonical = [System.Collections.Generic.List[string]]::new()
        foreach ($path in $paths) {
            $entry = $expected[$path]
            $rows.Add($entry)
            $canonical.Add(([string]$entry.kind + "`t" + [string]$entry.path + "`t" + [Int64]$entry.bytes + "`t" + [string]$entry.sha256))
        }
        $inventorySha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($canonical -join "`n") + "`n"))).ToLowerInvariant()
        return [PSCustomObject][ordered]@{ archive_sha256 = $archiveSha; expanded_bytes = $expandedBytes; member_count = [Int64]$rawMemberCount; entries = @($rows.ToArray()); inventory_sha256 = $inventorySha }
    }
    finally {
        if ($null -ne $gzip) { $gzip.Dispose() }
        $compressed.Dispose()
    }
}
