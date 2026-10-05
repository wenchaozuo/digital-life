# Pure policy helpers for the D32 bounded compiler diagnostic.
# This file defines functions only; it never imports modules or launches processes.

$script:D32BoundedCompilerDiagnosticAuthorityType = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_AUTHORITY_V1'
$script:D32BoundedCompilerDiagnosticResultType = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_V1'
$script:D32BoundedDiagnosticSourceProofAuthorityType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_AUTHORITY_V1'
$script:D32BoundedDiagnosticSourceProofCandidateType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_CANDIDATE_V2'
$script:D32BoundedDiagnosticHistoricalInv7CandidateSha = '2de30edf5de48aa4ed3216c3d3df13c3e2f0ac51'
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

function Test-D32BoundedDiagnosticSourceGraphProof {
    param([AllowNull()][object]$Graph)
    $fields = @('schema_version', 'record_type', 'gate_authority', 'formal_gate_usable', 'status', 'semantic_scope', 'lock_sha256',
        'lock_dependency_edges_sha256', 'graph_sha256', 'root_manifest_path', 'selected_root_ids', 'root_selection_rule', 'host_triple',
        'target_triple', 'target_resolution_scope', 'locked_package_count', 'included_package_ids', 'included_package_count',
        'excluded_package_count', 'classification_count', 'classifications', 'included_edges', 'dependency_decisions',
        'inactive_target_edge_count', 'unknown_cfg_conservative_include_count', 'included_manifest_set_sha256', 'feature_rule',
        'root_dev_dependency_rule', 'nonroot_dev_dependency_rule', 'build_proc_macro_rule', 'closed_reachability_set_sha256',
        'source_plan_version', 'selected_target_mode', 'selected_crate_kinds')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Graph $fields) -or
        [int64]$Graph.schema_version -ne 2 -or [string]$Graph.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_SOURCE_GRAPH_PROOF_V2' -or
        [string]$Graph.gate_authority -cne 'NONE' -or $Graph.formal_gate_usable -isnot [bool] -or [bool]$Graph.formal_gate_usable -or
        [string]$Graph.status -cne 'CURRENT_LOCKED_SOURCE_GRAPH_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
        [string]$Graph.semantic_scope -cne 'FULL_LOCK_AUDIT_CATALOG_PLUS_SELECTED_REACHABLE_CONSERVATIVE_SUPERSET' -or
        [string]$Graph.lock_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Graph.lock_dependency_edges_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Graph.graph_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Graph.included_manifest_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Graph.closed_reachability_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Graph.root_manifest_path -cne 'vita-agent/Cargo.toml' -or
        [string]$Graph.root_selection_rule -cne 'EXACT_PACKAGE_NAMED_BY_MANIFEST_PATH_DEFAULT_FEATURES_PLUS_D32_A_TEST_HELPER_NO_WORKSPACE_EXPANSION' -or
        [string]$Graph.host_triple -cne 'x86_64-pc-windows-msvc' -or [string]$Graph.target_triple -cne 'x86_64-pc-windows-msvc' -or
        [string]$Graph.target_resolution_scope -cne 'ONE_FIXED_X86_64_PC_WINDOWS_MSVC_HOST_AND_TARGET' -or [int]$Graph.source_plan_version -ne 2 -or
        [string]$Graph.selected_target_mode -cne 'ALL_TARGETS_FOR_SELECTED_PACKAGE_ONLY' -or
        $Graph.selected_crate_kinds -isnot [Array] -or
        [string]::Join(',', [string[]]$Graph.selected_crate_kinds) -cne 'lib,bin,example,test,bench,custom-build,proc-macro' -or
        [string]$Graph.feature_rule -cne 'ALL_OPTIONAL_AND_FEATURE_ACTIVATION_EDGES_INCLUDED_UNLESS_TARGET_PREDICATE_PROVEN_FALSE' -or
        [string]$Graph.root_dev_dependency_rule -cne 'INCLUDED_FOR_SELECTED_PACKAGE_ALL_TARGETS' -or
        [string]$Graph.nonroot_dev_dependency_rule -cne 'EXCLUDED_NOT_BUILT_FOR_DEPENDENCY_PACKAGE' -or
        [string]$Graph.build_proc_macro_rule -cne 'INCLUDED_HOST_EQUALS_TARGET' -or
        $Graph.selected_root_ids -isnot [Array] -or $Graph.selected_root_ids.Count -ne 1 -or
        $Graph.included_package_ids -isnot [Array] -or $Graph.classifications -isnot [Array] -or
        $Graph.included_edges -isnot [Array] -or $Graph.dependency_decisions -isnot [Array] -or
        [Int64]$Graph.locked_package_count -le 0 -or [Int64]$Graph.locked_package_count -gt 2048 -or
        [Int64]$Graph.included_package_count -lt 1 -or [Int64]$Graph.excluded_package_count -lt 0 -or
        [Int64]$Graph.classification_count -ne [Int64]$Graph.locked_package_count -or
        [Int64]$Graph.included_package_count + [Int64]$Graph.excluded_package_count -ne [Int64]$Graph.locked_package_count -or
        $Graph.classifications.Count -ne [Int64]$Graph.locked_package_count -or
        $Graph.included_package_ids.Count -ne [Int64]$Graph.included_package_count -or
        $Graph.dependency_decisions.Count -gt 65536 -or $Graph.included_edges.Count -gt 65536) { return $false }
    $rootId = [string]$Graph.selected_root_ids[0]
    if ($rootId -notmatch '^digital-life-vita-agent@[^|]+\|workspace\|workspace$') { return $false }
    $included = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $Graph.included_package_ids) { if ($id -isnot [string] -or -not $included.Add([string]$id)) { return $false } }
    if (-not $included.Contains($rootId)) { return $false }
    $classified = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $includedClassifications = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $excludedClassifications = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($class in $Graph.classifications) {
        if ([string]$class.classification -ceq 'INCLUDED') {
            $classFields = @('package_id', 'classification', 'source_kind', 'source_identity', 'manifest_path', 'manifest_sha256', 'witness_kind', 'witness_root_path', 'closed_reachability_sha256')
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $class $classFields) -or
                [string]$class.source_kind -cnotin @('workspace', 'registry', 'git') -or
                [string]$class.manifest_path -notmatch '^[A-Za-z0-9_./-]+/Cargo\.toml$|^Cargo\.toml$' -or
                [string]$class.manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$class.closed_reachability_sha256 -cne [string]$Graph.closed_reachability_set_sha256 -or
                [string]$class.witness_kind -cne 'ROOT_PATH_IN_VERIFIED_DECLARATION_GRAPH' -or
                $class.witness_root_path -isnot [Array] -or $class.witness_root_path.Count -lt 1 -or
                [string]$class.witness_root_path[0] -cne $rootId -or
                [string]$class.witness_root_path[$class.witness_root_path.Count - 1] -cne [string]$class.package_id -or
                -not $classified.Add([string]$class.package_id) -or -not $included.Contains([string]$class.package_id)) { return $false }
            $identityMatch = [regex]::Match([string]$class.package_id, '^(?<name>[A-Za-z0-9_-]+)@(?<version>[0-9A-Za-z.+_-]+)\|(?<kind>workspace|registry|git)\|(?<source>.*)$')
            if (-not $identityMatch.Success -or [string]$identityMatch.Groups['kind'].Value -cne [string]$class.source_kind -or
                [string]$identityMatch.Groups['source'].Value -cne [string]$class.source_identity) { return $false }
            $includedClassifications.Add([string]$class.package_id, $class)
        }
        elseif ([string]$class.classification -ceq 'EXCLUDED_WITH_WITNESS') {
            $classFields = @('package_id', 'classification', 'source_kind', 'source_identity', 'witness_kind', 'unreachable_from_roots', 'complete_reachable_parent_count',
                'complete_reachable_dependency_decision_count', 'no_active_incoming_edge_from_included', 'closed_reachability_sha256')
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $class $classFields) -or
                [string]$class.source_kind -cnotin @('workspace', 'registry', 'git') -or
                [string]$class.witness_kind -cne 'CLOSED_REACHABILITY_CUT' -or $class.unreachable_from_roots -isnot [Array] -or
                $class.unreachable_from_roots.Count -ne 1 -or [string]$class.unreachable_from_roots[0] -cne $rootId -or
                $class.no_active_incoming_edge_from_included -isnot [bool] -or -not [bool]$class.no_active_incoming_edge_from_included -or
                [Int64]$class.complete_reachable_parent_count -ne [Int64]$Graph.included_package_count -or
                [Int64]$class.complete_reachable_dependency_decision_count -ne [Int64]$Graph.dependency_decisions.Count -or
                [string]$class.closed_reachability_sha256 -cne [string]$Graph.closed_reachability_set_sha256 -or
                -not $classified.Add([string]$class.package_id) -or $included.Contains([string]$class.package_id)) { return $false }
            $identityMatch = [regex]::Match([string]$class.package_id, '^(?<name>[A-Za-z0-9_-]+)@(?<version>[0-9A-Za-z.+_-]+)\|(?<kind>workspace|registry|git)\|(?<source>.*)$')
            if (-not $identityMatch.Success -or [string]$identityMatch.Groups['kind'].Value -cne [string]$class.source_kind -or
                [string]$identityMatch.Groups['source'].Value -cne [string]$class.source_identity) { return $false }
            $excludedClassifications.Add([string]$class.package_id, $class)
        }
        else { return $false }
    }
    if ($classified.Count -ne [Int64]$Graph.locked_package_count -or $includedClassifications.Count -ne [Int64]$Graph.included_package_count -or
        $excludedClassifications.Count -ne [Int64]$Graph.excluded_package_count) { return $false }
    foreach ($edge in $Graph.included_edges) {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $edge @('parent_package_id', 'target_package_id', 'lock_spec', 'dependency_alias', 'kind', 'target_predicate', 'predicate_proven', 'predicate_witness', 'optional_included')) -or
            -not $included.Contains([string]$edge.parent_package_id) -or -not $included.Contains([string]$edge.target_package_id)) { return $false }
        if (@($Graph.dependency_decisions | Where-Object {
            [string]$_.disposition -cin @('INCLUDED', 'INCLUDED_UNKNOWN_CFG') -and
            [string]$_.parent_package_id -ceq [string]$edge.parent_package_id -and
            [string]$_.target_package_id -ceq [string]$edge.target_package_id -and
            [string]$_.lock_specs[0] -ceq [string]$edge.lock_spec -and
            [string]$_.alias -ceq [string]$edge.dependency_alias -and
            [string]$_.kind -ceq [string]$edge.kind -and
            [string]$_.target -ceq [string]$edge.target_predicate -and
            [bool]$_.predicate_proven -eq [bool]$edge.predicate_proven -and
            [string]$_.predicate_witness -ceq [string]$edge.predicate_witness -and
            [bool]$_.optional_included -eq [bool]$edge.optional_included
        }).Count -ne 1) { return $false }
    }
    foreach ($decision in $Graph.dependency_decisions) {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $decision @('parent_package_id', 'alias', 'kind', 'target', 'disposition', 'predicate_proven', 'predicate_witness', 'target_package_id', 'lock_specs', 'optional_included')) -or
            -not $included.Contains([string]$decision.parent_package_id) -or $decision.lock_specs -isnot [Array]) { return $false }
        if ([string]$decision.disposition -cin @('INCLUDED', 'INCLUDED_UNKNOWN_CFG')) {
            if (-not $included.Contains([string]$decision.target_package_id) -or $decision.lock_specs.Count -ne 1 -or
                @($Graph.included_edges | Where-Object {
                    [string]$_.parent_package_id -ceq [string]$decision.parent_package_id -and
                    [string]$_.target_package_id -ceq [string]$decision.target_package_id -and
                    [string]$_.lock_spec -ceq [string]$decision.lock_specs[0] -and
                    [string]$_.dependency_alias -ceq [string]$decision.alias -and
                    [string]$_.kind -ceq [string]$decision.kind -and
                    [string]$_.target_predicate -ceq [string]$decision.target -and
                    [bool]$_.predicate_proven -eq [bool]$decision.predicate_proven -and
                    [string]$_.predicate_witness -ceq [string]$decision.predicate_witness -and
                    [bool]$_.optional_included -eq [bool]$decision.optional_included
                }).Count -ne 1) { return $false }
        }
    }
    foreach ($id in $Graph.included_package_ids) {
        $class = $includedClassifications[[string]$id]
        $path = [string[]]$class.witness_root_path
        for ($i = 1; $i -lt $path.Length; $i++) {
            if (-not @($Graph.included_edges | Where-Object { [string]$_.parent_package_id -ceq $path[$i - 1] -and [string]$_.target_package_id -ceq $path[$i] }).Count) { return $false }
        }
    }
    foreach ($id in $excludedClassifications.Keys) {
        if (@($Graph.included_edges | Where-Object { [string]$_.target_package_id -ceq $id }).Count -gt 0 -or
            @($Graph.dependency_decisions | Where-Object { [string]$_.disposition -cin @('INCLUDED', 'INCLUDED_UNKNOWN_CFG') -and [string]$_.target_package_id -ceq $id }).Count -gt 0) { return $false }
    }
    $includedIds = [string[]]@($Graph.included_package_ids); [Array]::Sort($includedIds, [StringComparer]::Ordinal)
    $expectedClosedSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($includedIds -join "`n") + "`n"))).ToLowerInvariant()
    if ($expectedClosedSha -cne [string]$Graph.closed_reachability_set_sha256) { return $false }
    $manifestCanon = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $includedIds) {
        $class = $includedClassifications[$id]
        $manifestCanon.Add($id + "`t" + [string]$class.source_kind + "`t" + [string]$class.source_identity + "`t" + [string]$class.manifest_path + "`t" + [string]$class.manifest_sha256)
    }
    $manifestCanon.Sort([StringComparer]::Ordinal)
    $expectedManifestSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($manifestCanon -join "`n") + "`n"))).ToLowerInvariant()
    if ($expectedManifestSha -cne [string]$Graph.included_manifest_set_sha256) { return $false }
    $edgeCanon = [System.Collections.Generic.List[string]]::new()
    foreach ($edge in $Graph.included_edges) { $edgeCanon.Add(([string]$edge.parent_package_id + "`t" + [string]$edge.target_package_id + "`t" + [string]$edge.dependency_alias + "`t" + [string]$edge.kind + "`t" + [string]$edge.target_predicate + "`t" + [string]$edge.predicate_witness + "`t" + [string]$edge.lock_spec)) }
    $edgeCanon.Sort([StringComparer]::Ordinal)
    $decisionCanon = [System.Collections.Generic.List[string]]::new()
    foreach ($decision in $Graph.dependency_decisions) { $decisionCanon.Add(([string]$decision.parent_package_id + "`t" + [string]$decision.alias + "`t" + [string]$decision.kind + "`t" + [string]$decision.target + "`t" + [string]$decision.disposition + "`t" + [string]$decision.predicate_witness + "`t" + [string]$decision.target_package_id + "`t" + [string]::Join(',', [string[]]$decision.lock_specs) + "`t" + [string]$decision.predicate_proven + "`t" + [string]$decision.optional_included)) }
    $decisionCanon.Sort([StringComparer]::Ordinal)
    $rootCanonical = [string]::Join("`n", [string[]]$Graph.selected_root_ids)
    $expectedGraphSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(([string]$Graph.lock_sha256 + "`n" + [string]$Graph.lock_dependency_edges_sha256 + "`n" + $rootCanonical + "`n" + ($edgeCanon -join "`n") + "`n" + ($decisionCanon -join "`n") + "`n" + $expectedClosedSha + "`n" + $expectedManifestSha + "`n")))).ToLowerInvariant()
    if ($expectedGraphSha -cne [string]$Graph.graph_sha256) { return $false }
    return $true
}

function Add-D32BoundedDiagnosticSourceProofCandidateFailureReason {
    param([AllowNull()][System.Collections.Generic.List[string]]$FailureReasons, [Parameter(Mandatory = $true)][string]$Reason)
    if ($null -ne $FailureReasons) { $FailureReasons.Add($Reason) }
}

function New-D32BoundedDiagnosticSourceProofCandidateDocument {
    param(
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$HistoricalOriginCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][ValidateSet('CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY', 'BLOCKED')][string]$Status,
        [Parameter(Mandatory = $true)][string]$ProofAuthorityPath,
        [Parameter(Mandatory = $true)][string]$ProofAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$ProofEntryPath,
        [Parameter(Mandatory = $true)][string]$ProofEntrySha256,
        [Parameter(Mandatory = $true)][string]$ProofStartedAtUtc,
        [Parameter(Mandatory = $true)][string]$ProofCompletedAtUtc,
        [Parameter(Mandatory = $true)][long]$ProofElapsedMilliseconds,
        [Parameter(Mandatory = $true)][object]$ProofBudget,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$SourcePins,
        [AllowNull()][object]$CurrentProfileLockBindings,
        [AllowNull()][object]$CurrentSourceClosure,
        [AllowNull()][object]$PrimaryError
    )
    return [PSCustomObject][ordered]@{
        schema_version = 2
        record_type = $script:D32BoundedDiagnosticSourceProofCandidateType
        source_plan_semantics_version = 2
        gate_authority = 'NONE'
        candidate_sha = $CandidateSha
        historical_origin_candidate_sha = $HistoricalOriginCandidateSha
        source_repo = $Repository
        status = $Status
        formal_phase1_allowed = $false
        formal_aggregate_allowed = $false
        diagnostic_invocation_authority = 'NONE_UNTRUSTED_CANDIDATE_ONLY'
        historical_origin = [PSCustomObject][ordered]@{
            fetch_completion = 'NOT_RETAINED'
            attempt_state = 'BLOCKED'
            gate_authority = 'NONE'
        }
        proof_authority = [PSCustomObject][ordered]@{ path = $ProofAuthorityPath; sha256 = $ProofAuthoritySha256 }
        proof_entry = [PSCustomObject][ordered]@{ path = $ProofEntryPath; sha256 = $ProofEntrySha256 }
        proof_started_at_utc = $ProofStartedAtUtc
        proof_completed_at_utc = $ProofCompletedAtUtc
        proof_elapsed_milliseconds = $ProofElapsedMilliseconds
        proof_budget = $ProofBudget
        source_pins = @($SourcePins)
        current_profile_lock_bindings = $CurrentProfileLockBindings
        current_source_closure = $CurrentSourceClosure
        primary_error = $PrimaryError
    }
}

function Test-D32BoundedDiagnosticSourceProofCandidate {
    param([AllowNull()][object]$Record, [AllowNull()][System.Collections.Generic.List[string]]$FailureReasons)
    $fields = @('schema_version', 'record_type', 'source_plan_semantics_version', 'gate_authority', 'candidate_sha', 'historical_origin_candidate_sha',
        'source_repo', 'status', 'formal_phase1_allowed', 'formal_aggregate_allowed', 'diagnostic_invocation_authority',
        'historical_origin', 'proof_authority', 'proof_entry', 'proof_started_at_utc', 'proof_completed_at_utc',
        'proof_elapsed_milliseconds', 'proof_budget', 'source_pins', 'current_profile_lock_bindings', 'current_source_closure', 'primary_error')
    $historicalFields = @('fetch_completion', 'attempt_state', 'gate_authority')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields) -or
        [int64]$Record.schema_version -ne 2 -or [string]$Record.record_type -cne $script:D32BoundedDiagnosticSourceProofCandidateType -or
        [int]$Record.source_plan_semantics_version -ne 2 -or
        [string]$Record.gate_authority -cne 'NONE' -or
        [string]$Record.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Record.historical_origin_candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$Record.historical_origin_candidate_sha -ceq [string]$Record.candidate_sha -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.source_repo) -or
        [string]$Record.status -cnotin @('CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY', 'BLOCKED') -or
        $Record.formal_phase1_allowed -isnot [bool] -or [bool]$Record.formal_phase1_allowed -or
        $Record.formal_aggregate_allowed -isnot [bool] -or [bool]$Record.formal_aggregate_allowed -or
        [string]$Record.diagnostic_invocation_authority -cne 'NONE_UNTRUSTED_CANDIDATE_ONLY' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.historical_origin $historicalFields) -or
        [string]$Record.historical_origin.fetch_completion -cne 'NOT_RETAINED' -or
        [string]$Record.historical_origin.attempt_state -cne 'BLOCKED' -or
        [string]$Record.historical_origin.gate_authority -cne 'NONE' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_authority @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.proof_authority.path) -or
        [string]$Record.proof_authority.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_entry @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.proof_entry.path) -or
        [string]$Record.proof_entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.proof_elapsed_milliseconds) -or
        (($Record.primary_error -isnot [string]) -and ($null -ne $Record.primary_error)) -or
        (($Record.current_profile_lock_bindings -isnot [Array]) -and ($null -ne $Record.current_profile_lock_bindings)) -or
        (($null -ne $Record.current_source_closure) -and ([string]$Record.current_source_closure.HistoricalAttemptState -cne 'BLOCKED'))) {
        $reason = if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields)) { 'candidate-exact-fields' }
            elseif (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.historical_origin $historicalFields)) { 'historical-origin-object-shape' }
            elseif (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_authority @('path', 'sha256'))) { 'proof-authority-object-shape' }
            elseif (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_entry @('path', 'sha256'))) { 'proof-entry-object-shape' }
            elseif ([string]$Record.status -ceq 'BLOCKED' -and [String]::IsNullOrWhiteSpace([string]$Record.primary_error)) { 'blocked-primary-error-missing' }
            else { 'candidate-envelope-or-common-values' }
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason $reason
        return $false
    }
    if ($null -ne $Record.current_source_closure -and
        ([string]$Record.current_source_closure.CurrentCandidateSha -cne [string]$Record.candidate_sha -or
         [string]$Record.current_source_closure.HistoricalOriginCandidateSha -cne [string]$Record.historical_origin_candidate_sha)) {
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'source-closure-current-historical-crossbind'
        return $false
    }
    if ([string]$Record.status -ceq 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -and $null -ne $Record.current_source_closure -and
        -not (Test-D32BoundedDiagnosticSourceGraphProof $Record.current_source_closure.SourceGraphProof)) {
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'source-graph-proof-shape-or-witness'
        return $false
    }
    if ([string]$Record.status -ceq 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY') {
        if ($null -eq $Record.current_source_closure -or [Int64]$Record.proof_elapsed_milliseconds -gt 300000 -or $null -ne $Record.primary_error) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'verified-result-closure-time-or-primary-error'
            return $false
        }
        if ($Record.source_pins -isnot [Array] -or $Record.source_pins.Count -ne 5) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'verified-result-source-pin-count'
            return $false
        }
        if ($Record.current_profile_lock_bindings -isnot [Array] -or $Record.current_profile_lock_bindings.Count -ne 3) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'verified-result-profile-lock-binding-count'
            return $false
        }
        if (
            [string]$Record.current_source_closure.HistoricalAttemptState -cne 'BLOCKED' -or
            [string]$Record.current_source_closure.HistoricalFetchCompletion -cne 'NOT_RETAINED' -or
            [string]$Record.current_source_closure.HistoricalGateAuthority -cne 'NONE') {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'historical-origin-status-binding'
            return $false
        }
        if (
            [string]$Record.current_source_closure.RegistryContentProof.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_REGISTRY_SOURCE_CONTENT_PROOF_V2' -or
            [string]$Record.current_source_closure.GitContentProof.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_CONTENT_PROOF_V2' -or
            [string]$Record.current_source_closure.SourceGraphProof.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_SOURCE_GRAPH_PROOF_V2' -or
            [string]$Record.current_source_closure.CurrentCandidateSha -cne [string]$Record.candidate_sha -or
            [string]$Record.current_source_closure.HistoricalOriginCandidateSha -cne [string]$Record.historical_origin_candidate_sha) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'proof-record-type-or-current-historical-binding'
            return $false
        }
        if ([Int64]$Record.current_source_closure.SourceGraphProof.included_package_count + [Int64]$Record.current_source_closure.SourceGraphProof.excluded_package_count -ne [Int64]$Record.current_source_closure.SourceGraphProof.locked_package_count) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'source-graph-package-partition-count'
            return $false
        }
        if ([string]$Record.current_source_closure.RegistryContentProof.status -cne 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
            [bool]$Record.current_source_closure.RegistryContentProof.formal_gate_usable -or
            [string]$Record.current_source_closure.RegistryContentProof.lock_sha256 -cne [string]$Record.current_source_closure.SourceGraphProof.lock_sha256 -or
            $Record.current_source_closure.RegistryContentProof.verified_package_ids -isnot [Array]) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'registry-proof-status-lock-or-package-set'
            return $false
        }
        if ([string]$Record.current_source_closure.GitContentProof.status -cne 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
            [bool]$Record.current_source_closure.GitContentProof.formal_gate_usable -or
            [string]$Record.current_source_closure.GitContentProof.lock_sha256 -cne [string]$Record.current_source_closure.SourceGraphProof.lock_sha256 -or
            $Record.current_source_closure.GitContentProof.verified_package_ids -isnot [Array] -or
            $Record.current_source_closure.CurrentManifestProof -isnot [Array]) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'git-proof-status-lock-package-or-manifest-set'
            return $false
        }
    }
    if ([string]$Record.status -ceq 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY') {
        $registryIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in $Record.current_source_closure.RegistryContentProof.verified_package_ids) {
            if ($id -isnot [string] -or -not $registryIds.Add([string]$id)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'registry-proof-package-id-set'
                return $false
            }
        }
        $gitIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in $Record.current_source_closure.GitContentProof.verified_package_ids) {
            if ($id -isnot [string] -or -not $gitIds.Add([string]$id)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'git-proof-package-id-set'
                return $false
            }
        }
        $workspaceManifests = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($manifest in $Record.current_source_closure.CurrentManifestProof) {
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $manifest @('manifest_path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
                [string]$manifest.manifest_path -notmatch '^[A-Za-z0-9_./-]+/Cargo\.toml$' -or
                -not (Test-D32BoundedCompilerDiagnosticInteger $manifest.bytes -Positive) -or [string]$manifest.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$manifest.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$manifest.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
                -not $workspaceManifests.TryAdd([string]$manifest.manifest_path, [string]$manifest.sha256)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'workspace-manifest-proof-shape-or-duplicate'
                return $false
            }
        }
        if ($workspaceManifests.Count -ne $Record.current_profile_lock_bindings.Count) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'workspace-manifest-to-profile-binding-count'
            return $false
        }
        foreach ($binding in $Record.current_profile_lock_bindings) {
            if (-not $workspaceManifests.ContainsKey([string]$binding.manifest_path)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'profile-binding-manifest-unmatched'
                return $false
            }
        }
        foreach ($class in $Record.current_source_closure.SourceGraphProof.classifications) {
            if ([string]$class.classification -cne 'INCLUDED') { continue }
            switch ([string]$class.source_kind) {
                'workspace' {
                    if (-not $workspaceManifests.ContainsKey([string]$class.manifest_path) -or $workspaceManifests[[string]$class.manifest_path] -cne [string]$class.manifest_sha256) {
                        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-workspace-manifest-crossbind'
                        return $false
                    }
                }
                'registry' {
                    if (-not $registryIds.Contains([string]$class.package_id) -or [string]$class.source_identity -cne 'registry+https://github.com/rust-lang/crates.io-index') {
                        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-registry-package-crossbind'
                        return $false
                    }
                }
                'git' {
                    if (-not $gitIds.Contains([string]$class.package_id) -or
                        @($Record.current_source_closure.GitContentProof.sources | Where-Object { [string]$_.source -ceq [string]$class.source_identity }).Count -ne 1) {
                        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-git-package-crossbind'
                        return $false
                    }
                }
                default {
                    Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-package-source-kind-unknown'
                    return $false
                }
            }
        }
        $lockBinding = @($Record.current_profile_lock_bindings | Where-Object { [string]$_.lock_path -ceq 'vita-agent/Cargo.lock' })
        if ($lockBinding.Count -ne 1 -or [string]$lockBinding[0].lock_sha256 -cne [string]$Record.current_source_closure.SourceGraphProof.lock_sha256) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'vita-agent-lock-profile-crossbind'
            return $false
        }
    }
    if ([string]$Record.status -ceq 'BLOCKED' -and [String]::IsNullOrWhiteSpace([string]$Record.primary_error)) {
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'blocked-primary-error-missing'
        return $false
    }
    return $true
}

function Test-D32BoundedDiagnosticSourceProofAuthorityShape {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$ExpectedHistoricalOriginCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$EntryScriptPath,
        [Parameter(Mandatory = $true)][string]$RunnerPath,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$ToolchainProfileSha256
    )
    $top = @('schema_version', 'record_type', 'gate_authority', 'candidate_sha', 'historical_origin_candidate_sha',
        'source_repo', 'repository_identity', 'toolchain_profile', 'source_pins', 'dependency_origin', 'proof_budget',
        'output_candidate', 'run_id', 'issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Document -Expected $top) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [int]$Document.schema_version -ne 1 -or
        $Document.record_type -isnot [string] -or [string]$Document.record_type -cne $script:D32BoundedDiagnosticSourceProofAuthorityType -or
        $Document.gate_authority -isnot [string] -or [string]$Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or [string]$Document.candidate_sha -cne $ExpectedCandidateSha -or
        $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        $Document.historical_origin_candidate_sha -isnot [string] -or
        [string]$Document.historical_origin_candidate_sha -cne $ExpectedHistoricalOriginCandidateSha -or
        [string]$Document.historical_origin_candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$Document.historical_origin_candidate_sha -ceq [string]$Document.candidate_sha -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$Document.source_repo), [IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.repository_identity @('volume_serial_hex', 'file_id_hex')) -or
        [string]$Document.run_id -cnotmatch '^[0-9a-f]{32}$') { return $false }

    $profile = $Document.toolchain_profile
    if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $profile) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$profile.path, [IO.Path]::GetFullPath($ToolchainProfilePath)) -or
        [string]$profile.sha256 -cne $ToolchainProfileSha256 -or
        [string]$profile.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $profile.path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $profile.path 'E:\d32\inv7\r\c')) { return $false }

    $origin = $Document.dependency_origin
    $originFields = @('path', 'volume_serial_hex', 'file_id_hex', 'owner_record', 'blocked_diagnostic', 'fetch_records',
        'manifest_refs', 'registry_archives', 'registry_archive_root', 'registry_source_root', 'git_database_root', 'git_checkout_root', 'git_content_refs')
    $requiredOrigin = 'E:\d32\inv7\r\c'
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $origin $originFields) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.path, $requiredOrigin) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin) -or
        $origin.fetch_records -isnot [Array] -or $origin.fetch_records.Count -gt 3 -or
        $origin.manifest_refs -isnot [Array] -or $origin.manifest_refs.Count -ne 6 -or
        $origin.registry_archives -isnot [Array] -or $origin.registry_archives.Count -eq 0 -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.owner_record) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.owner_record.path, 'E:\d32\inv7\D32-PHASE0-OWNER.json') -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.blocked_diagnostic) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.blocked_diagnostic.path, 'E:\d32\inv7\D32-PHASE0-BLOCKED-DIAGNOSTIC.json')) { return $false }
    foreach ($reference in @($origin.fetch_records) + @($origin.manifest_refs)) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false }
    }
    $rootPaths = @(
        [PSCustomObject]@{ Name = 'registry_archive_root'; Path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f' },
        [PSCustomObject]@{ Name = 'registry_source_root'; Path = 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f' },
        [PSCustomObject]@{ Name = 'git_database_root'; Path = 'E:\d32\inv7\r\c\git\db' },
        [PSCustomObject]@{ Name = 'git_checkout_root'; Path = 'E:\d32\inv7\r\c\git\checkouts' })
    foreach ($rootPin in $rootPaths) {
        $reference = $origin.PSObject.Properties[[string]$rootPin.Name].Value
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $reference @('path', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32BoundedCompilerDiagnosticIdentityPair $reference) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$reference.path, [string]$rootPin.Path)) { return $false }
    }
    foreach ($archive in $origin.registry_archives) {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $archive @('source', 'name', 'version', 'checksum', 'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
            [string]$archive.source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            [string]$archive.name -notmatch '^[A-Za-z0-9_-]+$' -or [string]$archive.version -notmatch '^[0-9A-Za-z.+_-]+$' -or
            [string]$archive.checksum -cnotmatch '^[0-9a-f]{64}$' -or [string]$archive.sha256 -cne [string]$archive.checksum -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.bytes -Positive) -or [Int64]$archive.bytes -gt 268435456 -or
            [string]$archive.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$archive.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$archive.path, (Join-Path ([string]$origin.registry_archive_root.path) ([string]$archive.name + '-' + [string]$archive.version + '.crate')))) { return $false }
    }
    if ($origin.git_content_refs -isnot [Array] -or $origin.git_content_refs.Count -eq 0 -or $origin.git_content_refs.Count -gt 16) { return $false }
    $gitSourcesSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($reference in $origin.git_content_refs) {
        if (-not (Test-D32BoundedCompilerDiagnosticGitContentReferenceShape $reference) -or -not $gitSourcesSeen.Add([string]$reference.source)) { return $false }
    }

    $pins = $Document.source_pins
    $expectedPins = @(
        'scripts/d32-bounded-diagnostic-sourceproof.ps1',
        'scripts/d32-bounded-compiler-diagnostic.ps1',
        'scripts/d32-bounded-compiler-diagnostic-policy.ps1',
        'scripts/d32-build-toolchain-profile.ps1',
        'scripts/d32-powershell-module-authority.ps1')
    if ($pins -isnot [Array] -or $pins.Count -ne $expectedPins.Count) { return $false }
    $pinPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pin in $pins) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin $pin.path $Repository) -or -not $pinPaths.Add([string]$pin.path)) { return $false }
    }
    foreach ($relative in $expectedPins) {
        $expectedPath = [IO.Path]::GetFullPath((Join-Path $Repository ($relative.Replace('/', '\'))))
        $matches = @($pins | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.path, $expectedPath) })
        if ($matches.Count -ne 1) { return $false }
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($EntryScriptPath), [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-diagnostic-sourceproof.ps1'))) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($RunnerPath), [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-compiler-diagnostic.ps1')))) { return $false }

    $budget = $Document.proof_budget
    $budgetFields = @('combined_milliseconds', 'managed_buffer_bytes', 'max_registry_archive_bytes', 'max_git_pack_bytes',
        'max_git_index_bytes', 'max_git_object_bytes', 'max_git_object_count', 'max_git_delta_depth', 'max_git_expanded_bytes', 'max_manifest_or_lock_file_bytes')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $budget $budgetFields)) { return $false }
    foreach ($name in $budgetFields) { if (-not (Test-D32BoundedCompilerDiagnosticInteger $budget.($name) -Positive)) { return $false } }
    if (
        [Int64]$budget.combined_milliseconds -ne 300000 -or [Int64]$budget.managed_buffer_bytes -ne 536870912 -or
        [Int64]$budget.max_registry_archive_bytes -ne 268435456 -or [Int64]$budget.max_git_pack_bytes -ne 268435456 -or
        [Int64]$budget.max_git_index_bytes -ne 67108864 -or [Int64]$budget.max_git_object_bytes -ne 67108864 -or
        [Int64]$budget.max_git_object_count -ne 500000 -or [Int64]$budget.max_git_delta_depth -ne 32 -or
        [Int64]$budget.max_git_expanded_bytes -ne 34359738368 -or [Int64]$budget.max_manifest_or_lock_file_bytes -ne 16777216) { return $false }

    $output = $Document.output_candidate
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $output @('path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.path), [string]$output.parent_path) -or
        [string]$output.parent_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$output.parent_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $requiredOrigin) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $profile.path)) { return $false }
    try { $null = [DateTimeOffset]::Parse([string]$Document.issued_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $false }
    return $true
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

function Test-D32BoundedCompilerDiagnosticGitContentReferenceShape {
    param([AllowNull()][object]$Reference)
    $fields = @('source', 'commit', 'database_path', 'database_volume_serial_hex', 'database_file_id_hex',
        'checkout_cache_path', 'checkout_cache_volume_serial_hex', 'checkout_cache_file_id_hex',
        'checkout_path', 'checkout_volume_serial_hex', 'checkout_file_id_hex',
        'pack_path', 'pack_bytes', 'pack_volume_serial_hex', 'pack_file_id_hex',
        'index_path', 'index_bytes', 'index_volume_serial_hex', 'index_file_id_hex')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Reference $fields) -or
        $Reference.source -isnot [string] -or $Reference.commit -isnot [string] -or
        [string]$Reference.commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Reference.source -notmatch '^git\+https://[^?#@\s]+(?:\?[^#\r\n]+)?#([0-9a-f]{40})$' -or
        [string]$Matches[1] -cne [string]$Reference.commit) { return $false }
    $databaseRoot = 'E:\d32\inv7\r\c\git\db'
    $checkoutRoot = 'E:\d32\inv7\r\c\git\checkouts'
    foreach ($path in @($Reference.database_path, $Reference.checkout_cache_path, $Reference.checkout_path, $Reference.pack_path, $Reference.index_path)) {
        if (-not (Test-D32BoundedCompilerDiagnosticCanonicalPath $path)) { return $false }
    }
    if (-not (Test-D32BoundedCompilerDiagnosticWithin $Reference.database_path $databaseRoot) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.checkout_cache_path $checkoutRoot) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.checkout_path $Reference.checkout_cache_path) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.pack_path $Reference.database_path) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.index_path $Reference.database_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Reference.pack_path), [IO.Path]::GetDirectoryName([string]$Reference.index_path)) -or
        [IO.Path]::GetFileName([string]$Reference.checkout_path) -cne ([string]$Reference.commit).Substring(0, 7) -or
        [IO.Path]::GetFileName([string]$Reference.pack_path) -cnotmatch '^pack-([0-9a-f]{40})\.pack$' -or
        [IO.Path]::GetFileName([string]$Reference.index_path) -cnotmatch '^pack-([0-9a-f]{40})\.idx$') { return $false }
    $packId = [regex]::Match([IO.Path]::GetFileName([string]$Reference.pack_path), '^pack-([0-9a-f]{40})\.pack$').Groups[1].Value
    $indexId = [regex]::Match([IO.Path]::GetFileName([string]$Reference.index_path), '^pack-([0-9a-f]{40})\.idx$').Groups[1].Value
    if ($packId -cne $indexId -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Reference.pack_bytes -Positive) -or [Int64]$Reference.pack_bytes -gt 268435456 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Reference.index_bytes -Positive) -or [Int64]$Reference.index_bytes -gt 67108864) { return $false }
    foreach ($name in @('database', 'checkout_cache', 'checkout', 'pack', 'index')) {
        $volumeName = $name + '_volume_serial_hex'
        $fileName = $name + '_file_id_hex'
        if ([string]$Reference.PSObject.Properties[$volumeName].Value -cnotmatch '^[0-9a-f]{16}$' -or
            [string]$Reference.PSObject.Properties[$fileName].Value -cnotmatch '^[0-9a-f]{32}$') { return $false }
    }
    return $true
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
    $originFields = @('path', 'volume_serial_hex', 'file_id_hex', 'historical_origin_candidate_sha', 'owner_record', 'blocked_diagnostic', 'protoc_run_grant', 'fetch_records', 'manifest_refs', 'registry_archive_root', 'registry_source_root', 'git_database_root', 'git_checkout_root', 'registry_archives', 'git_source_authority', 'git_content_refs')
    $requiredOrigin = 'E:\d32\inv7\r\c'
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $cargoHome $cargoFields) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin $originFields) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$cargoHome.path, $requiredOrigin) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.path, $requiredOrigin) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $cargoHome) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin) -or
        [string]$origin.historical_origin_candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$origin.historical_origin_candidate_sha -ceq [string]$Document.candidate_sha -or
        [string]$cargoHome.volume_serial_hex -cne [string]$origin.volume_serial_hex -or [string]$cargoHome.file_id_hex -cne [string]$origin.file_id_hex -or
        $origin.fetch_records -isnot [Array] -or $origin.fetch_records.Count -gt 3 -or
        $origin.manifest_refs -isnot [Array] -or $origin.manifest_refs.Count -ne 6 -or
        $origin.registry_archives -isnot [Array] -or $origin.registry_archives.Count -eq 0 -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.owner_record) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.blocked_diagnostic) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.protoc_run_grant) -or
        $origin.git_content_refs -isnot [Array] -or $origin.git_content_refs.Count -eq 0 -or $origin.git_content_refs.Count -gt 16 -or
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
    $seenGitContentSources = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($reference in $origin.git_content_refs) {
        if (-not (Test-D32BoundedCompilerDiagnosticGitContentReferenceShape $reference) -or -not $seenGitContentSources.Add([string]$reference.source)) { return $false }
    }

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

function ConvertFrom-D32BoundedDiagnosticLockStringArray {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Body)
    $items = [System.Collections.Generic.List[string]]::new()
    $index = 0
    while ($index -lt $Body.Length) {
        while ($index -lt $Body.Length -and ($Body[$index] -eq ',' -or [char]::IsWhiteSpace($Body[$index]))) { $index++ }
        if ($index -ge $Body.Length) { break }
        if ($Body[$index] -cne '"') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array has an unsupported TOML token' }
        $index++
        $value = [Text.StringBuilder]::new()
        $closed = $false
        while ($index -lt $Body.Length) {
            $character = $Body[$index++]
            if ($character -ceq '"') { $closed = $true; break }
            if ($character -ceq '\') {
                if ($index -ge $Body.Length) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: truncated TOML string escape' }
                $escape = $Body[$index++]
                if ($escape -cnotin @('"', '\', 'n', 'r', 't')) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unsupported dependency-string escape' }
                $character = switch ($escape) { 'n' { [char]10 } 'r' { [char]13 } 't' { [char]9 } default { $escape } }
            }
            [void]$value.Append($character)
        }
        if (-not $closed) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unterminated dependency string' }
        $items.Add($value.ToString())
        while ($index -lt $Body.Length -and [char]::IsWhiteSpace($Body[$index])) { $index++ }
        if ($index -lt $Body.Length -and $Body[$index] -cne ',') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array separator is unsupported' }
    }
    return $items.ToArray()
}

function ConvertFrom-D32BoundedDiagnosticLockDependencySpec {
    param([Parameter(Mandatory = $true)][string]$Value)
    $match = [regex]::Match($Value, '^(?<name>[A-Za-z0-9_-]+)(?: (?<version>[0-9][0-9A-Za-z.+_-]*))?(?: \((?<source>[^()\r\n]+)\))?$')
    if (-not $match.Success) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency edge identity is outside the supported finite Cargo.lock format' }
    return [PSCustomObject][ordered]@{
        raw = $Value
        name = [string]$match.Groups['name'].Value
        version = if ($match.Groups['version'].Success) { [string]$match.Groups['version'].Value } else { $null }
        source = if ($match.Groups['source'].Success) { [string]$match.Groups['source'].Value } else { $null }
    }
}

function Get-D32BoundedCompilerDiagnosticLockSources {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$LockText)
    if ($LockText.Length -le 0 -or $LockText.Length -gt 8388608) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: finite Cargo.lock input is empty or exceeds 8 MiB' }
    $packages = [System.Collections.Generic.List[object]]::new()
    $current = $null
    $collectingEdges = $false
    $lockVersion = $null
    $totalEdgeTextCount = 0
    foreach ($line in ($LockText -split '\r?\n')) {
        if ($line -cmatch '^\[\[package\]\]$') {
            if ($collectingEdges) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: truncated Cargo.lock dependency array before the next package' }
            if ($null -ne $current) { $packages.Add($current) }
            if ($packages.Count -gt 2048) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock package count exceeds its fixed 2048-entry limit' }
            $current = [ordered]@{ name = $null; version = $null; source = $null; checksum = $null; dependency_text = $null; dependencies = @() }
            continue
        }
        if ($null -eq $current) {
            $rootLine = $line.Trim()
            if ([String]::IsNullOrWhiteSpace($rootLine) -or $rootLine.StartsWith('#')) { continue }
            if ($rootLine -cmatch '^version\s*=\s*([0-9]+)\s*$') {
                if ($null -ne $lockVersion -or [int]$Matches[1] -notin @(3, 4)) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock version is duplicated or outside the finite supported v3/v4 formats' }
                $lockVersion = [int]$Matches[1]
                continue
            }
            throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unsupported Cargo.lock root statement or table before package catalog'
        }
        if ($collectingEdges) {
            $current.dependency_text += "`n" + $line
            if ($line -match '\]') {
                $close = $current.dependency_text.LastIndexOf(']')
                if ($close -lt 0 -or -not [String]::IsNullOrWhiteSpace($current.dependency_text.Substring($close + 1))) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array tail is unsupported' }
                $body = $current.dependency_text.Substring(0, $close)
                $current.dependencies = @(ConvertFrom-D32BoundedDiagnosticLockStringArray -Body $body)
                $totalEdgeTextCount += $current.dependencies.Count
                if ($totalEdgeTextCount -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock dependency edge count exceeds its fixed 65536-entry limit' }
                $collectingEdges = $false
            }
            continue
        }
        if ([String]::IsNullOrWhiteSpace($line) -or $line.Trim().StartsWith('#')) { continue }
        if ($line -cmatch '^name\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.name) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package name field' }; $current.name = [string]$Matches[1]; continue }
        if ($line -cmatch '^version\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.version) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package version field' }; $current.version = [string]$Matches[1]; continue }
        if ($line -cmatch '^source\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.source) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package source field' }; $current.source = [string]$Matches[1]; continue }
        if ($line -cmatch '^checksum\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.checksum) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package checksum field' }; $current.checksum = [string]$Matches[1]; continue }
        if ($line -cmatch '^dependencies\s*=\s*\[(.*)$') {
            if ($null -ne $current.dependency_text) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package dependency array' }
            $current.dependency_text = [string]$Matches[1]
            if ($current.dependency_text -match '\]') {
                $close = $current.dependency_text.LastIndexOf(']')
                if (-not [String]::IsNullOrWhiteSpace($current.dependency_text.Substring($close + 1))) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array tail is unsupported' }
                $current.dependencies = @(ConvertFrom-D32BoundedDiagnosticLockStringArray -Body $current.dependency_text.Substring(0, $close))
                $totalEdgeTextCount += $current.dependencies.Count
                if ($totalEdgeTextCount -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock dependency edge count exceeds its fixed 65536-entry limit' }
            }
            else { $collectingEdges = $true }
            continue
        }
        throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: package record contains an unsupported or malformed Cargo.lock field/table'
    }
    if ($collectingEdges) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unterminated Cargo.lock dependency array' }
    if ($null -ne $current) { $packages.Add($current) }
    if ($null -eq $lockVersion -or $packages.Count -eq 0 -or $packages.Count -gt 2048) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: finite Cargo.lock requires one supported version and a bounded nonempty package catalog' }
    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($package in $packages) {
        if ([String]::IsNullOrWhiteSpace([string]$package.name) -or [string]$package.name -notmatch '^[A-Za-z0-9_-]+$' -or
            [String]::IsNullOrWhiteSpace([string]$package.version) -or [string]$package.version -notmatch '^[0-9A-Za-z.+_-]+$') {
            throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock package identity is malformed'
        }
        $sourceKind = $null
        $commit = $null
        if ($null -ne $package.source -and [string]$package.source -like 'registry+*') {
            if ([string]$package.checksum -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: locked registry package lacks its exact SHA-256 checksum' }
            $sourceKind = 'registry'
        }
        elseif ($null -ne $package.source -and [string]$package.source -like 'git+*') {
            $gitMatch = [regex]::Match([string]$package.source, '#([0-9a-f]{40})$')
            if (-not $gitMatch.Success -or [string]$package.checksum -ne '') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: locked Git package source/commit is incomplete' }
            $sourceKind = 'git'
            $commit = [string]$gitMatch.Groups[1].Value
        }
        elseif ($null -eq $package.source -and $null -eq $package.checksum) { $sourceKind = 'workspace' }
        else { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock source kind is unsupported or incomplete' }
        $sourceIdentity = if ($null -eq $package.source) { 'workspace' } else { [string]$package.source }
        $id = [string]$package.name + '@' + [string]$package.version + '|' + $sourceKind + '|' + $sourceIdentity
        $edgeSpecs = [System.Collections.Generic.List[object]]::new()
        foreach ($dependencyText in $package.dependencies) { $edgeSpecs.Add((ConvertFrom-D32BoundedDiagnosticLockDependencySpec -Value ([string]$dependencyText))) }
        $output.Add([PSCustomObject][ordered]@{
            package_id = $id; name = [string]$package.name; version = [string]$package.version; source = $package.source
            source_kind = $sourceKind; checksum = $package.checksum; commit = $commit; dependency_specs = @($edgeSpecs.ToArray()); dependency_ids = @()
        })
    }
    return $output.ToArray()
}

function Get-D32BoundedCompilerDiagnosticSourcePlan {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$LockText)
    $maxLockCharacters = 8388608
    $maxLockedPackages = 2048
    $maxRegistryPackages = 1536
    $maxGitSources = 16
    if ($LockText.Length -le 0 -or $LockText.Length -gt $maxLockCharacters) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: lock input is empty or exceeds its fixed 8 MiB text bound' }
    $packages = @(Get-D32BoundedCompilerDiagnosticLockSources -LockText $LockText)
    if ($packages.Count -eq 0 -or $packages.Count -gt $maxLockedPackages) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: locked package inventory is empty or exceeds its fixed 2048-entry bound' }
    $catalog = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($package in $packages) { if (-not $catalog.TryAdd([string]$package.package_id, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate full Cargo.lock package identity' } }
    $edges = [System.Collections.Generic.List[object]]::new()
    foreach ($package in $packages) {
        $targets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($spec in $package.dependency_specs) {
            $matches = @($packages | Where-Object {
                [string]$_.name -ceq [string]$spec.name -and
                ($null -eq $spec.version -or [string]$_.version -ceq [string]$spec.version) -and
                ($null -eq $spec.source -or [string]$_.source -ceq [string]$spec.source)
            })
            if ($matches.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Cargo.lock dependency edge does not resolve to exactly one audited package ID' }
            $target = $matches[0]
            if (-not $targets.Add([string]$target.package_id)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate dependency edge target is unsupported' }
            $edges.Add([PSCustomObject][ordered]@{ parent_package_id = [string]$package.package_id; target_package_id = [string]$target.package_id; lock_spec = [string]$spec.raw })
        }
        $targetIds = [string[]]@($targets)
        [Array]::Sort($targetIds, [StringComparer]::Ordinal)
        $package.dependency_ids = @($targetIds)
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
            if ([string]$package.source -cne 'registry+https://github.com/rust-lang/crates.io-index') { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: non-crates.io registry source is outside the approved finite origin' }
            $key = [string]$package.name + [char]0 + [string]$package.version
            if (-not $packageKeys.Add($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate locked registry name/version tuple' }
            $archivePath = [IO.Path]::GetFullPath((Join-Path $registryCache ([string]$package.name + '-' + [string]$package.version + '.crate')))
            $sourcePath = [IO.Path]::GetFullPath((Join-Path $registrySource ([string]$package.name + '-' + [string]$package.version)))
            if (-not $pathKeys.Add($archivePath) -or -not $pathKeys.Add($sourcePath)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: case-insensitive registry path collision' }
            $registryRows.Add([PSCustomObject][ordered]@{ package_id = $package.package_id; name = $package.name; version = $package.version; checksum = $package.checksum; source = $package.source; archive_path = $archivePath; extracted_source_path = $sourcePath })
        }
        elseif ($package.source_kind -ceq 'git') {
            $source = [string]$package.source
            $match = [regex]::Match($source, '^git\+(https://[^?#@\s]+(?:\?[^#\r\n]+)?)#([0-9a-f]{40})$')
            if (-not $match.Success -or [string]$match.Groups[2].Value -cne [string]$package.commit) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source must be an immutable HTTPS URL plus the same full lowercase 40-hex lock commit' }
            $url = [string]$match.Groups[1].Value
            $parsedUrl = $null
            if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$parsedUrl) -or $parsedUrl.Scheme -cne 'https' -or [String]::IsNullOrEmpty($parsedUrl.Host) -or -not [String]::IsNullOrEmpty($parsedUrl.UserInfo)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source URL is not an absolute credential-free HTTPS URL' }
            $query = if ($url.Contains('?')) { $url.Substring($url.IndexOf('?') + 1) } else { '' }
            if ($query -cnotmatch ('(?:^|&)rev=' + [regex]::Escape([string]$package.commit) + '(?:&|$)')) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source query does not pin the exact full commit with rev=' }
            if (-not $gitBySource.ContainsKey($source)) {
                $gitBySource.Add($source, [PSCustomObject][ordered]@{ source = $source; url = $url; commit = [string]$package.commit; database_root = [IO.Path]::GetFullPath((Join-Path $cargoHome 'git/db')); checkout_root = [IO.Path]::GetFullPath((Join-Path $cargoHome 'git/checkouts')) })
            }
        }
        elseif ($package.source_kind -cne 'workspace') { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: lock contains an unapproved source kind' }
    }
    if ($registryRows.Count -gt $maxRegistryPackages -or $gitBySource.Count -gt $maxGitSources) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: registry or Git tuple count exceeds its fixed finite bound' }
    $registryRows.Sort([System.Comparison[object]]{ param($a, $b) [StringComparer]::Ordinal.Compare(([string]$a.name + [char]0 + [string]$a.version), ([string]$b.name + [char]0 + [string]$b.version)) })
    $gitRows = [System.Collections.Generic.List[object]]::new()
    foreach ($source in @($gitBySource.Keys | Sort-Object -CaseSensitive)) { $gitRows.Add($gitBySource[$source]) }
    $registryCanonical = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $registryRows) { $registryCanonical.Add(('registry' + [char]9 + $row.name + [char]9 + $row.version + [char]9 + $row.checksum)) }
    $gitCanonical = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $gitRows) { $gitCanonical.Add(('git' + [char]9 + $row.url + [char]9 + $row.commit)) }
    $edgeCanonical = [System.Collections.Generic.List[string]]::new()
    foreach ($edge in $edges) { $edgeCanonical.Add(([string]$edge.parent_package_id + [char]9 + [string]$edge.target_package_id + [char]9 + [string]$edge.lock_spec)) }
    $edgeCanonical.Sort([StringComparer]::Ordinal)
    $utf8 = [Text.UTF8Encoding]::new($false)
    $registryDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(([string]::Join([char]10, $registryCanonical.ToArray())) + [char]10))).ToLowerInvariant()
    $gitDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(([string]::Join([char]10, $gitCanonical.ToArray())) + [char]10))).ToLowerInvariant()
    $edgeDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(([string]::Join([char]10, $edgeCanonical.ToArray())) + [char]10))).ToLowerInvariant()
    $lockDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($LockText))).ToLowerInvariant()
    return [PSCustomObject][ordered]@{
        schema_version = 2; record_type = 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2'; gate_authority = 'NONE'; verification_status = 'NOT_RUN'
        semantic_scope = 'FULL_LOCK_AUDIT_CATALOG_PLUS_SELECTED_REACHABLE_CONSERVATIVE_SUPERSET'
        cargo_home = $cargoHome; target_triple = 'x86_64-pc-windows-msvc'; host_triple = 'x86_64-pc-windows-msvc'
        lock_bytes = [Int64]$utf8.GetByteCount($LockText); lock_sha256 = $lockDigest
        locked_package_count = [Int64]$packages.Count; locked_packages = @($packages)
        lock_dependency_edge_count = [Int64]$edges.Count; lock_dependency_edges = @($edges.ToArray()); lock_dependency_edges_sha256 = $edgeDigest
        registry_package_count = [Int64]$registryRows.Count; registry_tuple_sha256 = $registryDigest
        registry_archive_root = [IO.Path]::GetFullPath($registryCache); registry_source_root = [IO.Path]::GetFullPath($registrySource); registry_packages = @($registryRows.ToArray())
        git_source_count = [Int64]$gitRows.Count; git_tuple_sha256 = $gitDigest; git_sources = @($gitRows.ToArray())
        selected_roots = @(); selected_root_rule = 'NOT_RESOLVED_WITHOUT_PINNED_MANIFEST'; requested_features = @('default', 'd32-a-test-helper')
        verifier_managed_buffer_cap_bytes = [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes; source_proof_status = 'NOT_VERIFIED'
    }
}

function Split-D32BoundedDiagnosticTopLevel {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text, [char]$Separator = ',')
    $parts = [System.Collections.Generic.List[string]]::new()
    $start = 0; $depthSquare = 0; $depthCurly = 0; $depthParen = 0; $quote = [char]0; $escaped = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = $Text[$i]
        if ($quote -ne [char]0) {
            if ($quote -ceq '"' -and $escaped) { $escaped = $false; continue }
            if ($quote -ceq '"' -and $ch -ceq '\\') { $escaped = $true; continue }
            if ($ch -ceq $quote) { $quote = [char]0 }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; continue }
        if ($ch -ceq '[') { $depthSquare++; continue }
        if ($ch -ceq ']') { $depthSquare--; if ($depthSquare -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unbalanced TOML array' }; continue }
        if ($ch -ceq '{') { $depthCurly++; continue }
        if ($ch -ceq '}') { $depthCurly--; if ($depthCurly -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unbalanced TOML inline table' }; continue }
        if ($ch -ceq '(') { $depthParen++; continue }
        if ($ch -ceq ')') { $depthParen--; if ($depthParen -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unbalanced cfg parenthesis' }; continue }
        if ($ch -ceq $Separator -and $depthSquare -eq 0 -and $depthCurly -eq 0 -and $depthParen -eq 0) {
            $parts.Add($Text.Substring($start, $i - $start).Trim()); $start = $i + 1
        }
    }
    if ($quote -ne [char]0 -or $depthSquare -ne 0 -or $depthCurly -ne 0 -or $depthParen -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML value has unbalanced string/container delimiters' }
    if ($start -lt $Text.Length -or $Text.Length -eq 0) { $parts.Add($Text.Substring($start).Trim()) }
    return $parts.ToArray()
}

function Remove-D32BoundedDiagnosticTomlComment {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)
    $quote = [char]0; $escaped = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $ch = $Line[$i]
        if ($quote -ne [char]0) {
            if ($quote -ceq '"' -and $escaped) { $escaped = $false; continue }
            if ($quote -ceq '"' -and $ch -ceq '\\') { $escaped = $true; continue }
            if ($ch -ceq $quote) { $quote = [char]0 }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; continue }
        if ($ch -ceq '#') { return $Line.Substring(0, $i) }
    }
    return $Line
}

function ConvertFrom-D32BoundedDiagnosticTomlString {
    param([Parameter(Mandatory = $true)][string]$Text)
    $value = $Text.Trim()
    if ($value.Length -lt 2 -or ($value[0] -cne '"' -and $value[0] -cne "'") -or $value[$value.Length - 1] -cne $value[0]) {
        throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: expected a bounded TOML string'
    }
    $quote = $value[0]; $result = [Text.StringBuilder]::new()
    for ($i = 1; $i -lt ($value.Length - 1); $i++) {
        $ch = $value[$i]
        if ($quote -ceq '"' -and $ch -ceq '\\') {
            $i++; if ($i -ge ($value.Length - 1)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: truncated TOML string escape' }
            $escape = $value[$i]
            $decoded = switch ($escape) {
                '"' { '"' } '\\' { '\\' } 'n' { [char]10 } 'r' { [char]13 } 't' { [char]9 } 'b' { [char]8 } 'f' { [char]12 }
                default { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported TOML string escape' }
            }
            [void]$result.Append($decoded); continue
        }
        [void]$result.Append($ch)
    }
    return $result.ToString()
}

function ConvertFrom-D32BoundedDiagnosticCargoValue {
    param([Parameter(Mandatory = $true)][string]$Text)
    $value = $Text.Trim()
    if ($value.Length -ge 2 -and (($value[0] -ceq '"' -and $value[$value.Length - 1] -ceq '"') -or ($value[0] -ceq "'" -and $value[$value.Length - 1] -ceq "'"))) {
        return [PSCustomObject]@{ kind = 'string'; value = (ConvertFrom-D32BoundedDiagnosticTomlString -Text $value) }
    }
    if ($value -ceq 'true' -or $value -ceq 'false') { return [PSCustomObject]@{ kind = 'bool'; value = ($value -ceq 'true') } }
    if ($value.StartsWith('[') -and $value.EndsWith(']')) {
        $items = [System.Collections.Generic.List[string]]::new()
        $inner = $value.Substring(1, $value.Length - 2)
        foreach ($part in (Split-D32BoundedDiagnosticTopLevel -Text $inner)) {
            if ([String]::IsNullOrWhiteSpace($part)) { continue }
            $parsed = ConvertFrom-D32BoundedDiagnosticCargoValue -Text $part
            if ([string]$parsed.kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: only bounded string arrays are supported in dependency metadata' }
            $items.Add([string]$parsed.value)
        }
        return [PSCustomObject]@{ kind = 'array'; value = @($items.ToArray()) }
    }
    if ($value.StartsWith('{') -and $value.EndsWith('}')) {
        $map = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        $inner = $value.Substring(1, $value.Length - 2)
        foreach ($part in (Split-D32BoundedDiagnosticTopLevel -Text $inner)) {
            if ([String]::IsNullOrWhiteSpace($part)) { continue }
            $assignment = [regex]::Match($part, '^\s*(?<key>[A-Za-z0-9_-]+)\s*=\s*(?<value>.+?)\s*$')
            if (-not $assignment.Success) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported inline-table field syntax' }
            $key = [string]$assignment.Groups['key'].Value
            if ($map.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate inline-table field' }
            $map.Add($key, (ConvertFrom-D32BoundedDiagnosticCargoValue -Text ([string]$assignment.Groups['value'].Value)))
        }
        return [PSCustomObject]@{ kind = 'table'; value = $map }
    }
    throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported TOML value in the finite dependency parser'
}

function Test-D32BoundedDiagnosticTomlStatementComplete {
    param([Parameter(Mandatory = $true)][string]$Text)
    $square = 0; $curly = 0; $quote = [char]0; $escaped = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = $Text[$i]
        if ($quote -ne [char]0) {
            if ($quote -ceq '"' -and $escaped) { $escaped = $false; continue }
            if ($quote -ceq '"' -and $ch -ceq '\\') { $escaped = $true; continue }
            if ($ch -ceq $quote) { $quote = [char]0 }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; continue }
        if ($ch -ceq '[') { $square++ } elseif ($ch -ceq ']') { $square-- } elseif ($ch -ceq '{') { $curly++ } elseif ($ch -ceq '}') { $curly-- }
        if ($square -lt 0 -or $curly -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML statement has unbalanced delimiters' }
    }
    return ($quote -eq [char]0 -and $square -eq 0 -and $curly -eq 0)
}

function ConvertFrom-D32BoundedDiagnosticCargoManifest {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text, [string]$SourcePath = '')
    if ($Text.Length -le 0 -or [Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576 -or $Text.Contains("`0")) {
        throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: manifest is empty or exceeds the 1 MiB finite input bound'
    }
    $section = 'other'; $targetCondition = ''; $nestedAlias = ''; $nestedKind = 'dependencies'; $nestedKey = ''; $pending = ''
    $package = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $workspace = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $workspacePackage = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $dependencies = [System.Collections.Generic.List[object]]::new(); $workspaceDependencies = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $features = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $patches = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $nestedDeps = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $workspaceRootSeen = $false
    $lineNumber = 0
    foreach ($rawLine in ($Text -split '\r?\n')) {
        $lineNumber++; $line = (Remove-D32BoundedDiagnosticTomlComment -Line $rawLine).Trim()
        if ([String]::IsNullOrWhiteSpace($line)) { continue }
        if ([String]::IsNullOrEmpty($pending) -and $line.StartsWith('[')) {
            if ($line -match '^\[\[.*\]\]$') { $section = 'other'; $targetCondition = ''; $nestedAlias = ''; $nestedKey = ''; continue }
            if ($line -notmatch '^\[(?<body>[^\[\]]+)\]$') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported TOML table header' }
            $body = [string]$Matches['body']; $section = 'other'; $targetCondition = ''; $nestedAlias = ''; $nestedKey = ''; $nestedKind = 'dependencies'
            switch -Regex ($body) {
                '^package$' { $section = 'package'; break }
                '^workspace$' { $section = 'workspace'; $workspaceRootSeen = $true; break }
                '^workspace\.package$' { $section = 'workspace_package'; break }
                '^workspace\.dependencies$' { $section = 'workspace_dependencies'; break }
                '^features$' { $section = 'features'; break }
                '^patch\.crates-io$' { $section = 'patches'; break }
                '^(?<dependency_kind>dependencies|dev-dependencies|build-dependencies)$' { $section = [string]$Matches['dependency_kind']; break }
                '^(?<parent>dependencies|dev-dependencies|build-dependencies)\.(?<alias>[A-Za-z0-9_-]+)$' { $section = 'nested_dependency'; $nestedKind = [string]$Matches['parent']; $nestedAlias = [string]$Matches['alias']; $targetCondition = ''; $nestedKey = $nestedKind + [char]0 + $nestedAlias; break }
                '^workspace\.dependencies\.(?<alias>[A-Za-z0-9_-]+)$' { $section = 'nested_workspace_dependency'; $nestedAlias = [string]$Matches['alias']; break }
                '^target\.(?<target>"[^"]+"|''[^'']+''|[A-Za-z0-9_-]+)\.(?<kind>dependencies|dev-dependencies|build-dependencies)$' {
                    $targetCondition = [string]$Matches['target']; if ($targetCondition.Length -ge 2) { $targetCondition = $targetCondition.Substring(1, $targetCondition.Length - 2) }; $section = 'target_' + [string]$Matches['kind']; break
                }
                '^target\.(?<target>"[^"]+"|''[^'']+''|[A-Za-z0-9_-]+)\.(?<kind>dependencies|dev-dependencies|build-dependencies)\.(?<alias>[A-Za-z0-9_-]+)$' {
                    $targetCondition = [string]$Matches['target']; if ($targetCondition.Length -ge 2) { $targetCondition = $targetCondition.Substring(1, $targetCondition.Length - 2) }; $section = 'nested_dependency'; $nestedKind = [string]$Matches['kind']; $nestedAlias = [string]$Matches['alias']; $nestedKey = $nestedKind + [char]0 + $targetCondition + [char]0 + $nestedAlias; break
                }
                default {
                    if ($body -match '^(?:replace(?:\.|$)|patch\.)' -and $body -cne 'patch.crates-io') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported source-affecting replace or patch table' }
                    $section = 'other'
                }
            }
            continue
        }
        if (-not [String]::IsNullOrEmpty($pending)) { $pending += ' ' + $line } else { $pending = $line }
        if (-not (Test-D32BoundedDiagnosticTomlStatementComplete -Text $pending)) { continue }
        $assignment = [regex]::Match($pending, '^\s*(?<key>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?)\s*=\s*(?<value>.+?)\s*$')
        if (-not $assignment.Success) { if ($section -ne 'other') { throw ('D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported assignment at ' + $SourcePath + ':' + $lineNumber) }; $pending = ''; continue }
        $key = [string]$assignment.Groups['key'].Value; $value = ConvertFrom-D32BoundedDiagnosticCargoValue -Text ([string]$assignment.Groups['value'].Value)
        switch -Regex ($section) {
            '^package$' { if ($package.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate package field' }; $package.Add($key, $value); break }
            '^workspace$' { if ($workspace.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate workspace field' }; $workspace.Add($key, $value); break }
            '^workspace_package$' { if ($workspacePackage.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate workspace package field' }; $workspacePackage.Add($key, $value); break }
            '^features$' { if ($features.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate feature declaration' }; $features.Add($key, $value); break }
            '^dependencies$|^dev-dependencies$|^build-dependencies$|^target_' {
                $kind = $section; $condition = $targetCondition
                if ($section.StartsWith('target_')) { $kind = $section.Substring(7) }
                if ($value.kind -ceq 'string') { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $fields.Add('version', $value) }
                elseif ($value.kind -ceq 'table') { $fields = $value.value }
                else { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: dependency declaration must be a string or inline table' }
                $dependencies.Add([PSCustomObject]@{ alias = $key; kind = $kind; target = $condition; fields = $fields }); break
            }
            '^nested_dependency$' {
                $fields = $null
                if (-not $nestedDeps.TryGetValue($nestedKey, [ref]$fields)) { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $nestedDeps.Add($nestedKey, [PSCustomObject]@{ alias = $nestedAlias; kind = $nestedKind; target = $targetCondition; fields = $fields }) }
                else { $fields = $nestedDeps[$nestedKey].fields }
                if ($fields.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate nested dependency field' }; $fields.Add($key, $value); break
            }
            '^workspace_dependencies$' {
                if ($value.kind -ceq 'string') { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $fields.Add('version', $value) }
                elseif ($value.kind -ceq 'table') { $fields = $value.value } else { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: workspace dependency must be a string or inline table' }
                if ($workspaceDependencies.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate workspace dependency' }; $workspaceDependencies.Add($key, $fields); break
            }
            '^nested_workspace_dependency$' {
                $fields = $null
                if (-not $workspaceDependencies.TryGetValue($nestedAlias, [ref]$fields)) { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $workspaceDependencies.Add($nestedAlias, $fields) }
                if ($fields.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate nested workspace dependency field' }; $fields.Add($key, $value); break
            }
            '^patches$' {
                if ($value.kind -ceq 'string') { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $fields.Add('version', $value) }
                elseif ($value.kind -ceq 'table') { $fields = $value.value } else { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: patch declaration must be a string or inline table' }
                if ($patches.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate patch declaration' }; $patches.Add($key, $fields); break
            }
            default { }
        }
        $pending = ''
    }
    if (-not [String]::IsNullOrEmpty($pending)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: manifest ends with an incomplete TOML statement' }
    foreach ($nestedKeyValue in $nestedDeps.Keys) {
        $nested = $nestedDeps[$nestedKeyValue]
        $dependencies.Add([PSCustomObject]@{ alias = [string]$nested.alias; kind = [string]$nested.kind; target = [string]$nested.target; fields = $nested.fields })
    }
    foreach ($key in @('name', 'version')) {
        if ($package.ContainsKey($key) -and $package[$key].kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: package name/version must be literal strings unless workspace inheritance is explicit' }
    }
    if ($package.ContainsKey('workspace') -and $package['workspace'].kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: package.workspace must be a literal relative path' }
    if ($package.ContainsKey('version.workspace') -and ($package['version.workspace'].kind -cne 'bool' -or -not [bool]$package['version.workspace'].value)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: package version workspace inheritance must be explicitly true' }
    if ($workspace.ContainsKey('members') -and $workspace['members'].kind -cne 'array') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: workspace members must be a supported string array' }
    if ($workspace.ContainsKey('default-members') -and $workspace['default-members'].kind -cne 'array') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: workspace default-members must be a supported string array' }
    foreach ($feature in $features.Values) { if ($feature.kind -cne 'array') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: feature activation declarations must be bounded string arrays' } }
    return [PSCustomObject][ordered]@{
        source_path = $SourcePath
        package_name = if ($package.ContainsKey('name')) { [string]$package['name'].value } else { $null }
        package_version = if ($package.ContainsKey('version')) { [string]$package['version'].value } else { $null }
        package_version_workspace = ($package.ContainsKey('version.workspace') -and $package['version.workspace'].kind -ceq 'bool' -and [bool]$package['version.workspace'].value)
        is_workspace_root = $workspaceRootSeen
        workspace_root_path = if ($package.ContainsKey('workspace')) { [string]$package['workspace'].value } else { $null }
        workspace_members = if ($workspace.ContainsKey('members') -and $workspace['members'].kind -ceq 'array') { @($workspace['members'].value) } else { @() }
        workspace_default_members = if ($workspace.ContainsKey('default-members') -and $workspace['default-members'].kind -ceq 'array') { @($workspace['default-members'].value) } else { @() }
        workspace_package = $workspacePackage; workspace_dependencies = $workspaceDependencies; dependencies = @($dependencies.ToArray()); features = $features; patches = $patches
    }
}

function Get-D32BoundedDiagnosticTargetPredicate {
    param([Parameter(Mandatory = $true)][string]$Expression, [Parameter(Mandatory = $true)][string]$TargetTriple)
    if ($Expression -ceq $TargetTriple) { return [PSCustomObject]@{ value = $true; proven = $true; witness = 'exact target triple' } }
    if ($Expression -match '^cfg\((?<inner>.*)\)$') { $inner = [string]$Matches['inner'] } else { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown target selector conservatively included' } }
    $inner = $inner.Trim()
    foreach ($operator in @('all', 'any', 'not')) {
        if ($inner.StartsWith($operator + '(') -and $inner.EndsWith(')')) {
            $parts = @(Split-D32BoundedDiagnosticTopLevel -Text $inner.Substring($operator.Length + 1, $inner.Length - $operator.Length - 2))
            if ($operator -ceq 'not') { if ($parts.Count -ne 1) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'malformed unknown cfg conservatively included' } }; $child = Get-D32BoundedDiagnosticTargetPredicate -Expression ('cfg(' + $parts[0] + ')') -TargetTriple $TargetTriple; if (-not $child.proven) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'not of unknown cfg conservatively included' } }; return [PSCustomObject]@{ value = -not [bool]$child.value; proven = $true; witness = 'not(' + [string]$child.witness + ')' } }
            $children = @($parts | ForEach-Object { Get-D32BoundedDiagnosticTargetPredicate -Expression ('cfg(' + $_ + ')') -TargetTriple $TargetTriple })
            if ($operator -ceq 'all') { if (@($children | Where-Object { $_.proven -and -not $_.value }).Count -gt 0) { return [PSCustomObject]@{ value = $false; proven = $true; witness = 'all contains proven-false target predicate' } }; if (@($children | Where-Object { -not $_.proven }).Count -gt 0) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown member of all conservatively included' } }; return [PSCustomObject]@{ value = $true; proven = $true; witness = 'all target predicates proven true' } }
            if (@($children | Where-Object { $_.proven -and $_.value }).Count -gt 0) { return [PSCustomObject]@{ value = $true; proven = $true; witness = 'any contains proven-true target predicate' } }; if (@($children | Where-Object { -not $_.proven }).Count -gt 0) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown member of any conservatively included' } }; return [PSCustomObject]@{ value = $false; proven = $true; witness = 'all any-target predicates proven false' }
        }
    }
    $atom = [regex]::Match($inner, '^(?<name>[A-Za-z0-9_]+)\s*=\s*(?<value>"[^"]+")$')
    if ($atom.Success) {
        $name = [string]$atom.Groups['name'].Value; $value = [string]$atom.Groups['value'].Value.Trim('"')
        $facts = @{ target_arch = 'x86_64'; target_os = 'windows'; target_family = 'windows'; target_env = 'msvc'; target_vendor = 'pc'; target_endian = 'little'; target_pointer_width = '64' }
        if ($facts.ContainsKey($name)) { return [PSCustomObject]@{ value = ($facts[$name] -ceq $value); proven = $true; witness = ($name + '=' + $facts[$name]) } }
        return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown cfg atom conservatively included' }
    }
    if ($inner -ceq 'windows') { return [PSCustomObject]@{ value = $true; proven = $true; witness = 'windows host/target fact' } }
    if ($inner -ceq 'unix') { return [PSCustomObject]@{ value = $false; proven = $true; witness = 'not a Unix target' } }
    return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown cfg expression conservatively included' }
}

function Test-D32BoundedDiagnosticVersionRequirement {
    param([Parameter(Mandatory = $true)][string]$Requirement, [Parameter(Mandatory = $true)][string]$LockedVersion)
    if ($Requirement -ceq '*') { return $true }
    if ($Requirement -match '^=(?<exact>[0-9A-Za-z.+_-]+)$') { return [string]$Matches['exact'] -ceq $LockedVersion }
    if ($Requirement.Contains('-') -and $Requirement -ceq $LockedVersion) { return $true }
    if ($LockedVersion -match '-' -or $LockedVersion -notmatch '^(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:\+(?<build>[0-9A-Za-z.-]+))?$') { return $false }
    $locked = [version]::new([int]$Matches.major, [int]$Matches.minor, [int]$Matches.patch)
    foreach ($part in [regex]::Split($Requirement, '\s*,\s*')) {
        if ($part -match '^(?<op>>=|<=|>|<|\^|~|=)?\s*(?<major>0|[1-9][0-9]*)(?:\.(?<minor>0|[1-9][0-9]*|\*))?(?:\.(?<patch>0|[1-9][0-9]*|\*))?$') {
            $op = if ($Matches.op) { [string]$Matches.op } else { '^' }; $major = [int]$Matches.major
            $minor = if ($Matches.minor -and $Matches.minor -ne '*') { [int]$Matches.minor } else { 0 }; $patch = if ($Matches.patch -and $Matches.patch -ne '*') { [int]$Matches.patch } else { 0 }
            $minorWildcard = ($Matches.minor -ceq '*')
            $patchWildcard = ($Matches.patch -ceq '*')
            $specified = if ($Matches.patch -and -not $patchWildcard) { 3 } elseif ($Matches.minor -and -not $minorWildcard) { 2 } else { 1 }
            if (($minorWildcard -or $patchWildcard) -and $op -cnotin @('^', '')) { return $false }
            if ($minorWildcard -and $Matches.patch -and $Matches.patch -cne '*') { return $false }
            $base = [version]::new($major, $minor, $patch)
            if ($minorWildcard) { if ([int]$locked.Major -ne $major) { return $false }; continue }
            if ($patchWildcard) { if ([int]$locked.Major -ne $major -or [int]$locked.Minor -ne $minor) { return $false }; continue }
            $ok = switch ($op) {
                '=' { $locked -eq $base -and $specified -eq 3 }
                '>' { $locked -gt $base }
                '>=' { $locked -ge $base }
                '<' { $locked -lt $base }
                '<=' { $locked -le $base }
                '~' { if ($specified -ge 2) { $locked -ge $base -and $locked -lt [version]::new($major, $minor + 1, 0) } else { $locked -ge $base -and $locked -lt [version]::new($major + 1, 0, 0) } }
                default { if ($major -gt 0 -or $specified -eq 1) { $locked -ge $base -and $locked -lt [version]::new($major + 1, 0, 0) } elseif ($minor -gt 0 -or $specified -eq 2) { $locked -ge $base -and $locked -lt [version]::new(0, $minor + 1, 0) } else { $locked -ge $base -and $locked -lt [version]::new(0, 0, $patch + 1) } }
            }
            if (-not $ok) { return $false }; continue
        }
        return $false
    }
    return $true
}

function Resolve-D32BoundedDiagnosticWorkspaceDependency {
    param([Parameter(Mandatory = $true)][object]$Dependency, [AllowNull()][object]$WorkspaceManifest)
    $fields = $Dependency.fields
    if (-not ($fields -is [System.Collections.IDictionary])) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency fields are not a supported map' }
    $workspaceFlag = $fields.ContainsKey('workspace') -and $fields['workspace'].kind -ceq 'bool' -and [bool]$fields['workspace'].value
    if (-not $workspaceFlag) { return $Dependency }
    if ($null -eq $WorkspaceManifest -or -not $WorkspaceManifest.workspace_dependencies.ContainsKey([string]$Dependency.alias)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: inherited dependency has no verified workspace declaration'
    }
    $merged = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($key in $WorkspaceManifest.workspace_dependencies[[string]$Dependency.alias].Keys) { $merged.Add([string]$key, $WorkspaceManifest.workspace_dependencies[[string]$Dependency.alias][$key]) }
    foreach ($key in $fields.Keys) {
        if ($key -ceq 'workspace') { continue }
        if ($key -cin @('features', 'optional', 'default-features')) { continue }
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: workspace-inherited dependency overrides a source/version field'
    }
    return [PSCustomObject]@{ alias = $Dependency.alias; kind = $Dependency.kind; target = $Dependency.target; fields = $merged }
}

function Assert-D32BoundedDiagnosticDependencyFields {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields)
    $allowed = @('version', 'package', 'path', 'git', 'rev', 'branch', 'tag', 'registry', 'optional', 'default-features', 'features', 'workspace')
    foreach ($key in $Fields.Keys) {
        if ($allowed -cnotcontains [string]$key) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency manifest uses an unsupported field that may alter package selection or source identity' }
        $value = $Fields[$key]
        switch ([string]$key) {
            { $_ -in @('version', 'package', 'path', 'git', 'rev', 'branch', 'tag', 'registry') } {
                if ($null -eq $value -or [string]$value.kind -cne 'string' -or [String]::IsNullOrWhiteSpace([string]$value.value)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source/version dependency field is not a nonempty literal string' }
                break
            }
            { $_ -in @('optional', 'default-features', 'workspace') } {
                if ($null -eq $value -or [string]$value.kind -cne 'bool') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency activation field is not a literal boolean' }
                if ([string]$key -ceq 'workspace' -and -not [bool]$value.value) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: workspace inheritance must be explicitly true when present' }
                break
            }
            'features' {
                if ($null -eq $value -or [string]$value.kind -cne 'array' -or $value.value -isnot [Array]) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency features are not a bounded string array' }
                break
            }
        }
    }
    $sourceSelectors = 0
    foreach ($key in @('path', 'git', 'registry')) { if ($Fields.ContainsKey($key)) { $sourceSelectors++ } }
    if ($sourceSelectors -gt 1 -or ($Fields.ContainsKey('rev') -and -not $Fields.ContainsKey('git')) -or
        (($Fields.ContainsKey('branch') -or $Fields.ContainsKey('tag')) -and -not $Fields.ContainsKey('git')) -or
        ($Fields.ContainsKey('branch') -and $Fields.ContainsKey('tag'))) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency has ambiguous or unsupported source selectors'
    }
}

function Get-D32BoundedDiagnosticDependencyExpectedSource {
    param([Parameter(Mandatory = $true)][object]$Dependency, [Parameter(Mandatory = $true)][object]$RootManifest,
        [Parameter(Mandatory = $true)][object]$ParentPackage)
    $fields = $Dependency.fields; Assert-D32BoundedDiagnosticDependencyFields -Fields $fields
    $packageName = if ($fields.ContainsKey('package')) { [string]$fields['package'].value } else { [string]$Dependency.alias }
    if ($fields.ContainsKey('path')) {
        if ([string]$ParentPackage.source_kind -ceq 'workspace') { return [PSCustomObject]@{ name = $packageName; source_kind = 'workspace'; source = $null; path = [string]$fields['path'].value; path_base = 'DEPENDENCY_PARENT_MANIFEST' } }
        if ([string]$ParentPackage.source_kind -ceq 'git') { return [PSCustomObject]@{ name = $packageName; source_kind = 'git'; source = [string]$ParentPackage.source; path = [string]$fields['path'].value; path_base = 'DEPENDENCY_PARENT_MANIFEST' } }
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: path dependency from a registry package is outside the approved current source mapping'
    }
    if ($fields.ContainsKey('git')) {
        if (-not $fields.ContainsKey('rev') -or [string]$fields['rev'].value -cnotmatch '^[0-9a-f]{40}$' -or $fields.ContainsKey('branch') -or $fields.ContainsKey('tag')) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: Git dependency must use one exact full-commit rev and no floating selector' }
        $url = [string]$fields['git'].value
        if ($url.Contains('?') -or $url.Contains('#') -or $url -match '[@\s]') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: Git dependency URL has query, fragment, credentials, or whitespace outside the finite form' }
        $source = 'git+' + $url + '?rev=' + [string]$fields['rev'].value + '#' + [string]$fields['rev'].value
        return [PSCustomObject]@{ name = $packageName; source_kind = 'git'; source = $source }
    }
    if ($fields.ContainsKey('registry') -and [string]$fields['registry'].value -cne 'crates-io') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: non-crates.io registry dependency is outside the fixed source domain' }
    $patch = $null
    foreach ($patchAlias in $RootManifest.patches.Keys) {
        $patchFields = $RootManifest.patches[$patchAlias]
        $patchedName = if ($patchFields.ContainsKey('package')) { [string]$patchFields['package'].value } else { [string]$patchAlias }
        if ($patchedName -ceq $packageName) { if ($null -ne $patch) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: ambiguous root crates.io patch target' }; $patch = $patchFields }
    }
    if ($null -ne $patch) {
        Assert-D32BoundedDiagnosticDependencyFields -Fields $patch
        if ($patch.ContainsKey('path')) { return [PSCustomObject]@{ name = $packageName; source_kind = 'workspace'; source = $null; path = [string]$patch['path'].value; path_base = 'SELECTED_WORKSPACE_PATCH_MANIFEST' } }
        if ($patch.ContainsKey('git') -and $patch.ContainsKey('rev')) {
            if ([string]$patch['rev'].value -cnotmatch '^[0-9a-f]{40}$' -or $patch.ContainsKey('branch') -or $patch.ContainsKey('tag') -or
                [string]$patch['git'].value -match '[@\s?#]') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: root patch Git source is not one exact full-commit immutable URL' }
            $source = 'git+' + [string]$patch['git'].value + '?rev=' + [string]$patch['rev'].value + '#' + [string]$patch['rev'].value
            return [PSCustomObject]@{ name = $packageName; source_kind = 'git'; source = $source }
        }
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: unsupported root patch declaration'
    }
    return [PSCustomObject]@{ name = $packageName; source_kind = 'registry'; source = 'registry+https://github.com/rust-lang/crates.io-index' }
}

function Test-D32BoundedDiagnosticPathDependencyBinding {
    param([Parameter(Mandatory = $true)][object]$ParentPackage, [Parameter(Mandatory = $true)][object]$ParentManifest,
        [Parameter(Mandatory = $true)][object]$TargetPackage, [Parameter(Mandatory = $true)][object]$TargetManifest, [Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathRooted($Path) -or $Path.Contains(':') -or $Path.Contains('\') -or $Path.Contains("`0")) { return $false }
    if ([string]$ParentPackage.source_kind -ceq 'workspace') {
        if ([string]$TargetPackage.source_kind -cne 'workspace') { return $false }
    }
    elseif ([string]$ParentPackage.source_kind -ceq 'git') {
        if ([string]$TargetPackage.source_kind -cne 'git' -or [string]$TargetPackage.source -cne [string]$ParentPackage.source) { return $false }
    }
    else { return $false }
    $parentDirectory = [IO.Path]::GetDirectoryName(([string]$ParentManifest.source_path).Replace('/', '\'))
    if ($null -eq $parentDirectory) { $parentDirectory = '' }
    $sourceRoot = 'C:\d32\graph-source-root'
    $targetDirectory = [IO.Path]::GetFullPath((Join-Path $sourceRoot (Join-Path $parentDirectory $Path.Replace('/', '\'))))
    $relativeDirectory = [IO.Path]::GetRelativePath($sourceRoot, $targetDirectory).Replace('\', '/')
    if ($relativeDirectory -match '(^/|^[A-Za-z]:|(^|/)\.\.(?:/|$)|\x00)') { return $false }
    $expectedManifestPath = if ([String]::IsNullOrEmpty($relativeDirectory)) { 'Cargo.toml' } else { $relativeDirectory + '/Cargo.toml' }
    return [StringComparer]::Ordinal.Equals([string]$TargetManifest.source_path, $expectedManifestPath)
}

function Complete-D32BoundedDiagnosticManifestCatalog {
    param([Parameter(Mandatory = $true)][object]$Plan, [Parameter(Mandatory = $true)][object[]]$Candidates)
    if ($Candidates.Count -gt 4096) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: candidate manifest count exceeds its fixed 4096-entry bound' }
    $lockedPackageById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($lockedPackage in $Plan.locked_packages) {
        if (-not $lockedPackageById.TryAdd([string]$lockedPackage.package_id, $lockedPackage)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source-plan package identity is duplicated before manifest mapping'
        }
    }
    $parsed = [System.Collections.Generic.List[object]]::new()
    $bySourcePath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $candidateBytes = [Int64]0
    foreach ($candidate in $Candidates) {
        if ([string]$candidate.source_kind -cnotin @('workspace', 'registry', 'git') -or
            [string]$candidate.source_path -notmatch '^[A-Za-z0-9_./-]+/Cargo\.toml$|^Cargo\.toml$' -or
            [string]$candidate.content_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$candidate.content -isnot [string]) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: current source manifest candidate is not exact, bounded, or checksum-bound'
        }
        foreach ($segment in ([string]$candidate.source_path).Split('/')) {
            if ([String]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source manifest candidate path has an empty, dot, or traversal segment' }
        }
        $candidateSize = [Int64][Text.Encoding]::UTF8.GetByteCount([string]$candidate.content)
        if ($candidateSize -gt 1048576) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source manifest exceeds the 1 MiB content ceiling' }
        $candidateBytes += $candidateSize
        if ($candidateBytes -gt 67108864L) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: combined source-manifest candidate bytes exceed the 64 MiB managed buffer bound' }
        $actualSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes([string]$candidate.content))).ToLowerInvariant()
        if ($actualSha -cne [string]$candidate.content_sha256) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: manifest bytes differ from their archive/tree/file content digest' }
        if (-not [String]::IsNullOrEmpty([string]$candidate.package_id)) {
            if (-not $lockedPackageById.ContainsKey([string]$candidate.package_id)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: manifest candidate package ID is absent from the exact lock catalog' }
            $boundPackage = $lockedPackageById[[string]$candidate.package_id]
            $expectedCandidateSource = if ($null -eq $boundPackage.source) { 'workspace' } else { [string]$boundPackage.source }
            $actualCandidateSource = if ($candidate.source_kind -ceq 'workspace') { 'workspace' } else { [string]$candidate.source }
            if ([string]$candidate.source_kind -cne [string]$boundPackage.source_kind -or
                [string]$actualCandidateSource -cne [string]$expectedCandidateSource) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: explicit manifest package ID is cross-bound to another locked source kind or identity'
            }
        }
        elseif ($candidate.source_kind -ceq 'workspace' -and $null -ne $candidate.source) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: workspace manifest candidate unexpectedly names an external source identity'
        }
        $groupSource = if ($candidate.source_kind -ceq 'workspace') { 'workspace' } else { [string]$candidate.source }
        if ($candidate.source_kind -ceq 'registry' -and ($groupSource -cne 'registry+https://github.com/rust-lang/crates.io-index' -or [String]::IsNullOrEmpty([string]$candidate.package_id))) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: registry manifest candidate has a non-approved source or lacks its exact lock package binding' }
        if ($candidate.source_kind -ceq 'git' -and -not ($Plan.git_sources | Where-Object { [string]$_.source -ceq $groupSource })) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: Git manifest candidate is not from an exact lock-derived Git source' }
        $groupIdentity = if ($candidate.source_kind -ceq 'registry') { $groupSource + [char]0 + [string]$candidate.package_id } else { $groupSource }
        $key = $candidate.source_kind + [char]0 + $groupIdentity + [char]0 + [string]$candidate.source_path
        if ($bySourcePath.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: duplicate manifest path within one verified source identity' }
        $model = ConvertFrom-D32BoundedDiagnosticCargoManifest -Text ([string]$candidate.content) -SourcePath ([string]$candidate.source_path)
        $entry = [PSCustomObject]@{ source_kind = [string]$candidate.source_kind; source = $groupSource; group_identity = $groupIdentity; source_path = [string]$candidate.source_path; content_sha256 = [string]$candidate.content_sha256; explicit_package_id = [string]$candidate.package_id; model = $model }
        $parsed.Add($entry); $bySourcePath.Add($key, $entry)
    }
    foreach ($entry in $parsed) {
        $model = $entry.model
        if ([String]::IsNullOrEmpty([string]$model.package_name)) { continue }
        $manifestDirectory = [IO.Path]::GetDirectoryName([string]$entry.source_path.Replace('/', '\'))
        if ($null -eq $manifestDirectory) { $manifestDirectory = '' }
        $workspaceManifest = $null
        if (-not [String]::IsNullOrWhiteSpace([string]$model.workspace_root_path)) {
            $targetDir = [IO.Path]::GetFullPath((Join-Path ('C:\d32\manifest-root') (Join-Path $manifestDirectory ([string]$model.workspace_root_path))))
            $relativeDir = [IO.Path]::GetRelativePath('C:\d32\manifest-root', $targetDir).Replace('\', '/')
            if ($relativeDir -match '(^|/)\.\.(?:/|$)' -or [IO.Path]::IsPathRooted($relativeDir)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: explicit Cargo workspace path escapes its verified source root' }
            $workspacePath = if ([String]::IsNullOrEmpty($relativeDir)) { 'Cargo.toml' } else { $relativeDir + '/Cargo.toml' }
            $workspaceKey = $entry.source_kind + [char]0 + [string]$entry.group_identity + [char]0 + $workspacePath
            if (-not $bySourcePath.ContainsKey($workspaceKey) -or -not [bool]$bySourcePath[$workspaceKey].model.is_workspace_root) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: explicit package workspace manifest is absent from verified current source content' }
            $workspaceManifest = $bySourcePath[$workspaceKey].model
        }
        else {
            if ([bool]$model.is_workspace_root) { $workspaceManifest = $model }
            $ancestor = $manifestDirectory
            while ($null -eq $workspaceManifest -and -not [String]::IsNullOrEmpty($ancestor)) {
                $workspacePath = $ancestor.Replace('\', '/') + '/Cargo.toml'
                $workspaceKey = $entry.source_kind + [char]0 + [string]$entry.group_identity + [char]0 + $workspacePath
                if ($bySourcePath.ContainsKey($workspaceKey) -and [bool]$bySourcePath[$workspaceKey].model.is_workspace_root) { $workspaceManifest = $bySourcePath[$workspaceKey].model; break }
                $separator = $ancestor.LastIndexOf('\'); if ($separator -lt 0) { $ancestor = '' } elseif ($separator -eq 0) { $ancestor = '' } else { $ancestor = $ancestor.Substring(0, $separator) }
            }
        }
        if ($model.package_version_workspace) {
            if ($null -eq $workspaceManifest -or -not $workspaceManifest.workspace_package.ContainsKey('version') -or [string]$workspaceManifest.workspace_package['version'].kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: inherited package version lacks a verified workspace.package.version' }
            $model.package_version = [string]$workspaceManifest.workspace_package['version'].value
        }
        if ($null -ne $workspaceManifest) { $model | Add-Member -NotePropertyName workspace_manifest -NotePropertyValue $workspaceManifest -Force }
    }
    $catalog = [System.Collections.Generic.List[object]]::new()
    foreach ($package in $Plan.locked_packages) {
        $matches = @($parsed | Where-Object {
            $entry = $_
            if ([string]$entry.model.package_name -cne [string]$package.name -or [string]$entry.model.package_version -cne [string]$package.version) { return $false }
            if (-not [String]::IsNullOrEmpty([string]$entry.explicit_package_id)) { return [string]$entry.explicit_package_id -ceq [string]$package.package_id }
            if ([string]$package.source_kind -cne [string]$entry.source_kind) { return $false }
            if ([string]$package.source_kind -ceq 'workspace') { return $true }
            return [string]$package.source -ceq [string]$entry.source
        })
        if ($matches.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: multiple verified current manifests match one locked package identity' }
        if ($matches.Count -eq 1) {
            $entry = $matches[0]
            $catalog.Add([PSCustomObject]@{ package_id = [string]$package.package_id; source_kind = [string]$entry.source_kind; source_identity = [string]$entry.source; source_path = [string]$entry.source_path; content_sha256 = [string]$entry.content_sha256; model = $entry.model })
        }
    }
    return [PSCustomObject]@{ entries = @($catalog.ToArray()); verified_candidate_manifest_count = [Int64]$parsed.Count }
}

function Resolve-D32BoundedDiagnosticLockedDependencyGraph {
    param([Parameter(Mandatory = $true)][object]$Plan, [Parameter(Mandatory = $true)][object[]]$ManifestCatalog,
        [string]$RootManifestPath = 'vita-agent/Cargo.toml')
    if ([string]$Plan.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2' -or [int]$Plan.schema_version -ne 2 -or
        [string]$Plan.semantic_scope -cne 'FULL_LOCK_AUDIT_CATALOG_PLUS_SELECTED_REACHABLE_CONSERVATIVE_SUPERSET' -or
        [string]$Plan.host_triple -cne 'x86_64-pc-windows-msvc' -or [string]$Plan.target_triple -cne 'x86_64-pc-windows-msvc' -or
        $Plan.locked_packages -isnot [Array] -or $Plan.lock_dependency_edges -isnot [Array] -or $ManifestCatalog -isnot [Array] -or
        [string]$RootManifestPath -cne 'vita-agent/Cargo.toml' -or $Plan.locked_packages.Count -le 0 -or $Plan.locked_packages.Count -gt 2048 -or
        $Plan.lock_dependency_edges.Count -gt 65536 -or [string]$Plan.lock_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Plan.lock_dependency_edges_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source-plan version, fixed target, root selection, or manifest catalog is invalid' }
    $packageById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($package in $Plan.locked_packages) { if (-not $packageById.TryAdd([string]$package.package_id, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: lock catalog package identity is duplicated' } }
    $edgeByParent = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $edgeIdentitySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($edge in $Plan.lock_dependency_edges) {
        if (-not $packageById.ContainsKey([string]$edge.parent_package_id) -or -not $packageById.ContainsKey([string]$edge.target_package_id)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: lock edge references an unknown catalog package' }
        if ([String]::IsNullOrWhiteSpace([string]$edge.lock_spec) -or -not $edgeIdentitySet.Add(([string]$edge.parent_package_id + [char]0 + [string]$edge.lock_spec))) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: duplicate or empty lock edge identity cannot support exhaustive reconciliation' }
        if (-not $edgeByParent.ContainsKey([string]$edge.parent_package_id)) { $edgeByParent.Add([string]$edge.parent_package_id, [System.Collections.Generic.List[object]]::new()) }
        $edgeByParent[[string]$edge.parent_package_id].Add($edge)
    }
    $manifestById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $manifestRecordById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($manifest in $ManifestCatalog) {
        $manifestPackage = $null
        if ($null -ne $manifest -and $packageById.ContainsKey([string]$manifest.package_id)) { $manifestPackage = $packageById[[string]$manifest.package_id] }
        $expectedSourceIdentity = if ($null -eq $manifestPackage -or $null -eq $manifestPackage.source) { 'workspace' } else { [string]$manifestPackage.source }
        if ([string]$manifest.package_id -cnotmatch '^.+\|(?:workspace|registry|git)\|.+$' -or [string]$manifest.content_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $null -eq $manifest.model -or
            $null -eq $manifestPackage -or [string]$manifest.source_kind -cne [string]$manifestPackage.source_kind -or
            [string]$manifest.source_identity -cne $expectedSourceIdentity -or
            -not $manifestById.TryAdd([string]$manifest.package_id, $manifest.model)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source-verified manifest record is malformed or duplicated' }
        $manifestRecordById.Add([string]$manifest.package_id, $manifest)
    }
    $rootModels = @($ManifestCatalog | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.source_path, $RootManifestPath) })
    if ($rootModels.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: selected manifest path does not identify exactly one caller-pinned current root' }
    $rootModel = $rootModels[0].model
    if ([string]$rootModel.package_name -cne 'digital-life-vita-agent' -or $null -eq $rootModel.package_version -or
        -not $rootModel.features.ContainsKey('d32-a-test-helper')) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: selected current manifest package/feature identity differs from the fixed command' }
    $rootIds = @($Plan.locked_packages | Where-Object { $_.source_kind -ceq 'workspace' -and $_.name -ceq [string]$rootModel.package_name -and $_.version -ceq [string]$rootModel.package_version } | ForEach-Object { [string]$_.package_id })
    if ($rootIds.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: current selected package does not resolve to exactly one local lock package' }
    if (-not $manifestById.ContainsKey($rootIds[0])) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: selected root package lacks its exact current source-manifest pin' }
    $selectedRootWorkspace = if ($null -ne $rootModel.PSObject.Properties['workspace_manifest']) { $rootModel.workspace_manifest } else { $rootModel }

    $queue = [System.Collections.Generic.Queue[string]]::new(); $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $parentPath = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($rootId in $rootIds) { $queue.Enqueue($rootId); $parentPath[$rootId] = $rootId }
    $graphEdges = [System.Collections.Generic.List[object]]::new(); $dependencyDecisions = [System.Collections.Generic.List[object]]::new(); $unknownCfgCount = 0L; $inactiveCfgCount = 0L
    while ($queue.Count -gt 0) {
        $parentId = $queue.Dequeue(); if (-not $visited.Add($parentId)) { continue }
        if (-not $manifestById.ContainsKey($parentId)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: reachable locked package lacks a verified current source manifest; absence cannot prove exclusion' }
        $parentPackage = $packageById[$parentId]; $manifestModel = $manifestById[$parentId]
        if ([string]$manifestModel.package_name -cne [string]$parentPackage.name -or [string]$manifestModel.package_version -cne [string]$parentPackage.version) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: verified package manifest identity differs from its exact Cargo.lock package record' }
        $workspaceModel = if ($null -ne $manifestModel.PSObject.Properties['workspace_manifest']) { $manifestModel.workspace_manifest } elseif ([bool]$manifestModel.is_workspace_root) { $manifestModel } else { $null }
        $lockEdges = if ($edgeByParent.ContainsKey($parentId)) { @($edgeByParent[$parentId].ToArray()) } else { @() }
        $matchedLockEdges = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $dependencyRows = [System.Collections.Generic.List[object]]::new()
        foreach ($rawDependency in $manifestModel.dependencies) {
            $dependency = Resolve-D32BoundedDiagnosticWorkspaceDependency -Dependency $rawDependency -WorkspaceManifest $workspaceModel
            Assert-D32BoundedDiagnosticDependencyFields -Fields $dependency.fields
            $nonRootDev = ([string]$dependency.kind -ceq 'dev-dependencies' -and $parentId -cne $rootIds[0])
            $condition = if ([String]::IsNullOrEmpty([string]$dependency.target)) { [PSCustomObject]@{ value = $true; proven = $true; witness = 'unconditional dependency' } } else { Get-D32BoundedDiagnosticTargetPredicate -Expression ([string]$dependency.target) -TargetTriple ([string]$Plan.target_triple) }
            $resolvedTargets = [System.Collections.Generic.List[object]]::new()
            foreach ($edge in $lockEdges) {
                $targetPackage = $packageById[[string]$edge.target_package_id]
                $declarationFields = $dependency.fields
                $targetName = if ($declarationFields.ContainsKey('package')) { [string]$declarationFields['package'].value } else { [string]$dependency.alias }
                if ([string]$targetPackage.name -cne $targetName) { continue }
                $versionField = if ($declarationFields.ContainsKey('version')) { $declarationFields['version'] } else { $null }
                if ($null -ne $versionField -and [string]$versionField.kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency version is not a supported string' }
                $requirement = if ($null -eq $versionField) { '*' } else { [string]$versionField.value }
                if (-not (Test-D32BoundedDiagnosticVersionRequirement -Requirement $requirement -LockedVersion ([string]$targetPackage.version))) { continue }
                $expectedSource = Get-D32BoundedDiagnosticDependencyExpectedSource -Dependency $dependency -RootManifest $selectedRootWorkspace -ParentPackage $parentPackage
                if ([string]$targetPackage.source_kind -cne [string]$expectedSource.source_kind -or
                    (($null -eq $expectedSource.source) -ne ($null -eq $targetPackage.source)) -or
                    ($null -ne $expectedSource.source -and [string]$targetPackage.source -cne [string]$expectedSource.source)) { continue }
                if ($expectedSource.PSObject.Properties['path'] -and -not [String]::IsNullOrEmpty([string]$expectedSource.path)) {
                    if (-not $manifestById.ContainsKey([string]$targetPackage.package_id)) { continue }
                    $pathParentPackage = $parentPackage; $pathParentManifest = $manifestModel
                    if ([string]$expectedSource.path_base -ceq 'SELECTED_WORKSPACE_PATCH_MANIFEST') { $pathParentPackage = $packageById[$rootIds[0]]; $pathParentManifest = $selectedRootWorkspace }
                    if (-not (Test-D32BoundedDiagnosticPathDependencyBinding -ParentPackage $pathParentPackage -ParentManifest $pathParentManifest -TargetPackage $targetPackage -TargetManifest $manifestById[[string]$targetPackage.package_id] -Path ([string]$expectedSource.path))) { continue }
                }
                $resolvedTargets.Add($edge)
            }
            if ($nonRootDev) {
                if ($resolvedTargets.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: non-root development dependency maps ambiguously to lock edges' }
                if ($resolvedTargets.Count -eq 1) { [void]$matchedLockEdges.Add(([string]$parentId + [char]0 + [string]$resolvedTargets[0].lock_spec)) }
                $dependencyRows.Add([PSCustomObject]@{ parent_package_id = $parentId; alias = [string]$dependency.alias; kind = [string]$dependency.kind; target = [string]$dependency.target; disposition = 'EXCLUDED_NONROOT_DEV_DEPENDENCY'; predicate_proven = [bool]$condition.proven; predicate_witness = 'Cargo does not build dependency-package dev-dependencies for selected root all-targets command'; target_package_id = if ($resolvedTargets.Count -eq 1) { [string]$resolvedTargets[0].target_package_id } else { $null }; lock_specs = @($resolvedTargets | ForEach-Object { [string]$_.lock_spec }); optional_included = ($dependency.fields.ContainsKey('optional') -and [bool]$dependency.fields['optional'].value) })
                continue
            }
            if (-not [bool]$condition.value) {
                $inactiveCfgCount++
                if ($resolvedTargets.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: inactive target dependency maps ambiguously to lock edges' }
                if ($resolvedTargets.Count -eq 1) { [void]$matchedLockEdges.Add(([string]$parentId + [char]0 + [string]$resolvedTargets[0].lock_spec)) }
                $dependencyRows.Add([PSCustomObject]@{ parent_package_id = $parentId; alias = [string]$dependency.alias; kind = [string]$dependency.kind; target = [string]$dependency.target; disposition = 'EXCLUDED_TARGET_PREDICATE_PROVEN_FALSE'; predicate_proven = [bool]$condition.proven; predicate_witness = [string]$condition.witness; target_package_id = if ($resolvedTargets.Count -eq 1) { [string]$resolvedTargets[0].target_package_id } else { $null }; lock_specs = @($resolvedTargets | ForEach-Object { [string]$_.lock_spec }); optional_included = ($dependency.fields.ContainsKey('optional') -and [bool]$dependency.fields['optional'].value) })
                continue
            }
            if (-not $condition.proven) { $unknownCfgCount++ }
            if ($resolvedTargets.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: active/conservatively included manifest dependency does not resolve to exactly one exact lock edge' }
            $edge = $resolvedTargets[0]; [void]$matchedLockEdges.Add(([string]$parentId + [char]0 + [string]$edge.lock_spec))
            $isOptional = ($dependency.fields.ContainsKey('optional') -and [bool]$dependency.fields['optional'].value)
            $graphEdges.Add([PSCustomObject]@{ parent_package_id = $parentId; target_package_id = [string]$edge.target_package_id; lock_spec = [string]$edge.lock_spec; dependency_alias = [string]$dependency.alias; kind = [string]$dependency.kind; target_predicate = [string]$dependency.target; predicate_proven = [bool]$condition.proven; predicate_witness = [string]$condition.witness; optional_included = $isOptional })
            $dependencyRows.Add([PSCustomObject]@{ parent_package_id = $parentId; alias = [string]$dependency.alias; kind = [string]$dependency.kind; target = [string]$dependency.target; disposition = if ($condition.proven) { 'INCLUDED' } else { 'INCLUDED_UNKNOWN_CFG' }; predicate_proven = [bool]$condition.proven; predicate_witness = [string]$condition.witness; target_package_id = [string]$edge.target_package_id; lock_specs = @([string]$edge.lock_spec); optional_included = $isOptional })
            if (-not $visited.Contains([string]$edge.target_package_id)) { $queue.Enqueue([string]$edge.target_package_id); if (-not $parentPath.ContainsKey([string]$edge.target_package_id)) { $parentPath[[string]$edge.target_package_id] = $parentId } }
        }
        foreach ($edge in $lockEdges) {
            if (-not $matchedLockEdges.Contains(([string]$parentId + [char]0 + [string]$edge.lock_spec))) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: reachable parent has an unexplained lock dependency edge not reconciled with its complete manifest declarations'
            }
        }
        foreach ($decision in $dependencyRows) { $dependencyDecisions.Add($decision) }
    }
    $rootSetCanonical = [string]::Join("`n", [string[]]$rootIds)
    $includedIds = [string[]]@($visited); [Array]::Sort($includedIds, [StringComparer]::Ordinal)
    $excludedIds = [string[]]@(@($Plan.locked_packages | Where-Object { -not $visited.Contains([string]$_.package_id) } | ForEach-Object { [string]$_.package_id })); [Array]::Sort($excludedIds, [StringComparer]::Ordinal)
    $edgeCanon = [System.Collections.Generic.List[string]]::new(); $manifestCanon = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $includedIds) { $row = $manifestRecordById[$id]; $manifestCanon.Add($id + "`t" + [string]$row.source_kind + "`t" + [string]$row.source_identity + "`t" + [string]$row.source_path + "`t" + [string]$row.content_sha256) }
    $manifestCanon.Sort([StringComparer]::Ordinal)
    foreach ($edge in $graphEdges) { $edgeCanon.Add(([string]$edge.parent_package_id + "`t" + [string]$edge.target_package_id + "`t" + [string]$edge.dependency_alias + "`t" + [string]$edge.kind + "`t" + [string]$edge.target_predicate + "`t" + [string]$edge.predicate_witness + "`t" + [string]$edge.lock_spec)) }
    $edgeCanon.Sort([StringComparer]::Ordinal); $utf8 = [Text.UTF8Encoding]::new($false)
    $decisionCanon = [System.Collections.Generic.List[string]]::new()
    foreach ($decision in $dependencyDecisions) { $decisionCanon.Add(([string]$decision.parent_package_id + "`t" + [string]$decision.alias + "`t" + [string]$decision.kind + "`t" + [string]$decision.target + "`t" + [string]$decision.disposition + "`t" + [string]$decision.predicate_witness + "`t" + [string]$decision.target_package_id + "`t" + [string]::Join(',', [string[]]$decision.lock_specs) + "`t" + [string]$decision.predicate_proven + "`t" + [string]$decision.optional_included)) }
    $decisionCanon.Sort([StringComparer]::Ordinal)
    $closedSetSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(($includedIds -join "`n") + "`n"))).ToLowerInvariant()
    $manifestSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(($manifestCanon -join "`n") + "`n"))).ToLowerInvariant()
    $graphSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes(([string]$Plan.lock_sha256 + "`n" + [string]$Plan.lock_dependency_edges_sha256 + "`n" + $rootSetCanonical + "`n" + ($edgeCanon -join "`n") + "`n" + ($decisionCanon -join "`n") + "`n" + $closedSetSha + "`n" + $manifestSha + "`n")))).ToLowerInvariant()
    $classifications = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $includedIds) {
        $row = $manifestRecordById[$id]
        $path = [System.Collections.Generic.List[string]]::new(); $cursor = $id; $guard = 0
        while ($cursor -cne $rootIds[0]) {
            if (-not $parentPath.ContainsKey($cursor) -or $guard -ge $includedIds.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: included package lacks a bounded root reachability witness path' }
            $cursor = [string]$parentPath[$cursor]; $path.Add($cursor); $guard++
        }
        $path.Reverse(); $path.Add($id)
        $classifications.Add([PSCustomObject]@{ package_id = $id; classification = 'INCLUDED'; source_kind = [string]$packageById[$id].source_kind; source_identity = [string]$row.source_identity; manifest_path = [string]$row.source_path; manifest_sha256 = [string]$row.content_sha256; witness_kind = 'ROOT_PATH_IN_VERIFIED_DECLARATION_GRAPH'; witness_root_path = @($path.ToArray()); closed_reachability_sha256 = $closedSetSha })
    }
    foreach ($id in $excludedIds) { $classifications.Add([PSCustomObject]@{ package_id = $id; classification = 'EXCLUDED_WITH_WITNESS'; source_kind = [string]$packageById[$id].source_kind; source_identity = if ($null -eq $packageById[$id].source) { 'workspace' } else { [string]$packageById[$id].source }; witness_kind = 'CLOSED_REACHABILITY_CUT'; unreachable_from_roots = @($rootIds); complete_reachable_parent_count = [Int64]$visited.Count; complete_reachable_dependency_decision_count = [Int64]$dependencyDecisions.Count; no_active_incoming_edge_from_included = $true; closed_reachability_sha256 = $closedSetSha }) }
    return [PSCustomObject][ordered]@{
        schema_version = 2; record_type = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_GRAPH_PROOF_V2'; gate_authority = 'NONE'; formal_gate_usable = $false
        status = 'CURRENT_LOCKED_SOURCE_GRAPH_VERIFIED_FOR_DIAGNOSTIC_ONLY'; semantic_scope = [string]$Plan.semantic_scope
        lock_sha256 = [string]$Plan.lock_sha256; lock_dependency_edges_sha256 = [string]$Plan.lock_dependency_edges_sha256; graph_sha256 = $graphSha
        root_manifest_path = $RootManifestPath; selected_root_ids = @($rootIds); root_selection_rule = 'EXACT_PACKAGE_NAMED_BY_MANIFEST_PATH_DEFAULT_FEATURES_PLUS_D32_A_TEST_HELPER_NO_WORKSPACE_EXPANSION'
        host_triple = [string]$Plan.host_triple; target_triple = [string]$Plan.target_triple; target_resolution_scope = 'ONE_FIXED_X86_64_PC_WINDOWS_MSVC_HOST_AND_TARGET'
        locked_package_count = [Int64]$packageById.Count; included_package_ids = @($includedIds); included_package_count = [Int64]$includedIds.Count
        excluded_package_count = [Int64]$excludedIds.Count; classification_count = [Int64]$classifications.Count; classifications = @($classifications.ToArray())
        included_edges = @($graphEdges.ToArray()); dependency_decisions = @($dependencyDecisions.ToArray()); inactive_target_edge_count = $inactiveCfgCount; unknown_cfg_conservative_include_count = $unknownCfgCount; included_manifest_set_sha256 = $manifestSha
        feature_rule = 'ALL_OPTIONAL_AND_FEATURE_ACTIVATION_EDGES_INCLUDED_UNLESS_TARGET_PREDICATE_PROVEN_FALSE'
        root_dev_dependency_rule = 'INCLUDED_FOR_SELECTED_PACKAGE_ALL_TARGETS'; nonroot_dev_dependency_rule = 'EXCLUDED_NOT_BUILT_FOR_DEPENDENCY_PACKAGE'
        build_proc_macro_rule = 'INCLUDED_HOST_EQUALS_TARGET'; closed_reachability_set_sha256 = $closedSetSha; source_plan_version = 2
        selected_target_mode = 'ALL_TARGETS_FOR_SELECTED_PACKAGE_ONLY'; selected_crate_kinds = @('lib', 'bin', 'example', 'test', 'bench', 'custom-build', 'proc-macro')
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
        [int]$MaximumMembers = 10000,
        [Diagnostics.Stopwatch]$ProofTimer
    )
    if ($null -ne $ProofTimer -and (-not $ProofTimer.IsRunning -or $ProofTimer.ElapsedMilliseconds -ge 300000)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer is absent, stopped, or expired before archive parsing'
    }
    if ($CompressedBytes.Length -le 0 -or [Int64]$CompressedBytes.Length -gt $MaximumCompressedBytes -or
        $ExpectedArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedPackageRoot -cnotmatch '^[A-Za-z0-9_-]+-[0-9A-Za-z.+_-]+$' -or
        $MaximumExpandedBytes -le 0 -or $MaximumMemberBytes -le 0 -or $MaximumMembers -le 0 -or $MaximumMembers -gt 10000) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive bytes, expected package identity, or finite parser bound is invalid'
    }
    $archiveSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($CompressedBytes)).ToLowerInvariant()
    if ($null -ne $ProofTimer -and $ProofTimer.ElapsedMilliseconds -ge 300000) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer expired while hashing the compressed archive'
    }
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
        $manifestText = $null; $manifestContentSha256 = $null
        $ended = $false
        while (-not $ended) {
            if ($null -ne $ProofTimer -and $ProofTimer.ElapsedMilliseconds -ge 300000) {
                throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer expired during USTAR inventory'
            }
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
                    if ($null -ne $ProofTimer -and $ProofTimer.ElapsedMilliseconds -ge 300000) {
                        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer expired while consuming trailing archive data'
                    }
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
                    $captureManifest = ($relative -ceq 'Cargo.toml')
                    if ($captureManifest -and $size -gt 1048576L) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: crate Cargo.toml exceeds its 1 MiB dependency-graph parser bound' }
                    $manifestBuffer = if ($captureManifest) { [IO.MemoryStream]::new([int]$size) } else { $null }
                    try {
                        $remaining = [Int64]$size
                        $buffer = [byte[]]::new(65536)
                        while ($remaining -gt 0) {
                            if ($null -ne $ProofTimer -and $ProofTimer.ElapsedMilliseconds -ge 300000) {
                                throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer expired while hashing a USTAR member'
                            }
                            $take = [int][Math]::Min([Int64]$buffer.Length, $remaining)
                            $read = $gzip.Read($buffer, 0, $take)
                            if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: truncated file member data' }
                            $hash.AppendData($buffer, 0, $read)
                            if ($captureManifest) { $manifestBuffer.Write($buffer, 0, $read) }
                            $remaining -= $read
                        }
                        $fileSha = [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
                        if ($captureManifest) {
                            $manifestBytes = $manifestBuffer.ToArray()
                            try { $manifestText = [Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes) }
                            catch { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: Cargo.toml is not strict UTF-8' }
                            $manifestContentSha256 = $fileSha
                        }
                    }
                    finally { $hash.Dispose(); if ($null -ne $manifestBuffer) { $manifestBuffer.Dispose() } }
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
                    if ($null -ne $ProofTimer -and $ProofTimer.ElapsedMilliseconds -ge 300000) {
                        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer expired while consuming unsupported USTAR member data'
                    }
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
        if ($null -eq $manifestText -or [string]$manifestContentSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: checksum-matched crate archive lacks one regular root Cargo.toml' }
        $paths = [string[]]@($expected.Keys)
        [Array]::Sort($paths, [StringComparer]::Ordinal)
        $rows = [System.Collections.Generic.List[object]]::new()
        $canonical = [System.Collections.Generic.List[string]]::new()
        foreach ($path in $paths) {
            if ($null -ne $ProofTimer -and $ProofTimer.ElapsedMilliseconds -ge 300000) {
                throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer expired while finalizing the USTAR inventory'
            }
            $entry = $expected[$path]
            $rows.Add($entry)
            $canonical.Add(([string]$entry.kind + "`t" + [string]$entry.path + "`t" + [Int64]$entry.bytes + "`t" + [string]$entry.sha256))
        }
        $inventorySha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($canonical -join "`n") + "`n"))).ToLowerInvariant()
        return [PSCustomObject][ordered]@{ archive_sha256 = $archiveSha; expanded_bytes = $expandedBytes; member_count = [Int64]$rawMemberCount; entries = @($rows.ToArray()); inventory_sha256 = $inventorySha; manifest_text = $manifestText; manifest_sha256 = $manifestContentSha256 }
    }
    finally {
        if ($null -ne $gzip) { $gzip.Dispose() }
        $compressed.Dispose()
    }
}
