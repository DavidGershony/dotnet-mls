namespace DotnetMls.Codec;

/// <summary>
/// Deserialization reader for TLS-style binary encoding.
/// Reads fixed-width big-endian integers, raw byte slices,
/// length-prefixed opaque vectors, and sub-readers for structured vectors.
/// </summary>
public sealed class TlsReader
{
    /// <summary>
    /// Default maximum size (in bytes) for any single length-prefixed element.
    /// 4 MB is generous for MLS messages (large ratchet trees in big groups)
    /// while blocking multi-GB allocations from malformed length prefixes.
    /// </summary>
    public const int DefaultMaxElementSize = 4 * 1024 * 1024;

    private readonly byte[] _data;
    private readonly int _offset;
    private readonly int _length;
    private readonly int _maxElementSize;
    private int _position;

    /// <summary>
    /// Initializes a new <see cref="TlsReader"/> over the entire byte array.
    /// </summary>
    /// <param name="data">The data to read from.</param>
    /// <param name="maxElementSize">Maximum allowed size for any single length-prefixed read.
    /// Defaults to <see cref="DefaultMaxElementSize"/> (4 MB).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    public TlsReader(byte[] data, int maxElementSize = DefaultMaxElementSize)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
        _offset = 0;
        _length = data.Length;
        _maxElementSize = maxElementSize;
        _position = 0;
    }

    /// <summary>
    /// Initializes a new <see cref="TlsReader"/> over a sub-range of a byte array.
    /// </summary>
    /// <param name="data">The data to read from.</param>
    /// <param name="offset">The starting offset within the array.</param>
    /// <param name="length">The number of bytes available for reading.</param>
    /// <param name="maxElementSize">Maximum allowed size for any single length-prefixed read.
    /// Defaults to <see cref="DefaultMaxElementSize"/> (4 MB).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> or <paramref name="length"/> are out of range.</exception>
    public TlsReader(byte[] data, int offset, int length, int maxElementSize = DefaultMaxElementSize)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (offset < 0 || offset > data.Length)
            throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset is out of range.");
        if (length < 0 || offset + length > data.Length)
            throw new ArgumentOutOfRangeException(nameof(length), length, "Length is out of range.");

        _data = data;
        _offset = offset;
        _length = length;
        _maxElementSize = maxElementSize;
        _position = 0;
    }

    /// <summary>
    /// Gets the current read position within the reader's window.
    /// </summary>
    public int Position => _position;

    /// <summary>
    /// Gets the number of bytes remaining to be read.
    /// </summary>
    public int Remaining => _length - _position;

    /// <summary>
    /// Gets a value indicating whether all bytes have been consumed.
    /// </summary>
    public bool IsEmpty => _position >= _length;

    // ---- Fixed-width integer reads (big-endian) ----

    /// <summary>
    /// Reads a single unsigned byte.
    /// </summary>
    /// <returns>The byte value.</returns>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data.</exception>
    public byte ReadUint8()
    {
        EnsureAvailable(1);
        return _data[_offset + _position++];
    }

    /// <summary>
    /// Reads a 16-bit unsigned integer in big-endian byte order.
    /// </summary>
    /// <returns>The decoded value.</returns>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data.</exception>
    public ushort ReadUint16()
    {
        EnsureAvailable(2);
        int idx = _offset + _position;
        _position += 2;
        return (ushort)((_data[idx] << 8) | _data[idx + 1]);
    }

    /// <summary>
    /// Reads a 24-bit unsigned integer in big-endian byte order (3 bytes).
    /// </summary>
    /// <returns>The decoded value as a <see cref="uint"/>.</returns>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data.</exception>
    public uint ReadUint24()
    {
        EnsureAvailable(3);
        int idx = _offset + _position;
        _position += 3;
        return (uint)((_data[idx] << 16) | (_data[idx + 1] << 8) | _data[idx + 2]);
    }

    /// <summary>
    /// Reads a 32-bit unsigned integer in big-endian byte order.
    /// </summary>
    /// <returns>The decoded value.</returns>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data.</exception>
    public uint ReadUint32()
    {
        EnsureAvailable(4);
        int idx = _offset + _position;
        _position += 4;
        return (uint)((_data[idx] << 24) | (_data[idx + 1] << 16) | (_data[idx + 2] << 8) | _data[idx + 3]);
    }

    /// <summary>
    /// Reads a 64-bit unsigned integer in big-endian byte order.
    /// </summary>
    /// <returns>The decoded value.</returns>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data.</exception>
    public ulong ReadUint64()
    {
        EnsureAvailable(8);
        int idx = _offset + _position;
        _position += 8;
        return ((ulong)_data[idx] << 56)
             | ((ulong)_data[idx + 1] << 48)
             | ((ulong)_data[idx + 2] << 40)
             | ((ulong)_data[idx + 3] << 32)
             | ((ulong)_data[idx + 4] << 24)
             | ((ulong)_data[idx + 5] << 16)
             | ((ulong)_data[idx + 6] << 8)
             | _data[idx + 7];
    }

    // ---- Raw byte reads ----

    /// <summary>
    /// Reads the specified number of raw bytes and returns them as a new array.
    /// </summary>
    /// <param name="count">The number of bytes to read.</param>
    /// <returns>A new byte array containing the read bytes.</returns>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data.</exception>
    public byte[] ReadBytes(int count)
    {
        if (count < 0)
            throw new TlsDecodingException($"Cannot read a negative number of bytes ({count}).");
        if (count > _maxElementSize)
            throw new TlsDecodingException(
                $"Element size {count} exceeds maximum allowed size of {_maxElementSize} bytes.");

        EnsureAvailable(count);
        var result = new byte[count];
        Array.Copy(_data, _offset + _position, result, 0, count);
        _position += count;
        return result;
    }

    // ---- Opaque vector reads (length-prefixed byte arrays) ----

    /// <summary>
    /// Reads an opaque vector with a 1-byte (uint8) length prefix.
    /// </summary>
    /// <returns>A new byte array containing the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public byte[] ReadOpaque8()
    {
        int length = ReadUint8();
        return ReadBytes(length);
    }

    /// <summary>
    /// Reads an opaque vector with a 2-byte (uint16) length prefix.
    /// </summary>
    /// <returns>A new byte array containing the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public byte[] ReadOpaque16()
    {
        int length = ReadUint16();
        return ReadBytes(length);
    }

    /// <summary>
    /// Reads an opaque vector with a 3-byte (uint24) length prefix.
    /// </summary>
    /// <returns>A new byte array containing the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public byte[] ReadOpaque24()
    {
        int length = (int)ReadUint24();
        return ReadBytes(length);
    }

    /// <summary>
    /// Reads an opaque vector with a 4-byte (uint32) length prefix.
    /// </summary>
    /// <returns>A new byte array containing the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public byte[] ReadOpaque32()
    {
        long length = ReadUint32();
        if (length > int.MaxValue)
            throw new TlsDecodingException($"Opaque32 length ({length}) exceeds maximum array size.");

        return ReadBytes((int)length);
    }

    // ---- Sub-reader vector reads ----

    /// <summary>
    /// Reads a vector with a 1-byte (uint8) length prefix and returns a new <see cref="TlsReader"/>
    /// positioned over the vector's payload. Useful for parsing complex structures within a vector.
    /// </summary>
    /// <returns>A new <see cref="TlsReader"/> over the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public TlsReader ReadVector8()
    {
        int length = ReadUint8();
        return ReadSubReader(length);
    }

    /// <summary>
    /// Reads a vector with a 2-byte (uint16) length prefix and returns a new <see cref="TlsReader"/>
    /// positioned over the vector's payload.
    /// </summary>
    /// <returns>A new <see cref="TlsReader"/> over the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public TlsReader ReadVector16()
    {
        int length = ReadUint16();
        return ReadSubReader(length);
    }

    /// <summary>
    /// Reads a vector with a 3-byte (uint24) length prefix and returns a new <see cref="TlsReader"/>
    /// positioned over the vector's payload.
    /// </summary>
    /// <returns>A new <see cref="TlsReader"/> over the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public TlsReader ReadVector24()
    {
        int length = (int)ReadUint24();
        return ReadSubReader(length);
    }

    /// <summary>
    /// Reads a vector with a 4-byte (uint32) length prefix and returns a new <see cref="TlsReader"/>
    /// positioned over the vector's payload.
    /// </summary>
    /// <returns>A new <see cref="TlsReader"/> over the vector payload.</returns>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public TlsReader ReadVector32()
    {
        long length = ReadUint32();
        if (length > int.MaxValue)
            throw new TlsDecodingException($"Vector32 length ({length}) exceeds maximum array size.");

        return ReadSubReader((int)length);
    }

    // ---- MLS variable-length integer (RFC 9420 Section 2, RFC 9000 Section 16) ----

    /// <summary>
    /// Reads an MLS variable-length integer used for &lt;V&gt; length prefixes.
    /// The two most significant bits of the first byte encode the length:
    /// 00 → 1 byte (6 usable bits, 0-63),
    /// 01 → 2 bytes (14 usable bits, 0-16383),
    /// 10 → 4 bytes (30 usable bits, 0-2^30).
    /// </summary>
    public int ReadVarIntLength()
    {
        EnsureAvailable(1);
        byte first = _data[_offset + _position];
        int prefix = (first >> 6) & 0x03;

        switch (prefix)
        {
            case 0:
                _position++;
                return first & 0x3F;
            case 1:
                EnsureAvailable(2);
                {
                    int idx = _offset + _position;
                    _position += 2;
                    return ((_data[idx] & 0x3F) << 8) | _data[idx + 1];
                }
            case 2:
                EnsureAvailable(4);
                {
                    int idx = _offset + _position;
                    _position += 4;
                    return ((_data[idx] & 0x3F) << 24) | (_data[idx + 1] << 16) | (_data[idx + 2] << 8) | _data[idx + 3];
                }
            default:
                throw new TlsDecodingException($"Invalid MLS VarInt prefix 0x{first:X2} (top 2 bits = 11 is reserved).");
        }
    }

    /// <summary>
    /// Reads an opaque vector with an MLS variable-length integer prefix (&lt;V&gt; encoding).
    /// </summary>
    public byte[] ReadOpaqueV()
    {
        int length = ReadVarIntLength();
        return ReadBytes(length);
    }

    /// <summary>
    /// Reads a vector with an MLS variable-length integer prefix and returns a sub-reader.
    /// </summary>
    public TlsReader ReadVectorV()
    {
        int length = ReadVarIntLength();
        return ReadSubReader(length);
    }

    // ---- Private helpers ----

    /// <summary>
    /// Ensures that the specified number of bytes are available for reading.
    /// </summary>
    /// <param name="count">The number of bytes required.</param>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data remaining.</exception>
    private void EnsureAvailable(int count)
    {
        if (_position + count > _length)
            throw new TlsDecodingException(
                $"Insufficient data: attempted to read {count} byte(s) at position {_position}, but only {_length - _position} byte(s) remain.");
    }

    /// <summary>
    /// Returns bytes from the internal buffer between the given start position and current position.
    /// Useful after parsing a variable-length struct to extract the consumed raw bytes.
    /// </summary>
    internal byte[] GetRange(int fromPosition)
    {
        int length = _position - fromPosition;
        var result = new byte[length];
        Array.Copy(_data, _offset + fromPosition, result, 0, length);
        return result;
    }

    /// <summary>
    /// Creates a sub-reader over the next <paramref name="length"/> bytes and advances the current position.
    /// </summary>
    /// <param name="length">The number of bytes for the sub-reader.</param>
    /// <returns>A new <see cref="TlsReader"/> over the sub-range.</returns>
    /// <exception cref="TlsDecodingException">Thrown when there is insufficient data.</exception>
    private TlsReader ReadSubReader(int length)
    {
        EnsureAvailable(length);
        var subReader = new TlsReader(_data, _offset + _position, length, _maxElementSize);
        _position += length;
        return subReader;
    }
}
