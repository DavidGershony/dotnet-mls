namespace DotnetMls.Codec;

/// <summary>
/// Serialization writer for TLS-style binary encoding.
/// Writes fixed-width big-endian integers, raw byte spans,
/// length-prefixed opaque vectors, and structured vectors.
/// Uses a <see cref="MemoryStream"/> internally.
/// </summary>
public sealed class TlsWriter : IDisposable
{
    private readonly MemoryStream _stream;

    /// <summary>
    /// Initializes a new <see cref="TlsWriter"/> with an empty buffer.
    /// </summary>
    public TlsWriter() => _stream = new MemoryStream();

    // ---- Fixed-width integer writes (big-endian) ----

    /// <summary>
    /// Writes a single unsigned byte.
    /// </summary>
    /// <param name="value">The byte value to write.</param>
    public void WriteUint8(byte value)
    {
        _stream.WriteByte(value);
    }

    /// <summary>
    /// Writes a 16-bit unsigned integer in big-endian byte order.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUint16(ushort value)
    {
        _stream.WriteByte((byte)(value >> 8));
        _stream.WriteByte((byte)value);
    }

    /// <summary>
    /// Writes a 24-bit unsigned integer in big-endian byte order (3 bytes).
    /// </summary>
    /// <param name="value">The value to write. Must fit within 24 bits (0..16777215).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="value"/> exceeds 24 bits.</exception>
    public void WriteUint24(uint value)
    {
        if (value > 0xFF_FFFF)
            throw new ArgumentOutOfRangeException(nameof(value), value, "Value exceeds 24-bit maximum (16777215).");

        _stream.WriteByte((byte)(value >> 16));
        _stream.WriteByte((byte)(value >> 8));
        _stream.WriteByte((byte)value);
    }

    /// <summary>
    /// Writes a 32-bit unsigned integer in big-endian byte order.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUint32(uint value)
    {
        _stream.WriteByte((byte)(value >> 24));
        _stream.WriteByte((byte)(value >> 16));
        _stream.WriteByte((byte)(value >> 8));
        _stream.WriteByte((byte)value);
    }

    /// <summary>
    /// Writes a 64-bit unsigned integer in big-endian byte order.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUint64(ulong value)
    {
        _stream.WriteByte((byte)(value >> 56));
        _stream.WriteByte((byte)(value >> 48));
        _stream.WriteByte((byte)(value >> 40));
        _stream.WriteByte((byte)(value >> 32));
        _stream.WriteByte((byte)(value >> 24));
        _stream.WriteByte((byte)(value >> 16));
        _stream.WriteByte((byte)(value >> 8));
        _stream.WriteByte((byte)value);
    }

    // ---- Raw byte writes ----

    /// <summary>
    /// Writes raw bytes without a length prefix.
    /// </summary>
    /// <param name="data">The bytes to write.</param>
    public void WriteBytes(ReadOnlySpan<byte> data)
    {
        _stream.Write(data);
    }

    // ---- Opaque vectors (length-prefixed byte spans) ----

    /// <summary>
    /// Writes an opaque vector with a 1-byte (uint8) length prefix.
    /// Maximum payload length is 255 bytes.
    /// </summary>
    /// <param name="data">The data to write.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="data"/> exceeds 255 bytes.</exception>
    public void WriteOpaque8(ReadOnlySpan<byte> data)
    {
        if (data.Length > byte.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(data), data.Length, "Opaque8 data exceeds uint8 maximum length (255).");

        WriteUint8((byte)data.Length);
        WriteBytes(data);
    }

    /// <summary>
    /// Writes an opaque vector with a 2-byte (uint16) length prefix.
    /// Maximum payload length is 65535 bytes.
    /// </summary>
    /// <param name="data">The data to write.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="data"/> exceeds 65535 bytes.</exception>
    public void WriteOpaque16(ReadOnlySpan<byte> data)
    {
        if (data.Length > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(data), data.Length, "Opaque16 data exceeds uint16 maximum length (65535).");

        WriteUint16((ushort)data.Length);
        WriteBytes(data);
    }

    /// <summary>
    /// Writes an opaque vector with a 3-byte (uint24) length prefix.
    /// Maximum payload length is 16777215 bytes.
    /// </summary>
    /// <param name="data">The data to write.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="data"/> exceeds 16777215 bytes.</exception>
    public void WriteOpaque24(ReadOnlySpan<byte> data)
    {
        if (data.Length > 0xFF_FFFF)
            throw new ArgumentOutOfRangeException(nameof(data), data.Length, "Opaque24 data exceeds uint24 maximum length (16777215).");

        WriteUint24((uint)data.Length);
        WriteBytes(data);
    }

    /// <summary>
    /// Writes an opaque vector with a 4-byte (uint32) length prefix.
    /// </summary>
    /// <param name="data">The data to write.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="data"/> length exceeds uint32 range.</exception>
    public void WriteOpaque32(ReadOnlySpan<byte> data)
    {
        if ((ulong)data.Length > uint.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(data), data.Length, "Opaque32 data exceeds uint32 maximum length.");

        WriteUint32((uint)data.Length);
        WriteBytes(data);
    }

    // ---- Structured vectors (length-prefixed serialized items) ----

    /// <summary>
    /// Writes a vector of TLS-serializable items with a 1-byte (uint8) length prefix.
    /// The <paramref name="writeItems"/> action serializes items into a temporary writer;
    /// the resulting bytes are then written with the length prefix.
    /// </summary>
    /// <param name="writeItems">An action that writes items to a temporary <see cref="TlsWriter"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the serialized content exceeds 255 bytes.</exception>
    public void WriteVector8(Action<TlsWriter> writeItems)
    {
        var content = SerializeItems(writeItems);
        WriteOpaque8(content);
    }

    /// <summary>
    /// Writes a vector of TLS-serializable items with a 2-byte (uint16) length prefix.
    /// </summary>
    /// <param name="writeItems">An action that writes items to a temporary <see cref="TlsWriter"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the serialized content exceeds 65535 bytes.</exception>
    public void WriteVector16(Action<TlsWriter> writeItems)
    {
        var content = SerializeItems(writeItems);
        WriteOpaque16(content);
    }

    /// <summary>
    /// Writes a vector of TLS-serializable items with a 3-byte (uint24) length prefix.
    /// </summary>
    /// <param name="writeItems">An action that writes items to a temporary <see cref="TlsWriter"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the serialized content exceeds 16777215 bytes.</exception>
    public void WriteVector24(Action<TlsWriter> writeItems)
    {
        var content = SerializeItems(writeItems);
        WriteOpaque24(content);
    }

    /// <summary>
    /// Writes a vector of TLS-serializable items with a 4-byte (uint32) length prefix.
    /// </summary>
    /// <param name="writeItems">An action that writes items to a temporary <see cref="TlsWriter"/>.</param>
    public void WriteVector32(Action<TlsWriter> writeItems)
    {
        var content = SerializeItems(writeItems);
        WriteOpaque32(content);
    }

    // ---- MLS variable-length integer (RFC 9420 Section 2, RFC 9000 Section 16) ----

    /// <summary>
    /// Writes a variable-length integer as used by MLS for &lt;V&gt; length prefixes.
    /// Uses the smallest encoding that fits the value:
    /// 0-63 → 1 byte (00xxxxxx), 64-16383 → 2 bytes (01xxxxxx),
    /// 16384-2^30 → 4 bytes (10xxxxxx).
    /// </summary>
    public void WriteVarIntLength(int length)
    {
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length), length, "VarInt length cannot be negative.");

        if (length <= 63)
        {
            WriteUint8((byte)length);
        }
        else if (length <= 16383)
        {
            WriteUint16((ushort)(0x4000 | length));
        }
        else if (length <= 1073741823)
        {
            WriteUint32(0x80000000u | (uint)length);
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "VarInt length exceeds maximum (2^30 - 1).");
        }
    }

    /// <summary>
    /// Writes an opaque vector with an MLS variable-length integer prefix (&lt;V&gt; encoding).
    /// </summary>
    public void WriteOpaqueV(ReadOnlySpan<byte> data)
    {
        WriteVarIntLength(data.Length);
        WriteBytes(data);
    }

    /// <summary>
    /// Writes a vector of TLS-serializable items with an MLS variable-length integer prefix.
    /// </summary>
    public void WriteVectorV(Action<TlsWriter> writeItems)
    {
        var content = SerializeItems(writeItems);
        WriteOpaqueV(content);
    }

    // ---- Output ----

    /// <summary>
    /// Returns the serialized content as a byte array.
    /// </summary>
    /// <returns>A new byte array containing all written data.</returns>
    public byte[] ToArray() => _stream.ToArray();

    /// <inheritdoc />
    public void Dispose() => _stream.Dispose();

    // ---- Private helpers ----

    /// <summary>
    /// Serializes items via a temporary writer and returns the resulting bytes.
    /// </summary>
    private static byte[] SerializeItems(Action<TlsWriter> writeItems)
    {
        using var tempWriter = new TlsWriter();
        writeItems(tempWriter);
        return tempWriter.ToArray();
    }
}
