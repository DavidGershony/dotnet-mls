namespace DotnetMls.Codec;

/// <summary>
/// QUIC variable-length integer encoding and decoding (RFC 9000 Section 16).
/// Values are encoded in 1, 2, 4, or 8 bytes with a 2-bit prefix indicating the length:
/// <list type="bullet">
///   <item><description>1 byte  (prefix 00): values 0..63</description></item>
///   <item><description>2 bytes (prefix 01): values 0..16383</description></item>
///   <item><description>4 bytes (prefix 10): values 0..1073741823</description></item>
///   <item><description>8 bytes (prefix 11): values 0..4611686018427387903</description></item>
/// </list>
/// </summary>
public static class QuicVarint
{
    /// <summary>
    /// The maximum value representable by a QUIC variable-length integer: 2^62 - 1.
    /// </summary>
    public const ulong MaxValue = 4_611_686_018_427_387_903; // (1UL << 62) - 1

    private const ulong OneByteMax = 63;                     // 2^6 - 1
    private const ulong TwoByteMax = 16_383;                 // 2^14 - 1
    private const ulong FourByteMax = 1_073_741_823;         // 2^30 - 1

    /// <summary>
    /// Writes a QUIC variable-length integer to the given <see cref="TlsWriter"/>.
    /// </summary>
    /// <param name="writer">The writer to write to.</param>
    /// <param name="value">The value to encode. Must be at most <see cref="MaxValue"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="writer"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="value"/> exceeds <see cref="MaxValue"/>.</exception>
    public static void Write(TlsWriter writer, ulong value)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if (value > MaxValue)
            throw new ArgumentOutOfRangeException(nameof(value), value, $"QUIC varint value exceeds maximum ({MaxValue}).");

        if (value <= OneByteMax)
        {
            // 1 byte: 00xxxxxx
            writer.WriteUint8((byte)value);
        }
        else if (value <= TwoByteMax)
        {
            // 2 bytes: 01xxxxxx xxxxxxxx
            writer.WriteUint16((ushort)(0x4000 | value));
        }
        else if (value <= FourByteMax)
        {
            // 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            writer.WriteUint32(0x8000_0000 | (uint)value);
        }
        else
        {
            // 8 bytes: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            writer.WriteUint64(0xC000_0000_0000_0000 | value);
        }
    }

    /// <summary>
    /// Reads a QUIC variable-length integer from the given <see cref="TlsReader"/>.
    /// </summary>
    /// <param name="reader">The reader to read from.</param>
    /// <returns>The decoded value.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="reader"/> is null.</exception>
    /// <exception cref="TlsDecodingException">Thrown when the data is malformed or truncated.</exception>
    public static ulong Read(TlsReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        byte firstByte = reader.ReadUint8();
        int prefix = firstByte >> 6;

        switch (prefix)
        {
            case 0:
                // 1 byte: 00xxxxxx
                return (ulong)(firstByte & 0x3F);

            case 1:
            {
                // 2 bytes: 01xxxxxx xxxxxxxx
                byte secondByte = reader.ReadUint8();
                return (ulong)(((firstByte & 0x3F) << 8) | secondByte);
            }

            case 2:
            {
                // 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
                byte b1 = reader.ReadUint8();
                byte b2 = reader.ReadUint8();
                byte b3 = reader.ReadUint8();
                return (uint)(((firstByte & 0x3F) << 24) | (b1 << 16) | (b2 << 8) | b3);
            }

            case 3:
            {
                // 8 bytes: 11xxxxxx xxxxxxxx ... xxxxxxxx
                byte b1 = reader.ReadUint8();
                byte b2 = reader.ReadUint8();
                byte b3 = reader.ReadUint8();
                byte b4 = reader.ReadUint8();
                byte b5 = reader.ReadUint8();
                byte b6 = reader.ReadUint8();
                byte b7 = reader.ReadUint8();
                return ((ulong)(firstByte & 0x3F) << 56)
                     | ((ulong)b1 << 48)
                     | ((ulong)b2 << 40)
                     | ((ulong)b3 << 32)
                     | ((ulong)b4 << 24)
                     | ((ulong)b5 << 16)
                     | ((ulong)b6 << 8)
                     | b7;
            }

            default:
                // Unreachable: prefix is derived from 2 bits, so only 0-3 are possible.
                throw new TlsDecodingException($"Invalid QUIC varint prefix: {prefix}.");
        }
    }

    /// <summary>
    /// Returns the number of bytes required to encode the given value as a QUIC variable-length integer.
    /// </summary>
    /// <param name="value">The value to measure.</param>
    /// <returns>1, 2, 4, or 8.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="value"/> exceeds <see cref="MaxValue"/>.</exception>
    public static int EncodedLength(ulong value)
    {
        if (value <= OneByteMax)
            return 1;
        if (value <= TwoByteMax)
            return 2;
        if (value <= FourByteMax)
            return 4;
        if (value <= MaxValue)
            return 8;

        throw new ArgumentOutOfRangeException(nameof(value), value, $"QUIC varint value exceeds maximum ({MaxValue}).");
    }
}
