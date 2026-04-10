using DotnetMls.Codec;
using DotnetMls.Crypto;

namespace DotnetMls.KeySchedule;

/// <summary>
/// Maintains the confirmed and interim transcript hashes per RFC 9420 Section 8.2.
/// <para>
/// The transcript hash chain tracks the sequence of Commit messages in the group:
/// <code>
///   confirmed_transcript_hash[0] = "" (empty)
///   interim_transcript_hash[0]   = "" (empty)
///
///   confirmed_transcript_hash[epoch] = Hash(interim_transcript_hash[epoch-1] || content_tbs)
///   interim_transcript_hash[epoch]   = Hash(confirmed_transcript_hash[epoch] || confirmation_tag)
/// </code>
/// where <c>content_tbs</c> is the TLS-serialized FramedContentTBS for the Commit.
/// </para>
/// <para>
/// The confirmed transcript hash is included in the GroupContext, which in turn binds
/// the group state to the key schedule. The interim transcript hash carries forward
/// the confirmation tag so the next epoch's confirmed hash depends on it.
/// </para>
/// </summary>
public sealed class TranscriptHash
{
    private byte[] _confirmedTranscriptHash;
    private byte[] _interimTranscriptHash;

    /// <summary>
    /// The confirmed transcript hash up to the most recent Commit.
    /// This value is included in the GroupContext for the current epoch.
    /// </summary>
    public byte[] ConfirmedTranscriptHash => _confirmedTranscriptHash;

    /// <summary>
    /// The interim transcript hash, which incorporates the confirmation tag
    /// from the most recent Commit. This is used as input when computing
    /// the confirmed transcript hash for the next epoch.
    /// </summary>
    public byte[] InterimTranscriptHash => _interimTranscriptHash;

    /// <summary>
    /// Initializes a transcript hash for epoch 0 with empty hashes.
    /// Per RFC 9420 Section 8.2, both hashes start as the empty byte string.
    /// </summary>
    /// <param name="hashSize">
    /// The hash output size in bytes. Not used for initialization (hashes start empty)
    /// but retained for documentation clarity.
    /// </param>
    public TranscriptHash(int hashSize)
    {
        _confirmedTranscriptHash = Array.Empty<byte>();
        _interimTranscriptHash = Array.Empty<byte>();
    }

    /// <summary>
    /// Initializes a transcript hash with known confirmed and interim values.
    /// Used when restoring state from storage or when joining an existing group.
    /// </summary>
    /// <param name="confirmed">The confirmed transcript hash value.</param>
    /// <param name="interim">The interim transcript hash value.</param>
    public TranscriptHash(byte[] confirmed, byte[] interim)
    {
        _confirmedTranscriptHash = confirmed;
        _interimTranscriptHash = interim;
    }

    /// <summary>
    /// Updates the transcript hashes after processing a Commit.
    /// <para>
    /// Per RFC 9420 §8.2:
    /// <code>
    ///   confirmed_transcript_hash = Hash(interim_transcript_hash || ConfirmedTranscriptHashInput)
    ///   interim_transcript_hash   = Hash(confirmed_transcript_hash || InterimTranscriptHashInput)
    /// </code>
    /// where ConfirmedTranscriptHashInput = wire_format || content || signature,
    /// and InterimTranscriptHashInput = struct { MAC confirmation_tag; } with MAC = opaque&lt;V&gt;.
    /// </para>
    /// </summary>
    /// <param name="cs">The cipher suite providing the hash function.</param>
    /// <param name="confirmedTranscriptHashInput">
    /// The serialized ConfirmedTranscriptHashInput: wire_format || FramedContent || signature.
    /// </param>
    /// <param name="confirmationTag">
    /// The raw confirmation tag bytes from the Commit's FramedContentAuthData.
    /// Will be wrapped as opaque&lt;V&gt; per RFC 9420 §8.2.
    /// </param>
    public void Update(ICipherSuite cs, byte[] confirmedTranscriptHashInput, byte[] confirmationTag)
    {
        // confirmed_transcript_hash = Hash(interim_transcript_hash || ConfirmedTranscriptHashInput)
        var confirmedInput = Concat(_interimTranscriptHash, confirmedTranscriptHashInput);
        _confirmedTranscriptHash = cs.Hash(confirmedInput);

        // InterimTranscriptHashInput = struct { MAC confirmation_tag; }
        // MAC is opaque<V>, so we serialize with VarInt length prefix per TLS presentation language.
        byte[] interimTranscriptHashInput = TlsCodec.Serialize(w => w.WriteOpaqueV(confirmationTag));
        var interimInput = Concat(_confirmedTranscriptHash, interimTranscriptHashInput);
        _interimTranscriptHash = cs.Hash(interimInput);
    }

    /// <summary>
    /// Creates a deep copy of this transcript hash state.
    /// </summary>
    /// <returns>A new <see cref="TranscriptHash"/> with copies of the current hash values.</returns>
    public TranscriptHash Clone()
    {
        return new TranscriptHash(
            (byte[])_confirmedTranscriptHash.Clone(),
            (byte[])_interimTranscriptHash.Clone());
    }

    /// <summary>
    /// Concatenates two byte arrays.
    /// </summary>
    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}
