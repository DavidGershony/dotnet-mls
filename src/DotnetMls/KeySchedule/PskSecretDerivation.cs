using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Types;

namespace DotnetMls.KeySchedule;

/// <summary>
/// Computes the PSK secret from a list of pre-shared keys per RFC 9420 Section 8.4.
///
/// The algorithm iteratively folds over all PSKs:
/// <code>
///   psk_secret_[0] = zeros(KDF.Nh)
///
///   For each PSK at index i (0-based):
///     psk_extracted  = KDF.Extract(salt = zeros(KDF.Nh), ikm = psk_[i])
///     psk_input      = ExpandWithLabel(psk_extracted, "derived psk", PSKLabel_[i], KDF.Nh)
///     psk_secret_[i] = KDF.Extract(salt = psk_input, ikm = psk_secret_[i-1])
///
///   psk_secret = psk_secret_[n]
/// </code>
///
/// Where PSKLabel is a TLS-serialized struct containing the PreSharedKeyID,
/// the 0-based index of the PSK, and the total count of PSKs.
/// </summary>
public static class PskSecretDerivation
{
    /// <summary>
    /// A PSK together with its identifier, used as input to the PSK secret derivation.
    /// </summary>
    public class PskInput
    {
        /// <summary>
        /// The PreSharedKeyID that identifies this PSK (type, id bytes, nonce).
        /// </summary>
        public PreSharedKeyId Id { get; set; } = new();

        /// <summary>
        /// The actual PSK value (the raw key material).
        /// </summary>
        public byte[] PskValue { get; set; } = Array.Empty<byte>();
    }

    /// <summary>
    /// Computes the psk_secret from a list of PSKs per RFC 9420 Section 8.4.
    ///
    /// When the list is empty, returns zeros(KDF.Nh) — this matches the default
    /// psk_secret used when no PSKs are present in the key schedule.
    /// </summary>
    /// <param name="cs">The cipher suite providing KDF primitives.</param>
    /// <param name="psks">The ordered list of PSK inputs.</param>
    /// <returns>The computed psk_secret bytes of length KDF.Nh.</returns>
    public static byte[] ComputePskSecret(ICipherSuite cs, PskInput[] psks)
    {
        var nh = cs.SecretSize;
        var count = psks.Length;
        var zero = new byte[nh];

        // psk_secret_[0] = zeros(KDF.Nh)
        var pskSecret = new byte[nh];

        for (int i = 0; i < count; i++)
        {
            // Serialize PSKLabel for this position:
            //   struct {
            //       PreSharedKeyID id;
            //       uint16 index;
            //       uint16 count;
            //   } PSKLabel;
            var pskLabel = SerializePskLabel(psks[i].Id, (ushort)i, (ushort)count);

            // Step 1: psk_extracted = KDF.Extract(salt=zeros(Nh), ikm=psk[i])
            // This extracts the raw PSK into a pseudorandom key using a zero salt.
            var pskExtracted = cs.Extract(zero, psks[i].PskValue);

            // Step 2: psk_input = ExpandWithLabel(psk_extracted, "derived psk", PSKLabel, Nh)
            // This derives the labeled PSK input, binding it to the PSK's identity,
            // position (index), and the total count of PSKs in this derivation.
            var pskInput = cs.ExpandWithLabel(pskExtracted, "derived psk", pskLabel, nh);

            // Step 3: psk_secret[i] = KDF.Extract(salt=psk_input, ikm=psk_secret[i-1])
            // This folds the new PSK input into the running psk_secret accumulator.
            // Using psk_input as salt ensures each PSK contributes independently.
            pskSecret = cs.Extract(pskInput, pskSecret);
        }

        return pskSecret;
    }

    /// <summary>
    /// Serializes the PSKLabel struct used as context in ExpandWithLabel calls.
    ///
    /// Per RFC 9420 §8.4:
    /// <code>
    ///   struct {
    ///       PreSharedKeyID id;
    ///       uint16 index;
    ///       uint16 count;
    ///   } PSKLabel;
    /// </code>
    ///
    /// The PreSharedKeyID is serialized using its existing TLS serialization
    /// (which handles both External and Resumption PSK types), followed by
    /// the uint16 index and count fields.
    /// </summary>
    private static byte[] SerializePskLabel(PreSharedKeyId id, ushort index, ushort count)
    {
        return TlsCodec.Serialize(writer =>
        {
            id.WriteTo(writer);
            writer.WriteUint16(index);
            writer.WriteUint16(count);
        });
    }
}
