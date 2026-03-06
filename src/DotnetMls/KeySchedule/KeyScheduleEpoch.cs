using DotnetMls.Crypto;

namespace DotnetMls.KeySchedule;

/// <summary>
/// Epoch key schedule per RFC 9420 Section 8.
/// Derives all secrets for a single MLS epoch from the init secret,
/// commit secret, serialized group context, and optional PSK secret.
/// </summary>
public sealed class KeyScheduleEpoch
{
    // ---- Epoch secrets ----

    /// <summary>
    /// The init secret to be used as input for the next epoch's key schedule.
    /// </summary>
    public byte[] InitSecret { get; }

    /// <summary>
    /// Secret used to derive sender data encryption keys.
    /// </summary>
    public byte[] SenderDataSecret { get; }

    /// <summary>
    /// Secret used to derive the per-sender secret tree for message encryption.
    /// </summary>
    public byte[] EncryptionSecret { get; }

    /// <summary>
    /// Secret used to derive exported keying material via MLS exporters.
    /// </summary>
    public byte[] ExporterSecret { get; }

    /// <summary>
    /// An authenticator value available to group members for external verification.
    /// </summary>
    public byte[] EpochAuthenticator { get; }

    /// <summary>
    /// Secret used to derive the external HPKE key pair for external joins.
    /// </summary>
    public byte[] ExternalSecret { get; }

    /// <summary>
    /// Key used to compute the confirmation tag on Commit messages.
    /// </summary>
    public byte[] ConfirmationKey { get; }

    /// <summary>
    /// Key used to compute the membership tag on PublicMessage frames.
    /// </summary>
    public byte[] MembershipKey { get; }

    /// <summary>
    /// Pre-shared key for resumption, allowing epoch re-initialization.
    /// </summary>
    public byte[] ResumptionPsk { get; }

    /// <summary>
    /// The HPKE public key derived from <see cref="ExternalSecret"/> for external commits.
    /// </summary>
    public byte[] ExternalPub { get; }

    // ---- Intermediate values needed for Welcome messages ----

    /// <summary>
    /// The joiner secret, needed for encrypting Welcome messages to new joiners.
    /// </summary>
    public byte[] JoinerSecret { get; }

    /// <summary>
    /// The welcome secret, used to derive the key and nonce for GroupInfo encryption in Welcome.
    /// </summary>
    public byte[] WelcomeSecret { get; }

    /// <summary>
    /// AEAD key derived from <see cref="WelcomeSecret"/> for encrypting GroupInfo.
    /// </summary>
    public byte[] WelcomeKey { get; }

    /// <summary>
    /// AEAD nonce derived from <see cref="WelcomeSecret"/> for encrypting GroupInfo.
    /// </summary>
    public byte[] WelcomeNonce { get; }

    internal KeyScheduleEpoch(
        byte[] initSecret,
        byte[] senderDataSecret,
        byte[] encryptionSecret,
        byte[] exporterSecret,
        byte[] epochAuthenticator,
        byte[] externalSecret,
        byte[] confirmationKey,
        byte[] membershipKey,
        byte[] resumptionPsk,
        byte[] externalPub,
        byte[] joinerSecret,
        byte[] welcomeSecret,
        byte[] welcomeKey,
        byte[] welcomeNonce)
    {
        InitSecret = initSecret;
        SenderDataSecret = senderDataSecret;
        EncryptionSecret = encryptionSecret;
        ExporterSecret = exporterSecret;
        EpochAuthenticator = epochAuthenticator;
        ExternalSecret = externalSecret;
        ConfirmationKey = confirmationKey;
        MembershipKey = membershipKey;
        ResumptionPsk = resumptionPsk;
        ExternalPub = externalPub;
        JoinerSecret = joinerSecret;
        WelcomeSecret = welcomeSecret;
        WelcomeKey = welcomeKey;
        WelcomeNonce = welcomeNonce;
    }

    /// <summary>
    /// Creates the key schedule for an epoch. This handles both initial group creation
    /// and subsequent epoch transitions after a Commit.
    /// <para>
    /// Per RFC 9420 Section 8, the derivation is:
    /// <code>
    ///   extracted           = Extract(init_secret, commit_secret)
    ///   joiner_secret       = ExpandWithLabel(extracted, "joiner", GroupContext, Nh)
    ///   intermediate_secret = Extract(joiner_secret, psk_secret)
    ///   welcome_secret     = DeriveSecret(intermediate_secret, "welcome")
    ///   epoch_secret       = ExpandWithLabel(intermediate_secret, "epoch", GroupContext, Nh)
    /// </code>
    /// Then from epoch_secret all per-epoch secrets are derived using DeriveSecret.
    /// </para>
    /// </summary>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="initSecret">
    /// The init secret. For the first epoch this should be a random value of SecretSize bytes.
    /// For subsequent epochs this is the InitSecret from the previous epoch.
    /// </param>
    /// <param name="commitSecret">
    /// The commit secret from TreeKEM path processing. For initial group creation,
    /// pass an all-zero array of SecretSize bytes.
    /// </param>
    /// <param name="groupContext">
    /// The TLS-serialized GroupContext for this epoch.
    /// </param>
    /// <param name="pskSecret">
    /// The pre-shared key secret. If null or empty, defaults to Extract(zeros, zeros)
    /// per RFC 9420 Section 8.4.
    /// </param>
    /// <returns>A new <see cref="KeyScheduleEpoch"/> containing all derived secrets.</returns>
    public static KeyScheduleEpoch Create(
        ICipherSuite cs,
        byte[] initSecret,
        byte[] commitSecret,
        byte[] groupContext,
        byte[]? pskSecret = null)
    {
        var nh = cs.SecretSize;

        // Step 1: Derive the joiner secret per RFC 9420 §8:
        //   init_secret --> KDF.Extract <-- commit_secret
        //                      |
        //   ExpandWithLabel(., "joiner", GroupContext, Nh)
        //                      |
        //                joiner_secret
        var extracted = cs.Extract(initSecret, commitSecret);
        var joinerSecret = cs.ExpandWithLabel(extracted, "joiner", groupContext, nh);

        // Step 2: intermediate_secret = KDF.Extract(salt=joiner_secret, ikm=psk_secret)
        // psk_secret defaults to zeros(KDF.Nh) when no PSKs
        var effectivePskSecret = pskSecret ?? new byte[nh];
        if (effectivePskSecret.Length == 0) effectivePskSecret = new byte[nh];
        var intermediateSecret = cs.Extract(joinerSecret, effectivePskSecret);

        // Step 3: welcome_secret = DeriveSecret(intermediate_secret, "welcome")
        var welcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");

        // Step 4: epoch_secret = ExpandWithLabel(intermediate_secret, "epoch", GroupContext, Nh)
        var epochSecret = cs.ExpandWithLabel(intermediateSecret, "epoch", groupContext, nh);

        // Step 6: Derive all per-epoch secrets from epoch_secret
        // DeriveSecret(S, L) = ExpandWithLabel(S, L, "", Nh)
        var senderDataSecret = cs.DeriveSecret(epochSecret, "sender data");
        var encryptionSecret = cs.DeriveSecret(epochSecret, "encryption");
        var exporterSecret = cs.DeriveSecret(epochSecret, "exporter");
        var epochAuthenticator = cs.DeriveSecret(epochSecret, "authentication");
        var externalSecret = cs.DeriveSecret(epochSecret, "external");
        var confirmationKey = cs.DeriveSecret(epochSecret, "confirm");
        var membershipKey = cs.DeriveSecret(epochSecret, "membership");
        var resumptionPsk = cs.DeriveSecret(epochSecret, "resumption");
        var newInitSecret = cs.DeriveSecret(epochSecret, "init");

        // Step 7: Derive the external HPKE public key from external_secret
        // external_pub = DeriveKeyPair(external_secret).publicKey
        // DeriveKeyPair uses the HPKE KEM; we approximate by using the cipher suite's
        // HPKE key derivation. Per RFC 9420, DeriveKeyPair(ikm) produces a key pair
        // from the input keying material. We use ExpandWithLabel to derive a private key
        // and then compute the public key via the cipher suite.
        //
        // However, the ICipherSuite does not expose DeriveKeyPair directly.
        // We derive a seed and use GenerateHpkeKeyPair's deterministic equivalent.
        // For now, we store the external_secret and derive the key pair on demand.
        // The public key is obtained by treating external_secret as HPKE private key material
        // through the HPKE Encap/Decap mechanism.
        //
        // Per the spec, external_pub = KEM.DeriveKeyPair(external_secret).public_key
        // We'll store a placeholder and let the caller compute this if needed,
        // since ICipherSuite.GenerateHpkeKeyPair() is randomized, not deterministic from a seed.
        //
        // TODO: Add DeriveHpkeKeyPair(byte[] ikm) to ICipherSuite for deterministic key derivation.
        var externalPub = Array.Empty<byte>();

        // Step 8: Derive welcome key and nonce from welcome_secret
        // welcome_key = ExpandWithLabel(welcome_secret, "key", "", Nk)
        // welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", Nn)
        var welcomeKey = cs.ExpandWithLabel(welcomeSecret, "key", Array.Empty<byte>(), cs.AeadKeySize);
        var welcomeNonce = cs.ExpandWithLabel(welcomeSecret, "nonce", Array.Empty<byte>(), cs.AeadNonceSize);

        return new KeyScheduleEpoch(
            initSecret: newInitSecret,
            senderDataSecret: senderDataSecret,
            encryptionSecret: encryptionSecret,
            exporterSecret: exporterSecret,
            epochAuthenticator: epochAuthenticator,
            externalSecret: externalSecret,
            confirmationKey: confirmationKey,
            membershipKey: membershipKey,
            resumptionPsk: resumptionPsk,
            externalPub: externalPub,
            joinerSecret: joinerSecret,
            welcomeSecret: welcomeSecret,
            welcomeKey: welcomeKey,
            welcomeNonce: welcomeNonce);
    }

    /// <summary>
    /// Derives the key schedule for a new epoch after processing a Commit.
    /// This is equivalent to <see cref="Create"/> and is provided for readability
    /// at call sites where the init secret comes from a previous epoch.
    /// </summary>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="previousInitSecret">The init secret from the previous epoch.</param>
    /// <param name="commitSecret">The commit secret from TreeKEM path processing.</param>
    /// <param name="groupContext">The TLS-serialized GroupContext for the new epoch.</param>
    /// <param name="pskSecret">The pre-shared key secret, or null for the default.</param>
    /// <returns>A new <see cref="KeyScheduleEpoch"/> containing all derived secrets.</returns>
    public static KeyScheduleEpoch FromCommit(
        ICipherSuite cs,
        byte[] previousInitSecret,
        byte[] commitSecret,
        byte[] groupContext,
        byte[]? pskSecret = null)
    {
        return Create(cs, previousInitSecret, commitSecret, groupContext, pskSecret);
    }

    /// <summary>
    /// Creates the key schedule for an epoch directly from a joiner secret.
    /// This is used during Welcome processing, where the joiner secret is provided
    /// directly in the GroupSecrets rather than being derived from init_secret and commit_secret.
    /// <para>
    /// Per RFC 9420 Section 8, from the joiner_secret:
    /// <code>
    ///   intermediate_secret = Extract(joiner_secret, psk_secret)
    ///   welcome_secret     = DeriveSecret(intermediate_secret, "welcome")
    ///   epoch_secret       = ExpandWithLabel(intermediate_secret, "epoch", GroupContext, Nh)
    /// </code>
    /// Then from epoch_secret all per-epoch secrets are derived using DeriveSecret.
    /// </para>
    /// </summary>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="joinerSecret">The joiner secret from the Welcome message's GroupSecrets.</param>
    /// <param name="groupContext">The TLS-serialized GroupContext for this epoch.</param>
    /// <param name="pskSecret">The pre-shared key secret, or null for the default.</param>
    /// <returns>A new <see cref="KeyScheduleEpoch"/> containing all derived secrets.</returns>
    public static KeyScheduleEpoch FromJoinerSecret(
        ICipherSuite cs,
        byte[] joinerSecret,
        byte[] groupContext,
        byte[]? pskSecret = null)
    {
        var nh = cs.SecretSize;

        // Step 1: intermediate_secret = KDF.Extract(salt=joiner_secret, ikm=psk_secret)
        var effectivePskSecret = pskSecret ?? new byte[nh];
        if (effectivePskSecret.Length == 0) effectivePskSecret = new byte[nh];
        var intermediateSecret = cs.Extract(joinerSecret, effectivePskSecret);

        // Step 2: welcome_secret = DeriveSecret(intermediate_secret, "welcome")
        var welcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");

        // Step 3: epoch_secret = ExpandWithLabel(intermediate_secret, "epoch", GroupContext, Nh)
        var epochSecret = cs.ExpandWithLabel(intermediateSecret, "epoch", groupContext, nh);

        // Step 5: Derive all per-epoch secrets from epoch_secret
        var senderDataSecret = cs.DeriveSecret(epochSecret, "sender data");
        var encryptionSecret = cs.DeriveSecret(epochSecret, "encryption");
        var exporterSecret = cs.DeriveSecret(epochSecret, "exporter");
        var epochAuthenticator = cs.DeriveSecret(epochSecret, "authentication");
        var externalSecret = cs.DeriveSecret(epochSecret, "external");
        var confirmationKey = cs.DeriveSecret(epochSecret, "confirm");
        var membershipKey = cs.DeriveSecret(epochSecret, "membership");
        var resumptionPsk = cs.DeriveSecret(epochSecret, "resumption");
        var newInitSecret = cs.DeriveSecret(epochSecret, "init");

        // Step 6: external_pub placeholder (same as Create)
        var externalPub = Array.Empty<byte>();

        // Step 7: Derive welcome key and nonce from welcome_secret
        var welcomeKey = cs.ExpandWithLabel(welcomeSecret, "key", Array.Empty<byte>(), cs.AeadKeySize);
        var welcomeNonce = cs.ExpandWithLabel(welcomeSecret, "nonce", Array.Empty<byte>(), cs.AeadNonceSize);

        return new KeyScheduleEpoch(
            initSecret: newInitSecret,
            senderDataSecret: senderDataSecret,
            encryptionSecret: encryptionSecret,
            exporterSecret: exporterSecret,
            epochAuthenticator: epochAuthenticator,
            externalSecret: externalSecret,
            confirmationKey: confirmationKey,
            membershipKey: membershipKey,
            resumptionPsk: resumptionPsk,
            externalPub: externalPub,
            joinerSecret: joinerSecret,
            welcomeSecret: welcomeSecret,
            welcomeKey: welcomeKey,
            welcomeNonce: welcomeNonce);
    }

    /// <summary>
    /// Computes the confirmation tag for a Commit message.
    /// <para>
    /// Per RFC 9420 Section 8.1:
    ///   confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
    /// </para>
    /// </summary>
    /// <param name="cs">The cipher suite.</param>
    /// <param name="confirmedTranscriptHash">The confirmed transcript hash for this epoch.</param>
    /// <returns>The confirmation tag bytes.</returns>
    public byte[] ComputeConfirmationTag(ICipherSuite cs, byte[] confirmedTranscriptHash)
    {
        return cs.Mac(ConfirmationKey, confirmedTranscriptHash);
    }

    /// <summary>
    /// Computes the membership tag for a PublicMessage.
    /// <para>
    /// Per RFC 9420 Section 6.1:
    ///   membership_tag = MAC(membership_key, AuthenticatedContentTBM)
    /// </para>
    /// </summary>
    /// <param name="cs">The cipher suite.</param>
    /// <param name="authenticatedContentTbm">
    /// The TLS-serialized AuthenticatedContentTBM (content to be MACed).
    /// </param>
    /// <returns>The membership tag bytes.</returns>
    public byte[] ComputeMembershipTag(ICipherSuite cs, byte[] authenticatedContentTbm)
    {
        return cs.Mac(MembershipKey, authenticatedContentTbm);
    }

    /// <summary>
    /// Derives an exported secret using the MLS exporter mechanism.
    /// <para>
    /// Per RFC 9420 Section 8.5:
    ///   MLS-Exporter(label, context, length) =
    ///     ExpandWithLabel(DeriveSecret(exporter_secret, label), "exported", Hash(context), length)
    /// </para>
    /// </summary>
    /// <param name="cs">The cipher suite.</param>
    /// <param name="label">The exporter label.</param>
    /// <param name="context">The exporter context (will be hashed).</param>
    /// <param name="length">The desired output length in bytes.</param>
    /// <returns>The exported secret bytes.</returns>
    public byte[] DeriveExporterSecret(ICipherSuite cs, string label, byte[] context, int length)
    {
        // derived_secret = DeriveSecret(exporter_secret, label)
        var derivedSecret = cs.DeriveSecret(ExporterSecret, label);

        // Hash the context
        var hashedContext = cs.Hash(context);

        // result = ExpandWithLabel(derived_secret, "exported", Hash(context), length)
        return cs.ExpandWithLabel(derivedSecret, "exported", hashedContext, length);
    }
}
