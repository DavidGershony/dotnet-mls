using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.KeySchedule;
using DotnetMls.Types;

namespace DotnetMls.Message;

/// <summary>
/// Creates and processes MLS framed messages (RFC 9420 Section 6).
/// <para>
/// This class implements the message framing layer, which is responsible for:
/// <list type="bullet">
///   <item>Building the FramedContentTBS (To Be Signed) structure</item>
///   <item>Building the AuthenticatedContentTBM (To Be MACed) structure for membership tags</item>
///   <item>Creating and verifying PublicMessage (plaintext) frames</item>
///   <item>Creating and decrypting PrivateMessage (encrypted) frames</item>
/// </list>
/// </para>
/// </summary>
public static class MessageFraming
{
    // --- FramedContentTBS (To Be Signed) ---
    // Per RFC 9420 Section 6.1, the content to be signed is:
    //
    // struct {
    //     ProtocolVersion version = mls10;
    //     WireFormat wire_format;
    //     FramedContent content;
    //     select (FramedContentTBS.content.sender.sender_type) {
    //         case member:
    //         case new_member_commit:
    //             GroupContext context;
    //         case external:
    //         case new_member_proposal:
    //             struct{};
    //     };
    // } FramedContentTBS;

    /// <summary>
    /// Builds the FramedContentTBS (To Be Signed) byte sequence for signing or verification.
    /// <para>
    /// For member and new_member_commit senders, the serialized group context is appended
    /// after the framed content. For external and new_member_proposal senders, no context
    /// is appended.
    /// </para>
    /// </summary>
    /// <param name="wireFormat">The wire format (public or private message).</param>
    /// <param name="content">The framed content to be signed.</param>
    /// <param name="serializedGroupContext">
    /// The TLS-serialized GroupContext. Required for member and new_member_commit senders;
    /// may be null for external and new_member_proposal senders.
    /// </param>
    /// <returns>The serialized FramedContentTBS bytes.</returns>
    public static byte[] BuildFramedContentTbs(
        WireFormat wireFormat,
        FramedContent content,
        byte[]? serializedGroupContext)
    {
        return TlsCodec.Serialize(writer =>
        {
            // ProtocolVersion version = mls10;
            writer.WriteUint16(ProtocolVersion.Mls10);

            // WireFormat wire_format;
            writer.WriteUint16((ushort)wireFormat);

            // FramedContent content;
            content.WriteTo(writer);

            // GroupContext context (only for member / new_member_commit senders)
            if (content.Sender.SenderType == SenderType.Member ||
                content.Sender.SenderType == SenderType.NewMemberCommit)
            {
                if (serializedGroupContext != null)
                    writer.WriteBytes(serializedGroupContext);
            }
        });
    }

    // --- AuthenticatedContentTBM (To Be MACed for membership tag) ---
    // Per RFC 9420 Section 6.1:
    //
    // struct {
    //     FramedContentTBS content_tbs;
    //     FramedContentAuthData auth;
    // } AuthenticatedContentTBM;

    /// <summary>
    /// Builds the AuthenticatedContentTBM (To Be MACed) byte sequence for membership
    /// tag computation or verification.
    /// </summary>
    /// <param name="framedContentTbs">The already-serialized FramedContentTBS bytes.</param>
    /// <param name="auth">The authentication data (signature and optional confirmation tag).</param>
    /// <param name="contentType">
    /// The content type, which determines whether the confirmation tag is included
    /// in the auth data serialization.
    /// </param>
    /// <returns>The serialized AuthenticatedContentTBM bytes.</returns>
    public static byte[] BuildAuthenticatedContentTbm(
        byte[] framedContentTbs,
        FramedContentAuthData auth,
        ContentType contentType)
    {
        return TlsCodec.Serialize(writer =>
        {
            writer.WriteBytes(framedContentTbs);
            auth.WriteTo(writer, contentType);
        });
    }

    // --- Sign a FramedContent to produce PublicMessage ---

    /// <summary>
    /// Creates a signed PublicMessage from a FramedContent.
    /// <para>
    /// Steps:
    /// <list type="number">
    ///   <item>Build the FramedContentTBS for the public wire format</item>
    ///   <item>Sign the TBS with the sender's private signing key</item>
    ///   <item>Construct the FramedContentAuthData (signature + optional confirmation tag)</item>
    ///   <item>Compute the membership tag for member senders using the membership key</item>
    /// </list>
    /// </para>
    /// </summary>
    /// <param name="content">The framed content to sign.</param>
    /// <param name="signingPrivateKey">The sender's private signing key.</param>
    /// <param name="serializedGroupContext">
    /// The TLS-serialized GroupContext for this epoch. Required for member senders.
    /// </param>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="confirmationTag">
    /// The confirmation tag. Non-null only when the content type is Commit.
    /// </param>
    /// <param name="membershipKey">
    /// The membership key from the epoch key schedule, used to compute the membership
    /// tag for member senders. May be null if the sender is not a member.
    /// </param>
    /// <returns>A fully formed PublicMessage ready for wire transmission.</returns>
    public static PublicMessage CreatePublicMessage(
        FramedContent content,
        byte[] signingPrivateKey,
        byte[]? serializedGroupContext,
        ICipherSuite cs,
        byte[]? confirmationTag,
        byte[]? membershipKey)
    {
        // 1. Build TBS
        byte[] tbs = BuildFramedContentTbs(WireFormat.MlsPublicMessage, content, serializedGroupContext);

        // 2. Sign
        byte[] signature = cs.SignWithLabel(signingPrivateKey, "FramedContentTBS", tbs);

        // 3. Build auth data
        var auth = new FramedContentAuthData(signature, confirmationTag);

        // 4. Compute membership tag if sender is a member
        byte[]? membershipTag = null;
        if (content.Sender.SenderType == SenderType.Member && membershipKey != null)
        {
            byte[] tbm = BuildAuthenticatedContentTbm(tbs, auth, content.ContentType);
            membershipTag = cs.Mac(membershipKey, tbm);
        }

        return new PublicMessage(content, auth, membershipTag);
    }

    // --- Verify a PublicMessage ---

    /// <summary>
    /// Verifies the signature and membership tag of a PublicMessage.
    /// <para>
    /// Steps:
    /// <list type="number">
    ///   <item>Rebuild the FramedContentTBS and verify the signature</item>
    ///   <item>For member senders, rebuild the AuthenticatedContentTBM and verify the membership tag</item>
    /// </list>
    /// </para>
    /// </summary>
    /// <param name="msg">The public message to verify.</param>
    /// <param name="signerPublicKey">The signer's public verification key.</param>
    /// <param name="serializedGroupContext">
    /// The TLS-serialized GroupContext for this epoch.
    /// </param>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="membershipKey">
    /// The membership key from the epoch key schedule, used to verify the membership tag.
    /// May be null if the sender is not a member.
    /// </param>
    /// <returns>True if both the signature and membership tag (when present) are valid.</returns>
    public static bool VerifyPublicMessage(
        PublicMessage msg,
        byte[] signerPublicKey,
        byte[]? serializedGroupContext,
        ICipherSuite cs,
        byte[]? membershipKey)
    {
        // 1. Build TBS
        byte[] tbs = BuildFramedContentTbs(WireFormat.MlsPublicMessage, msg.Content, serializedGroupContext);

        // 2. Verify signature
        if (!cs.VerifyWithLabel(signerPublicKey, "FramedContentTBS", tbs, msg.Auth.Signature))
            return false;

        // 3. Verify membership tag for member senders
        if (msg.Content.Sender.SenderType == SenderType.Member)
        {
            if (membershipKey == null || msg.MembershipTag == null || msg.MembershipTag.Length == 0)
                return false;

            byte[] tbm = BuildAuthenticatedContentTbm(tbs, msg.Auth, msg.Content.ContentType);
            if (!cs.VerifyMac(membershipKey, tbm, msg.MembershipTag))
                return false;
        }

        return true;
    }

    // --- Encrypt FramedContent to produce PrivateMessage ---
    // Per RFC 9420 Section 6.3:
    //
    // The ciphertext is created by encrypting:
    //   PrivateMessageContent = content || auth || padding
    //
    // With key/nonce from the secret tree for the sender's leaf and generation.
    //
    // The sender data (leaf_index, generation) is encrypted separately using
    // the sender_data_secret.

    /// <summary>
    /// Creates an encrypted PrivateMessage from a FramedContent.
    /// <para>
    /// Steps:
    /// <list type="number">
    ///   <item>Sign the content using the private wire format</item>
    ///   <item>Get encryption key/nonce from the secret tree for the sender's leaf</item>
    ///   <item>Build and encrypt PrivateMessageContent (content bytes + auth + padding)</item>
    ///   <item>Encrypt sender data (leaf_index, generation) using sender_data_secret</item>
    /// </list>
    /// </para>
    /// </summary>
    /// <param name="content">The framed content to encrypt.</param>
    /// <param name="signingPrivateKey">The sender's private signing key.</param>
    /// <param name="serializedGroupContext">The TLS-serialized GroupContext for this epoch.</param>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="secretTree">The secret tree for the current epoch.</param>
    /// <param name="senderDataSecret">The sender data secret from the epoch key schedule.</param>
    /// <param name="confirmationTag">
    /// The confirmation tag. Non-null only when the content type is Commit.
    /// </param>
    /// <param name="senderLeafIndex">The sender's leaf index in the ratchet tree.</param>
    /// <param name="padding">Padding bytes to append to the plaintext before encryption.</param>
    /// <returns>A fully formed PrivateMessage ready for wire transmission.</returns>
    public static PrivateMessage CreatePrivateMessage(
        FramedContent content,
        byte[] signingPrivateKey,
        byte[]? serializedGroupContext,
        ICipherSuite cs,
        SecretTree secretTree,
        byte[] senderDataSecret,
        byte[]? confirmationTag,
        uint senderLeafIndex,
        byte[] padding)
    {
        // 1. Sign the content (using PrivateMessage wire format)
        byte[] tbs = BuildFramedContentTbs(WireFormat.MlsPrivateMessage, content, serializedGroupContext);
        byte[] signature = cs.SignWithLabel(signingPrivateKey, "FramedContentTBS", tbs);

        var auth = new FramedContentAuthData(signature, confirmationTag);

        // 2. Get encryption key and nonce from secret tree
        // The secret tree advances the ratchet and returns the generation number.
        (byte[] key, byte[] nonce, uint generation) = content.ContentType == ContentType.Application
            ? secretTree.GetApplicationKeyAndNonce(senderLeafIndex)
            : secretTree.GetHandshakeKeyAndNonce(senderLeafIndex);

        // 3. Build PrivateMessageContent = content.Content || auth || padding
        // Per RFC 9420 Section 6.3.1:
        // struct {
        //     select (PrivateMessage.content_type) {
        //         case application: opaque application_data<V>;
        //         case proposal:    Proposal proposal;
        //         case commit:      Commit commit;
        //     };
        //     FramedContentAuthData auth;
        //     opaque padding<V>;
        // } PrivateMessageContent;
        byte[] privateMessageContent = TlsCodec.Serialize(writer =>
        {
            // Per RFC 9420 Section 6.3.1: application data is VarInt-prefixed,
            // but proposal/commit are raw struct bytes (no length prefix)
            if (content.ContentType == ContentType.Application)
                writer.WriteOpaqueV(content.Content);
            else
                writer.WriteBytes(content.Content);
            auth.WriteTo(writer, content.ContentType);
            writer.WriteOpaqueV(padding);
        });

        // 4. Build AAD: serialized PrivateContentAAD
        // struct {
        //     opaque group_id<V>;
        //     uint64 epoch;
        //     ContentType content_type;
        //     opaque authenticated_data<V>;
        // } PrivateContentAAD;
        byte[] aad = BuildPrivateContentAad(content.GroupId, content.Epoch, content.ContentType, content.AuthenticatedData);

        // 5. Generate reuse_guard and XOR with content nonce
        // Per RFC 9420 Section 6.3.1:
        //   content_nonce = nonce XOR [reuse_guard, 0, 0, 0, 0, 0, 0, 0, 0]
        byte[] reuseGuard = cs.RandomBytes(4);
        byte[] contentNonce = (byte[])nonce.Clone();
        for (int i = 0; i < 4; i++)
            contentNonce[i] ^= reuseGuard[i];

        // 6. Encrypt content with the XORed nonce
        byte[] ciphertext = cs.AeadEncrypt(key, contentNonce, aad, privateMessageContent);

        // 7. Encrypt sender data
        // SenderData = { leaf_index: uint32, generation: uint32, reuse_guard: opaque[4] }
        byte[] senderData = TlsCodec.Serialize(writer =>
        {
            writer.WriteUint32(senderLeafIndex);
            writer.WriteUint32(generation);
            writer.WriteBytes(reuseGuard);
        });

        // Sender data key/nonce derived from sender_data_secret and ciphertext sample
        // ciphertext_sample = ciphertext[0..min(Nh, len(ciphertext))]
        byte[] senderDataKey = DeriveSenderDataKey(cs, senderDataSecret, ciphertext);
        byte[] senderDataNonce = DeriveSenderDataNonce(cs, senderDataSecret, ciphertext);

        // Sender data AAD is group_id + epoch + content_type (no authenticated_data)
        byte[] senderDataAad = BuildSenderDataAad(content.GroupId, content.Epoch, content.ContentType);
        byte[] encryptedSenderData = cs.AeadEncrypt(senderDataKey, senderDataNonce, senderDataAad, senderData);

        return new PrivateMessage
        {
            GroupId = content.GroupId,
            Epoch = content.Epoch,
            ContentType = content.ContentType,
            AuthenticatedData = content.AuthenticatedData,
            EncryptedSenderData = encryptedSenderData,
            Ciphertext = ciphertext
        };
    }

    // --- Decrypt a PrivateMessage ---

    /// <summary>
    /// Decrypts a PrivateMessage and returns the recovered FramedContent and auth data.
    /// <para>
    /// Steps:
    /// <list type="number">
    ///   <item>Decrypt sender data to recover leaf_index and generation</item>
    ///   <item>Get the decryption key/nonce from the secret tree for that leaf/generation</item>
    ///   <item>Decrypt the ciphertext to recover PrivateMessageContent</item>
    ///   <item>Parse the content bytes and auth data; reconstruct the FramedContent</item>
    /// </list>
    /// </para>
    /// </summary>
    /// <param name="msg">The encrypted private message to decrypt.</param>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="secretTree">The secret tree for the current epoch.</param>
    /// <param name="senderDataSecret">The sender data secret from the epoch key schedule.</param>
    /// <returns>
    /// A tuple containing the decrypted FramedContent and the FramedContentAuthData
    /// (signature and optional confirmation tag).
    /// </returns>
    public static (FramedContent content, FramedContentAuthData auth) DecryptPrivateMessage(
        PrivateMessage msg,
        ICipherSuite cs,
        SecretTree secretTree,
        byte[] senderDataSecret)
    {
        // 1. Build AADs
        // Sender data AAD: group_id + epoch + content_type (no authenticated_data)
        byte[] senderDataAad = BuildSenderDataAad(msg.GroupId, msg.Epoch, msg.ContentType);
        // Content AAD: full PrivateContentAAD including authenticated_data
        byte[] aad = BuildPrivateContentAad(msg.GroupId, msg.Epoch, msg.ContentType, msg.AuthenticatedData);

        // 2. Decrypt sender data to get leaf_index, generation, and reuse_guard
        byte[] senderDataKey = DeriveSenderDataKey(cs, senderDataSecret, msg.Ciphertext);
        byte[] senderDataNonce = DeriveSenderDataNonce(cs, senderDataSecret, msg.Ciphertext);

        byte[] senderData = cs.AeadDecrypt(senderDataKey, senderDataNonce, senderDataAad, msg.EncryptedSenderData);

        var sdReader = new TlsReader(senderData);
        uint leafIndex = sdReader.ReadUint32();
        uint generation = sdReader.ReadUint32();
        byte[] reuseGuard = sdReader.ReadBytes(4);

        // 3. Get key/nonce for the sender's generation from the secret tree
        (byte[] key, byte[] nonce) = msg.ContentType == ContentType.Application
            ? secretTree.GetApplicationKeyAndNonceForGeneration(leafIndex, generation)
            : secretTree.GetHandshakeKeyAndNonceForGeneration(leafIndex, generation);

        // 4. XOR reuse_guard with content nonce (same as encrypt side)
        byte[] contentNonce = (byte[])nonce.Clone();
        for (int i = 0; i < 4; i++)
            contentNonce[i] ^= reuseGuard[i];

        // 5. Decrypt content with the XORed nonce
        byte[] plaintext = cs.AeadDecrypt(key, contentNonce, aad, msg.Ciphertext);

        // 6. Parse PrivateMessageContent
        var pmReader = new TlsReader(plaintext);
        byte[] contentBytes;
        if (msg.ContentType == ContentType.Application)
        {
            // application_data<V> is VarInt-length-prefixed
            contentBytes = pmReader.ReadOpaqueV();
        }
        else
        {
            // Proposal/Commit are raw structs — parse to find the boundary, then extract bytes
            int startPos = pmReader.Position;
            if (msg.ContentType == ContentType.Proposal)
                Proposal.ReadFrom(pmReader);
            else
                Commit.ReadFrom(pmReader);
            int consumed = pmReader.Position - startPos;
            contentBytes = plaintext[startPos..pmReader.Position];
        }
        var auth = FramedContentAuthData.ReadFrom(pmReader, msg.ContentType);
        // Remaining bytes are padding (opaque<V>); discard.

        // 7. Reconstruct FramedContent
        var content = new FramedContent
        {
            GroupId = msg.GroupId,
            Epoch = msg.Epoch,
            Sender = new Sender(SenderType.Member, leafIndex),
            AuthenticatedData = msg.AuthenticatedData,
            ContentType = msg.ContentType,
            Content = contentBytes
        };

        return (content, auth);
    }

    /// <summary>
    /// Verifies the signature on a decrypted PrivateMessage's content.
    /// <para>
    /// After decrypting a PrivateMessage with <see cref="DecryptPrivateMessage"/>,
    /// call this method to verify the sender's signature over the content.
    /// </para>
    /// </summary>
    /// <param name="content">The decrypted FramedContent.</param>
    /// <param name="auth">The decrypted FramedContentAuthData containing the signature.</param>
    /// <param name="signerPublicKey">The signer's public verification key.</param>
    /// <param name="serializedGroupContext">The TLS-serialized GroupContext for this epoch.</param>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <returns>True if the signature is valid.</returns>
    public static bool VerifyPrivateMessageSignature(
        FramedContent content,
        FramedContentAuthData auth,
        byte[] signerPublicKey,
        byte[]? serializedGroupContext,
        ICipherSuite cs)
    {
        byte[] tbs = BuildFramedContentTbs(WireFormat.MlsPrivateMessage, content, serializedGroupContext);
        return cs.VerifyWithLabel(signerPublicKey, "FramedContentTBS", tbs, auth.Signature);
    }

    // --- Private helpers ---

    /// <summary>
    /// Builds the PrivateContentAAD structure used as additional authenticated data
    /// for both content encryption and sender data encryption.
    /// </summary>
    private static byte[] BuildPrivateContentAad(
        byte[] groupId,
        ulong epoch,
        ContentType contentType,
        byte[] authenticatedData)
    {
        return TlsCodec.Serialize(writer =>
        {
            writer.WriteOpaqueV(groupId);
            writer.WriteUint64(epoch);
            writer.WriteUint8((byte)contentType);
            writer.WriteOpaqueV(authenticatedData);
        });
    }

    /// <summary>
    /// Builds the SenderDataAAD structure used as additional authenticated data
    /// for sender data encryption/decryption. Per RFC 9420 Section 6.3.2, this
    /// contains only group_id, epoch, and content_type (no authenticated_data).
    /// </summary>
    private static byte[] BuildSenderDataAad(
        byte[] groupId,
        ulong epoch,
        ContentType contentType)
    {
        return TlsCodec.Serialize(writer =>
        {
            writer.WriteOpaqueV(groupId);
            writer.WriteUint64(epoch);
            writer.WriteUint8((byte)contentType);
        });
    }

    /// <summary>
    /// Derives the sender data encryption key from the sender_data_secret and a
    /// sample of the content ciphertext.
    /// <para>
    /// Per RFC 9420 Section 6.3.2:
    ///   ciphertext_sample = ciphertext[0..min(Nh, len(ciphertext))]
    ///   sender_data_key = ExpandWithLabel(sender_data_secret, "key", ciphertext_sample, Nk)
    /// </para>
    /// </summary>
    internal static byte[] DeriveSenderDataKey(ICipherSuite cs, byte[] senderDataSecret, byte[] ciphertext)
    {
        byte[] ciphertextSample = GetCiphertextSample(cs, ciphertext);
        return cs.ExpandWithLabel(senderDataSecret, "key", ciphertextSample, cs.AeadKeySize);
    }

    /// <summary>
    /// Derives the sender data encryption nonce from the sender_data_secret and a
    /// sample of the content ciphertext.
    /// <para>
    /// Per RFC 9420 Section 6.3.2:
    ///   ciphertext_sample = ciphertext[0..min(Nh, len(ciphertext))]
    ///   sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, Nn)
    /// </para>
    /// </summary>
    internal static byte[] DeriveSenderDataNonce(ICipherSuite cs, byte[] senderDataSecret, byte[] ciphertext)
    {
        byte[] ciphertextSample = GetCiphertextSample(cs, ciphertext);
        return cs.ExpandWithLabel(senderDataSecret, "nonce", ciphertextSample, cs.AeadNonceSize);
    }

    /// <summary>
    /// Extracts the ciphertext sample used for sender data key/nonce derivation.
    /// Per RFC 9420 Section 6.3.2, the sample is the first min(Nh, len(ciphertext))
    /// bytes of the ciphertext, where Nh is the hash output size.
    /// </summary>
    internal static byte[] GetCiphertextSample(ICipherSuite cs, byte[] ciphertext)
    {
        int sampleSize = Math.Min(cs.HashSize, ciphertext.Length);
        byte[] sample = new byte[sampleSize];
        Array.Copy(ciphertext, sample, sampleSize);
        return sample;
    }
}
