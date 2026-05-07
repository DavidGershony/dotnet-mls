using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Message;
using DotnetMls.Types;
using Xunit;

namespace DotnetMls.Tests;

public class MessageFramingTests
{
    private readonly ICipherSuite _cs = new CipherSuite0x0001();

    [Fact]
    public void VerifyPublicMessage_MemberSenderWithoutMembershipTag_ReturnsFalse()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        byte[] membershipKey = _cs.RandomBytes(_cs.SecretSize);
        byte[] serializedGroupContext = CreateGroupContext(groupId: "group-1"u8.ToArray(), epoch: 1);

        var message = CreatePublicProposalMessage(sigPriv, membershipKey);
        message.MembershipTag = null;

        Assert.False(MessageFraming.VerifyPublicMessage(
            message, sigPub, serializedGroupContext, _cs, membershipKey));
    }

    [Fact]
    public void VerifyPublicMessage_MemberSenderWithoutMembershipKey_ReturnsFalse()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        byte[] membershipKey = _cs.RandomBytes(_cs.SecretSize);
        byte[] serializedGroupContext = CreateGroupContext(groupId: "group-1"u8.ToArray(), epoch: 1);

        var message = CreatePublicProposalMessage(sigPriv, membershipKey);

        Assert.False(MessageFraming.VerifyPublicMessage(
            message, sigPub, serializedGroupContext, _cs, membershipKey: null));
    }

    [Fact]
    public void VerifyPublicMessage_NonMemberSenderWithoutMembershipKey_ReturnsTrue()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var content = new FramedContent
        {
            GroupId = "group-1"u8.ToArray(),
            Epoch = 1,
            Sender = new Sender(SenderType.NewMemberProposal, 0),
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Proposal,
            Content = TlsCodec.Serialize(writer => new RemoveProposal(1).WriteTo(writer))
        };

        var message = MessageFraming.CreatePublicMessage(
            content,
            sigPriv,
            serializedGroupContext: null,
            _cs,
            confirmationTag: null,
            membershipKey: null);

        Assert.False(content.Sender.SenderType == SenderType.Member);
        Assert.Null(message.MembershipTag);
        Assert.True(MessageFraming.VerifyPublicMessage(
            message, sigPub, serializedGroupContext: null, _cs, membershipKey: null));
    }

    private PublicMessage CreatePublicProposalMessage(byte[] signingPrivateKey, byte[] membershipKey)
    {
        var content = new FramedContent
        {
            GroupId = "group-1"u8.ToArray(),
            Epoch = 1,
            Sender = new Sender(SenderType.Member, 0),
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Proposal,
            Content = TlsCodec.Serialize(writer => new RemoveProposal(1).WriteTo(writer))
        };

        return MessageFraming.CreatePublicMessage(
            content,
            signingPrivateKey,
            CreateGroupContext(groupId: content.GroupId, epoch: content.Epoch),
            _cs,
            confirmationTag: null,
            membershipKey: membershipKey);
    }

    private byte[] CreateGroupContext(byte[] groupId, ulong epoch)
    {
        var groupContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = _cs.Id,
            GroupId = groupId,
            Epoch = epoch,
            TreeHash = Array.Empty<byte>(),
            ConfirmedTranscriptHash = Array.Empty<byte>(),
            Extensions = Array.Empty<Extension>()
        };

        return TlsCodec.Serialize(writer => groupContext.WriteTo(writer));
    }
}
