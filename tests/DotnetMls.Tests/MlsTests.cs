using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Group;
using DotnetMls.KeySchedule;
using DotnetMls.Tree;
using DotnetMls.Types;
using Xunit;

namespace DotnetMls.Tests;

// ================================================================
// TLS Codec Tests
// ================================================================

public class TlsWriterReaderTests
{
    [Fact]
    public void Uint8_RoundTrips()
    {
        var data = TlsCodec.Serialize(w => w.WriteUint8(0xAB));
        var reader = new TlsReader(data);
        Assert.Equal(0xAB, reader.ReadUint8());
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Uint16_RoundTrips()
    {
        var data = TlsCodec.Serialize(w => w.WriteUint16(0x1234));
        var reader = new TlsReader(data);
        Assert.Equal((ushort)0x1234, reader.ReadUint16());
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Uint24_RoundTrips()
    {
        var data = TlsCodec.Serialize(w => w.WriteUint24(0xABCDEF));
        var reader = new TlsReader(data);
        Assert.Equal(0xABCDEFu, reader.ReadUint24());
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Uint32_RoundTrips()
    {
        var data = TlsCodec.Serialize(w => w.WriteUint32(0xDEADBEEF));
        var reader = new TlsReader(data);
        Assert.Equal(0xDEADBEEFu, reader.ReadUint32());
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Uint64_RoundTrips()
    {
        var data = TlsCodec.Serialize(w => w.WriteUint64(0xDEADBEEFCAFEBABE));
        var reader = new TlsReader(data);
        Assert.Equal(0xDEADBEEFCAFEBABEuL, reader.ReadUint64());
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Uint16_IsBigEndian()
    {
        var data = TlsCodec.Serialize(w => w.WriteUint16(0x0102));
        Assert.Equal(new byte[] { 0x01, 0x02 }, data);
    }

    [Fact]
    public void Uint32_IsBigEndian()
    {
        var data = TlsCodec.Serialize(w => w.WriteUint32(0x01020304));
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, data);
    }

    [Fact]
    public void Opaque8_RoundTrips()
    {
        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
        var data = TlsCodec.Serialize(w => w.WriteOpaque8(payload));
        var reader = new TlsReader(data);
        var result = reader.ReadOpaque8();
        Assert.Equal(payload, result);
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Opaque16_RoundTrips()
    {
        byte[] payload = new byte[300];
        new Random(42).NextBytes(payload);
        var data = TlsCodec.Serialize(w => w.WriteOpaque16(payload));
        var reader = new TlsReader(data);
        var result = reader.ReadOpaque16();
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Opaque32_RoundTrips()
    {
        byte[] payload = new byte[] { 10, 20, 30 };
        var data = TlsCodec.Serialize(w => w.WriteOpaque32(payload));
        var reader = new TlsReader(data);
        var result = reader.ReadOpaque32();
        Assert.Equal(payload, result);
    }

    [Fact]
    public void EmptyOpaque_RoundTrips()
    {
        var data = TlsCodec.Serialize(w => w.WriteOpaque8(Array.Empty<byte>()));
        var reader = new TlsReader(data);
        var result = reader.ReadOpaque8();
        Assert.Empty(result);
    }

    [Fact]
    public void Vector16_WithMultipleItems_RoundTrips()
    {
        var data = TlsCodec.Serialize(w =>
            w.WriteVector16(inner =>
            {
                inner.WriteUint8(0x01);
                inner.WriteUint8(0x02);
                inner.WriteUint8(0x03);
            }));

        var reader = new TlsReader(data);
        var sub = reader.ReadVector16();
        Assert.Equal(0x01, sub.ReadUint8());
        Assert.Equal(0x02, sub.ReadUint8());
        Assert.Equal(0x03, sub.ReadUint8());
        Assert.True(sub.IsEmpty);
    }

    [Fact]
    public void MultipleFields_RoundTrips()
    {
        var data = TlsCodec.Serialize(w =>
        {
            w.WriteUint8(42);
            w.WriteUint16(1000);
            w.WriteUint32(0xCAFE);
            w.WriteOpaque8(new byte[] { 1, 2, 3 });
        });

        var reader = new TlsReader(data);
        Assert.Equal(42, reader.ReadUint8());
        Assert.Equal((ushort)1000, reader.ReadUint16());
        Assert.Equal(0xCAFEu, reader.ReadUint32());
        Assert.Equal(new byte[] { 1, 2, 3 }, reader.ReadOpaque8());
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Reader_InsufficientData_ThrowsTlsDecodingException()
    {
        var reader = new TlsReader(new byte[] { 0x01 });
        Assert.Throws<TlsDecodingException>(() => reader.ReadUint16());
    }

    [Fact]
    public void Reader_EmptyData_ReadUint8_Throws()
    {
        var reader = new TlsReader(Array.Empty<byte>());
        Assert.True(reader.IsEmpty);
        Assert.Throws<TlsDecodingException>(() => reader.ReadUint8());
    }

    [Fact]
    public void Uint24_ExceedsMax_Throws()
    {
        using var writer = new TlsWriter();
        Assert.Throws<ArgumentOutOfRangeException>(() => writer.WriteUint24(0x1_000_000));
    }

    [Fact]
    public void SubReader_HasCorrectBounds()
    {
        var data = TlsCodec.Serialize(w =>
        {
            w.WriteOpaque8(new byte[] { 0xAA, 0xBB });
            w.WriteUint8(0xFF);
        });

        var reader = new TlsReader(data);
        var sub = reader.ReadVector8();
        Assert.Equal(2, sub.Remaining);
        Assert.Equal(0xAA, sub.ReadUint8());
        Assert.Equal(0xBB, sub.ReadUint8());
        Assert.True(sub.IsEmpty);
        // The outer reader should still have the trailing 0xFF
        Assert.Equal(0xFF, reader.ReadUint8());
    }
}

// ================================================================
// QuicVarint Tests
// ================================================================

public class QuicVarintTests
{
    [Theory]
    [InlineData(0UL)]
    [InlineData(1UL)]
    [InlineData(63UL)]
    public void OneByte_Values_RoundTrip(ulong value)
    {
        var data = TlsCodec.Serialize(w => QuicVarint.Write(w, value));
        Assert.Single(data);
        var reader = new TlsReader(data);
        Assert.Equal(value, QuicVarint.Read(reader));
    }

    [Theory]
    [InlineData(64UL)]
    [InlineData(1000UL)]
    [InlineData(16383UL)]
    public void TwoByte_Values_RoundTrip(ulong value)
    {
        var data = TlsCodec.Serialize(w => QuicVarint.Write(w, value));
        Assert.Equal(2, data.Length);
        var reader = new TlsReader(data);
        Assert.Equal(value, QuicVarint.Read(reader));
    }

    [Theory]
    [InlineData(16384UL)]
    [InlineData(100000UL)]
    [InlineData(1073741823UL)]
    public void FourByte_Values_RoundTrip(ulong value)
    {
        var data = TlsCodec.Serialize(w => QuicVarint.Write(w, value));
        Assert.Equal(4, data.Length);
        var reader = new TlsReader(data);
        Assert.Equal(value, QuicVarint.Read(reader));
    }

    [Theory]
    [InlineData(1073741824UL)]
    [InlineData(4611686018427387903UL)]
    public void EightByte_Values_RoundTrip(ulong value)
    {
        var data = TlsCodec.Serialize(w => QuicVarint.Write(w, value));
        Assert.Equal(8, data.Length);
        var reader = new TlsReader(data);
        Assert.Equal(value, QuicVarint.Read(reader));
    }

    [Fact]
    public void MaxValue_RoundTrips()
    {
        var data = TlsCodec.Serialize(w => QuicVarint.Write(w, QuicVarint.MaxValue));
        var reader = new TlsReader(data);
        Assert.Equal(QuicVarint.MaxValue, QuicVarint.Read(reader));
    }

    [Fact]
    public void ExceedsMaxValue_Throws()
    {
        using var writer = new TlsWriter();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicVarint.Write(writer, QuicVarint.MaxValue + 1));
    }

    [Theory]
    [InlineData(0UL, 1)]
    [InlineData(63UL, 1)]
    [InlineData(64UL, 2)]
    [InlineData(16383UL, 2)]
    [InlineData(16384UL, 4)]
    [InlineData(1073741823UL, 4)]
    [InlineData(1073741824UL, 8)]
    public void EncodedLength_ReturnsCorrectSize(ulong value, int expectedLength)
    {
        Assert.Equal(expectedLength, QuicVarint.EncodedLength(value));
    }
}

// ================================================================
// TreeMath Tests
// ================================================================

public class TreeMathTests
{
    [Theory]
    [InlineData(0u, 0u)]  // Even index (leaf) => level 0
    [InlineData(1u, 1u)]  // 0b01 => 1 trailing one
    [InlineData(2u, 0u)]  // Even
    [InlineData(3u, 2u)]  // 0b11 => 2 trailing ones
    [InlineData(4u, 0u)]  // Even
    [InlineData(5u, 1u)]  // 0b101 => 1 trailing one
    [InlineData(7u, 3u)]  // 0b111 => 3 trailing ones
    public void Level_KnownValues(uint x, uint expected)
    {
        Assert.Equal(expected, TreeMath.Level(x));
    }

    [Theory]
    [InlineData(1u, 1u)]
    [InlineData(2u, 3u)]
    [InlineData(3u, 5u)]
    [InlineData(4u, 7u)]
    [InlineData(5u, 9u)]
    [InlineData(8u, 15u)]
    public void NodeCount_KnownValues(uint leafCount, uint expected)
    {
        Assert.Equal(expected, TreeMath.NodeCount(leafCount));
    }

    [Fact]
    public void NodeCount_Zero_ReturnsZero()
    {
        Assert.Equal(0u, TreeMath.NodeCount(0));
    }

    [Theory]
    [InlineData(1u, 0u)]
    [InlineData(2u, 1u)]
    [InlineData(3u, 3u)]
    [InlineData(4u, 3u)]
    [InlineData(5u, 7u)]
    [InlineData(8u, 7u)]
    public void Root_KnownValues(uint leafCount, uint expected)
    {
        Assert.Equal(expected, TreeMath.Root(leafCount));
    }

    [Fact]
    public void Root_ZeroLeaves_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => TreeMath.Root(0));
    }

    [Fact]
    public void Left_KnownValues()
    {
        // Node 1 (level 1): left = 0
        Assert.Equal(0u, TreeMath.Left(1));
        // Node 3 (level 2): left = 1
        Assert.Equal(1u, TreeMath.Left(3));
        // Node 7 (level 3): left = 3
        Assert.Equal(3u, TreeMath.Left(7));
    }

    [Fact]
    public void Right_KnownValues()
    {
        // Node 1 (level 1): right = 2
        Assert.Equal(2u, TreeMath.Right(1));
        // Node 3 (level 2): right = 5
        Assert.Equal(5u, TreeMath.Right(3));
        // Node 7 (level 3): right = 11
        Assert.Equal(11u, TreeMath.Right(7));
    }

    [Fact]
    public void Left_LeafNode_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => TreeMath.Left(0));
        Assert.Throws<InvalidOperationException>(() => TreeMath.Left(2));
    }

    [Fact]
    public void Right_LeafNode_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => TreeMath.Right(0));
    }

    [Theory]
    [InlineData(0u, true)]
    [InlineData(1u, false)]
    [InlineData(2u, true)]
    [InlineData(3u, false)]
    [InlineData(4u, true)]
    public void IsLeaf_KnownValues(uint x, bool expected)
    {
        Assert.Equal(expected, TreeMath.IsLeaf(x));
    }

    [Theory]
    [InlineData(0u, 0u)]
    [InlineData(1u, 2u)]
    [InlineData(2u, 4u)]
    [InlineData(3u, 6u)]
    public void LeafToNode_KnownValues(uint leafIndex, uint expected)
    {
        Assert.Equal(expected, TreeMath.LeafToNode(leafIndex));
    }

    [Theory]
    [InlineData(0u, 0u)]
    [InlineData(2u, 1u)]
    [InlineData(4u, 2u)]
    [InlineData(6u, 3u)]
    public void NodeToLeaf_KnownValues(uint nodeIndex, uint expected)
    {
        Assert.Equal(expected, TreeMath.NodeToLeaf(nodeIndex));
    }

    [Fact]
    public void DirectPath_TwoLeaves()
    {
        // Tree: 0-1-2, root=1
        // DirectPath of leaf 0: [1] (just the root)
        var dp = TreeMath.DirectPath(0, 2);
        Assert.Equal(new uint[] { 1 }, dp);

        // DirectPath of leaf 1: [1]
        dp = TreeMath.DirectPath(1, 2);
        Assert.Equal(new uint[] { 1 }, dp);
    }

    [Fact]
    public void DirectPath_FourLeaves()
    {
        // Tree with 4 leaves: nodes 0-6, root=3
        // Leaf 0 (node 0): path = [1, 3]
        var dp = TreeMath.DirectPath(0, 4);
        Assert.Equal(new uint[] { 1, 3 }, dp);

        // Leaf 3 (node 6): path = [5, 3]
        dp = TreeMath.DirectPath(3, 4);
        Assert.Equal(new uint[] { 5, 3 }, dp);
    }

    [Fact]
    public void DirectPath_SingleLeaf_ReturnsEmpty()
    {
        var dp = TreeMath.DirectPath(0, 1);
        Assert.Empty(dp);
    }

    [Fact]
    public void Copath_TwoLeaves()
    {
        // Copath of leaf 0 in 2-leaf tree: sibling of node 0 w.r.t parent 1 = node 2
        var cp = TreeMath.Copath(0, 2);
        Assert.Equal(new uint[] { 2 }, cp);

        // Copath of leaf 1: sibling of node 2 w.r.t parent 1 = node 0
        cp = TreeMath.Copath(1, 2);
        Assert.Equal(new uint[] { 0 }, cp);
    }

    [Fact]
    public void Copath_FourLeaves()
    {
        // Copath of leaf 0 in 4-leaf tree
        // node 0's sibling w.r.t parent 1 = 2
        // node 1's sibling w.r.t parent 3 = 5
        var cp = TreeMath.Copath(0, 4);
        Assert.Equal(new uint[] { 2, 5 }, cp);
    }

    [Fact]
    public void Copath_SingleLeaf_ReturnsEmpty()
    {
        Assert.Empty(TreeMath.Copath(0, 1));
    }

    [Fact]
    public void Parent_TwoLeafTree()
    {
        // In a 2-leaf tree (nodes 0,1,2), parent of 0 is 1, parent of 2 is 1
        uint nodeCount = TreeMath.NodeCount(2);
        Assert.Equal(1u, TreeMath.Parent(0, nodeCount));
        Assert.Equal(1u, TreeMath.Parent(2, nodeCount));
    }

    [Fact]
    public void Parent_Root_Throws()
    {
        uint nodeCount = TreeMath.NodeCount(4);
        Assert.Throws<InvalidOperationException>(() => TreeMath.Parent(3, nodeCount));
    }

    [Fact]
    public void Sibling_TwoLeafTree()
    {
        uint nodeCount = TreeMath.NodeCount(2);
        Assert.Equal(2u, TreeMath.Sibling(0, nodeCount));
        Assert.Equal(0u, TreeMath.Sibling(2, nodeCount));
    }

    [Fact]
    public void CommonAncestor_SameLeaf_ReturnsSelf()
    {
        var result = TreeMath.CommonAncestor(0, 0);
        Assert.Equal(0u, result);
    }

    [Fact]
    public void CommonAncestor_AdjacentLeaves_ReturnsParent()
    {
        var result = TreeMath.CommonAncestor(0, 1);
        Assert.Equal(1u, result);
    }

    [Fact]
    public void CommonAncestor_DistantLeaves()
    {
        // Leaves 0 and 3 in a 4-leaf tree: common ancestor is root node 3
        var result = TreeMath.CommonAncestor(0, 3);
        Assert.Equal(3u, result);
    }
}

// ================================================================
// RatchetTree Tests
// ================================================================

public class RatchetTreeTests
{
    private static LeafNode MakeLeaf(byte id)
    {
        return new LeafNode
        {
            EncryptionKey = new byte[] { id },
            SignatureKey = new byte[] { id },
            Credential = new BasicCredential(new byte[] { id }),
            Capabilities = new Capabilities
            {
                Versions = new ushort[] { 1 },
                CipherSuites = new ushort[] { 1 },
                Extensions = Array.Empty<ushort>(),
                Proposals = Array.Empty<ushort>(),
                Credentials = new ushort[] { 1 }
            },
            Source = LeafNodeSource.Commit,
            Extensions = Array.Empty<Extension>(),
            Signature = new byte[] { id }
        };
    }

    [Fact]
    public void AddLeaf_FirstLeaf_ReturnsIndex0()
    {
        var tree = new RatchetTree();
        var idx = tree.AddLeaf(MakeLeaf(1));
        Assert.Equal(0u, idx);
        Assert.Equal(1u, tree.LeafCount);
        Assert.Equal(1, tree.NodeCount);
    }

    [Fact]
    public void AddLeaf_SecondLeaf_ReturnsIndex1()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        var idx = tree.AddLeaf(MakeLeaf(2));
        Assert.Equal(1u, idx);
        Assert.Equal(2u, tree.LeafCount);
        Assert.Equal(3, tree.NodeCount);
    }

    [Fact]
    public void AddLeaf_ThreeLeaves_CorrectLayout()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        tree.AddLeaf(MakeLeaf(3));
        Assert.Equal(3u, tree.LeafCount);
        Assert.Equal(5, tree.NodeCount);
    }

    [Fact]
    public void GetLeaf_ReturnsCorrectNode()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(0xAA));
        var leaf = tree.GetLeaf(0);
        Assert.NotNull(leaf);
        Assert.Equal(new byte[] { 0xAA }, leaf!.EncryptionKey);
    }

    [Fact]
    public void GetLeaf_BlankSlot_ReturnsNull()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        tree.BlankLeaf(0);
        Assert.Null(tree.GetLeaf(0));
    }

    [Fact]
    public void BlankLeaf_ClearsDirectPath()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        tree.AddLeaf(MakeLeaf(3));

        // Set a parent node
        tree.SetParent(1, new ParentNode(new byte[] { 99 }, Array.Empty<byte>(), new List<uint>()));
        Assert.NotNull(tree.GetParent(1));

        // Blank leaf 0 should blank parent 1 (which is on the direct path of leaf 0)
        tree.BlankLeaf(0);
        Assert.Null(tree.GetLeaf(0));
        Assert.True(tree.IsBlank(1));
    }

    [Fact]
    public void AddLeaf_ReusesEmptySlot()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        tree.AddLeaf(MakeLeaf(3));

        // Blank leaf 1 (middle)
        tree.BlankLeaf(1);

        // Next add should reuse index 1
        var idx = tree.AddLeaf(MakeLeaf(4));
        Assert.Equal(1u, idx);
    }

    [Fact]
    public void Resolution_NonBlankLeaf_ContainsSelf()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        var resolution = tree.Resolution(0);
        Assert.Single(resolution);
        Assert.Equal(0u, resolution[0]);
    }

    [Fact]
    public void Resolution_BlankLeaf_IsEmpty()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        tree.BlankLeaf(0);
        var resolution = tree.Resolution(0); // node index 0
        Assert.Empty(resolution);
    }

    [Fact]
    public void Resolution_BlankParent_RecursesIntoChildren()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        // Parent node 1 is blank by default
        Assert.True(tree.IsBlank(1));

        var resolution = tree.Resolution(1);
        // Should contain both children: node 0 and node 2
        Assert.Equal(2, resolution.Count);
        Assert.Contains(0u, resolution);
        Assert.Contains(2u, resolution);
    }

    [Fact]
    public void GetOccupiedLeaves_ReturnsNonBlankLeaves()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        tree.AddLeaf(MakeLeaf(3));
        tree.BlankLeaf(1);

        var occupied = tree.GetOccupiedLeaves();
        Assert.Equal(2, occupied.Count);
        Assert.Contains(0u, occupied);
        Assert.Contains(2u, occupied);
    }

    [Fact]
    public void Clone_ProducesIndependentCopy()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));

        var clone = tree.Clone();
        Assert.Equal(tree.LeafCount, clone.LeafCount);
        Assert.Equal(tree.NodeCount, clone.NodeCount);

        // Modifying clone should not affect original
        clone.BlankLeaf(0);
        Assert.NotNull(tree.GetLeaf(0));
        Assert.Null(clone.GetLeaf(0));
    }

    [Fact]
    public void IsBlank_BlankNode_ReturnsTrue()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        // Parent at node 1 is blank
        Assert.True(tree.IsBlank(1));
    }

    [Fact]
    public void IsBlank_OccupiedLeaf_ReturnsFalse()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        Assert.False(tree.IsBlank(0));
    }

    /// <summary>
    /// RFC 9420 §7.5 and §12.4.3.3: ratchet_tree serialization uses optional&lt;Node&gt;.
    /// Node includes a NodeType discriminator byte (1=leaf, 2=parent).
    /// Wire format: uint8(present), if present: uint8(nodeType) + LeafNode/ParentNode.
    /// </summary>
    [Fact]
    public void RatchetTree_Serialization_IncludesNodeTypeDiscriminator()
    {
        var tree = new RatchetTree();
        tree.AddLeaf(MakeLeaf(1));
        tree.AddLeaf(MakeLeaf(2));
        // Tree has 3 nodes: leaf(0), parent(1-blank), leaf(2)

        // Serialize
        var data = TlsCodec.Serialize(w => tree.WriteTo(w));
        var outerReader = new TlsReader(data);
        var treeBytes = outerReader.ReadOpaqueV();
        var sub = new TlsReader(treeBytes);

        byte[] expectedLeaf0Bytes = TlsCodec.Serialize(w => MakeLeaf(1).WriteTo(w));
        byte[] expectedLeaf2Bytes = TlsCodec.Serialize(w => MakeLeaf(2).WriteTo(w));

        // Node 0: present leaf with nodeType=1
        Assert.Equal(1, sub.ReadUint8()); // present
        Assert.Equal(1, sub.ReadUint8()); // nodeType = leaf
        byte[] actualLeaf0 = sub.ReadBytes(expectedLeaf0Bytes.Length);
        Assert.Equal(expectedLeaf0Bytes, actualLeaf0);

        // Node 1: blank parent
        Assert.Equal(0, sub.ReadUint8()); // absent

        // Node 2: present leaf with nodeType=1
        Assert.Equal(1, sub.ReadUint8()); // present
        Assert.Equal(1, sub.ReadUint8()); // nodeType = leaf
        byte[] actualLeaf2 = sub.ReadBytes(expectedLeaf2Bytes.Length);
        Assert.Equal(expectedLeaf2Bytes, actualLeaf2);

        Assert.True(sub.IsEmpty);
    }

    /// <summary>
    /// Verifies that a ratchet tree with NodeType discriminator bytes round-trips
    /// through WriteTo/ReadFrom correctly.
    /// </summary>
    [Fact]
    public void RatchetTree_ReadFrom_WithNodeType_RoundTrips()
    {
        var leaf1 = MakeLeaf(1);
        var leaf2 = MakeLeaf(2);

        // Build wire format with NodeType discriminator (RFC 9420 §7.5)
        byte[] rfcTreeBytes = TlsCodec.Serialize(outerWriter =>
        {
            outerWriter.WriteVectorV(inner =>
            {
                // Node 0 (leaf): present + nodeType=1 + LeafNode
                inner.WriteUint8(1);
                inner.WriteUint8(1); // nodeType = leaf
                leaf1.WriteTo(inner);

                // Node 1 (parent): blank
                inner.WriteUint8(0);

                // Node 2 (leaf): present + nodeType=1 + LeafNode
                inner.WriteUint8(1);
                inner.WriteUint8(1); // nodeType = leaf
                leaf2.WriteTo(inner);
            });
        });

        var reader = new TlsReader(rfcTreeBytes);
        var tree = RatchetTree.ReadFrom(reader);

        Assert.Equal(3, tree.NodeCount);
        Assert.Equal(2u, tree.LeafCount);
        Assert.NotNull(tree.GetLeaf(0));
        Assert.Equal(new byte[] { 1 }, tree.GetLeaf(0)!.EncryptionKey);
        Assert.NotNull(tree.GetLeaf(1));
        Assert.Equal(new byte[] { 2 }, tree.GetLeaf(1)!.EncryptionKey);
        Assert.True(tree.IsBlank(1)); // parent is blank
    }
}

// ================================================================
// KeyScheduleEpoch Tests
// ================================================================

public class KeyScheduleEpochTests
{
    [Fact]
    public void Create_ProducesAllSecrets()
    {
        var cs = new CipherSuite0x0001();
        var initSecret = cs.RandomBytes(32);
        var commitSecret = new byte[32]; // zeros for initial
        var groupContext = cs.RandomBytes(64);

        var epoch = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, groupContext);

        Assert.Equal(32, epoch.InitSecret.Length);
        Assert.Equal(32, epoch.SenderDataSecret.Length);
        Assert.Equal(32, epoch.EncryptionSecret.Length);
        Assert.Equal(32, epoch.ExporterSecret.Length);
        Assert.Equal(32, epoch.EpochAuthenticator.Length);
        Assert.Equal(32, epoch.ExternalSecret.Length);
        Assert.Equal(32, epoch.ConfirmationKey.Length);
        Assert.Equal(32, epoch.MembershipKey.Length);
        Assert.Equal(32, epoch.ResumptionPsk.Length);
        Assert.Equal(32, epoch.JoinerSecret.Length);
        Assert.Equal(32, epoch.WelcomeSecret.Length);
        Assert.Equal(16, epoch.WelcomeKey.Length);   // AES-128 key
        Assert.Equal(12, epoch.WelcomeNonce.Length); // AES-GCM nonce
    }

    [Fact]
    public void Create_IsDeterministic()
    {
        var cs = new CipherSuite0x0001();
        var initSecret = new byte[32];
        var commitSecret = new byte[32];
        var groupContext = new byte[64];

        var epoch1 = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, groupContext);
        var epoch2 = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, groupContext);

        Assert.Equal(epoch1.InitSecret, epoch2.InitSecret);
        Assert.Equal(epoch1.ConfirmationKey, epoch2.ConfirmationKey);
        Assert.Equal(epoch1.EncryptionSecret, epoch2.EncryptionSecret);
        Assert.Equal(epoch1.WelcomeKey, epoch2.WelcomeKey);
    }

    [Fact]
    public void Create_DifferentInputs_ProduceDifferentSecrets()
    {
        var cs = new CipherSuite0x0001();
        var initSecret1 = cs.RandomBytes(32);
        var initSecret2 = cs.RandomBytes(32);
        var commitSecret = new byte[32];
        var groupContext = cs.RandomBytes(64);

        var epoch1 = KeyScheduleEpoch.Create(cs, initSecret1, commitSecret, groupContext);
        var epoch2 = KeyScheduleEpoch.Create(cs, initSecret2, commitSecret, groupContext);

        Assert.NotEqual(epoch1.InitSecret, epoch2.InitSecret);
        Assert.NotEqual(epoch1.ConfirmationKey, epoch2.ConfirmationKey);
    }

    [Fact]
    public void FromJoinerSecret_ProducesValidSecrets()
    {
        var cs = new CipherSuite0x0001();
        var joinerSecret = cs.RandomBytes(32);
        var groupContext = cs.RandomBytes(64);

        var epoch = KeyScheduleEpoch.FromJoinerSecret(cs, joinerSecret, groupContext);

        Assert.Equal(32, epoch.InitSecret.Length);
        Assert.Equal(32, epoch.ConfirmationKey.Length);
        Assert.Equal(16, epoch.WelcomeKey.Length);
    }

    [Fact]
    public void FromJoinerSecret_MatchesCreateWhenDerivedFromSameJoiner()
    {
        var cs = new CipherSuite0x0001();
        var initSecret = new byte[32];
        var commitSecret = new byte[32];
        var groupContext = new byte[64];

        // Create epoch normally to get the joiner secret
        var epoch1 = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, groupContext);

        // Derive from the joiner secret directly
        var epoch2 = KeyScheduleEpoch.FromJoinerSecret(cs, epoch1.JoinerSecret, groupContext);

        // These should match since they derive from the same joiner_secret
        Assert.Equal(epoch1.WelcomeKey, epoch2.WelcomeKey);
        Assert.Equal(epoch1.WelcomeNonce, epoch2.WelcomeNonce);
        Assert.Equal(epoch1.ConfirmationKey, epoch2.ConfirmationKey);
        Assert.Equal(epoch1.InitSecret, epoch2.InitSecret);
    }

    [Fact]
    public void ComputeConfirmationTag_ProducesConsistentMac()
    {
        var cs = new CipherSuite0x0001();
        var epoch = KeyScheduleEpoch.Create(cs, new byte[32], new byte[32], new byte[64]);
        var transcriptHash = cs.RandomBytes(32);

        var tag1 = epoch.ComputeConfirmationTag(cs, transcriptHash);
        var tag2 = epoch.ComputeConfirmationTag(cs, transcriptHash);
        Assert.Equal(tag1, tag2);
    }

    [Fact]
    public void ComputeMembershipTag_ProducesConsistentMac()
    {
        var cs = new CipherSuite0x0001();
        var epoch = KeyScheduleEpoch.Create(cs, new byte[32], new byte[32], new byte[64]);
        var tbm = cs.RandomBytes(128);

        var tag1 = epoch.ComputeMembershipTag(cs, tbm);
        var tag2 = epoch.ComputeMembershipTag(cs, tbm);
        Assert.Equal(tag1, tag2);
    }

    [Fact]
    public void DeriveExporterSecret_ProducesRequestedLength()
    {
        var cs = new CipherSuite0x0001();
        var epoch = KeyScheduleEpoch.Create(cs, new byte[32], new byte[32], new byte[64]);

        var exported = epoch.DeriveExporterSecret(cs, "test", "context"u8.ToArray(), 48);
        Assert.Equal(48, exported.Length);
    }

    [Fact]
    public void DeriveExporterSecret_DifferentLabels_DifferentOutputs()
    {
        var cs = new CipherSuite0x0001();
        var epoch = KeyScheduleEpoch.Create(cs, new byte[32], new byte[32], new byte[64]);
        var context = "ctx"u8.ToArray();

        var e1 = epoch.DeriveExporterSecret(cs, "label_a", context, 32);
        var e2 = epoch.DeriveExporterSecret(cs, "label_b", context, 32);
        Assert.NotEqual(e1, e2);
    }

    /// <summary>
    /// RFC 9420 §8 requires welcome_secret to be derived from an intermediate secret,
    /// NOT directly from joiner_secret:
    ///   intermediate = KDF.Extract(salt=joiner_secret, ikm=psk_secret)
    ///   welcome_secret = DeriveSecret(intermediate, "welcome")
    ///   epoch_secret = ExpandWithLabel(intermediate, "epoch", GroupContext, Nh)
    /// </summary>
    [Fact]
    public void WelcomeSecret_IsDerivedViaIntermediateSecret_PerRfc9420()
    {
        var cs = new CipherSuite0x0001();
        var initSecret = new byte[32];
        var commitSecret = new byte[32];
        var groupContext = new byte[64];

        var epoch = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, groupContext);

        // Per RFC 9420 §8:
        // intermediate_secret = KDF.Extract(salt=joiner_secret, ikm=psk_secret)
        // When no PSKs, psk_secret = zeros(Nh)
        byte[] pskSecret = new byte[cs.SecretSize];
        byte[] intermediateSecret = cs.Extract(epoch.JoinerSecret, pskSecret);

        // welcome_secret = DeriveSecret(intermediate_secret, "welcome")
        byte[] expectedWelcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");

        Assert.Equal(expectedWelcomeSecret, epoch.WelcomeSecret);
    }

    /// <summary>
    /// Same RFC 9420 §8 check for FromJoinerSecret path (used in Welcome processing).
    /// </summary>
    [Fact]
    public void FromJoinerSecret_WelcomeSecret_IsDerivedViaIntermediateSecret()
    {
        var cs = new CipherSuite0x0001();
        var joinerSecret = cs.RandomBytes(32);
        var groupContext = new byte[64];

        var epoch = KeyScheduleEpoch.FromJoinerSecret(cs, joinerSecret, groupContext);

        byte[] pskSecret = new byte[cs.SecretSize];
        byte[] intermediateSecret = cs.Extract(joinerSecret, pskSecret);
        byte[] expectedWelcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");

        Assert.Equal(expectedWelcomeSecret, epoch.WelcomeSecret);
    }

    /// <summary>
    /// RFC 9420 §8 requires epoch_secret to be derived from intermediate_secret, not member:
    ///   epoch_secret = ExpandWithLabel(intermediate, "epoch", GroupContext, Nh)
    /// </summary>
    [Fact]
    public void EpochSecret_IsDerivedViaIntermediateSecret_PerRfc9420()
    {
        var cs = new CipherSuite0x0001();
        var initSecret = new byte[32];
        var commitSecret = new byte[32];
        var groupContext = new byte[64];

        var epoch = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, groupContext);

        // Compute expected epoch_secret per RFC 9420:
        byte[] pskSecret = new byte[cs.SecretSize];
        byte[] intermediateSecret = cs.Extract(epoch.JoinerSecret, pskSecret);
        byte[] expectedEpochSecret = cs.ExpandWithLabel(
            intermediateSecret, "epoch", groupContext, cs.SecretSize);

        // Verify by checking a derived secret (confirmation_key = DeriveSecret(epoch_secret, "confirm"))
        byte[] expectedConfirmationKey = cs.DeriveSecret(expectedEpochSecret, "confirm");

        Assert.Equal(expectedConfirmationKey, epoch.ConfirmationKey);
    }
}

// ================================================================
// MlsGroup Lifecycle Tests
// ================================================================

public class MlsGroupLifecycleTests
{
    private readonly ICipherSuite _cs = new CipherSuite0x0001();

    [Fact]
    public void CreateGroup_ProducesValidGroup()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var identity = "alice"u8.ToArray();

        var group = MlsGroup.CreateGroup(_cs, identity, sigPriv, sigPub);

        Assert.Equal(0UL, group.Epoch);
        Assert.Equal(0u, group.MyLeafIndex);
        Assert.NotEmpty(group.GroupId);
        Assert.Equal(_cs.Id, group.CipherSuiteId);
        Assert.NotNull(group.Tree);
        Assert.Equal(1u, group.Tree.LeafCount);
    }

    [Fact]
    public void CreateGroup_WithCustomGroupId_UsesIt()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var customId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), sigPriv, sigPub, groupId: customId);
        Assert.Equal(customId, group.GroupId);
    }

    [Fact]
    public void CreateKeyPackage_ProducesValidPackage()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var kp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), sigPriv, sigPub,
            out var initPriv, out var hpkePriv);

        Assert.NotNull(kp);
        Assert.Equal(ProtocolVersion.Mls10, kp.Version);
        Assert.Equal(_cs.Id, kp.CipherSuite);
        Assert.Equal(32, kp.InitKey.Length);
        Assert.NotNull(kp.LeafNode);
        Assert.NotEmpty(kp.Signature);
        Assert.Equal(32, initPriv.Length);
        Assert.Equal(32, hpkePriv.Length);
    }

    [Fact]
    public void CommitAddMember_AdvancesEpoch()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        Assert.Equal(0UL, group.Epoch);

        // Create a key package for Bob
        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        // Alice adds Bob
        var addProposals = group.ProposeAdd(new[] { bobKp });
        var (commitMsg, welcome) = group.Commit(addProposals);

        Assert.NotNull(commitMsg);
        Assert.NotNull(welcome);

        group.MergePendingCommit();
        Assert.Equal(1UL, group.Epoch);
        Assert.Equal(2u, group.Tree.LeafCount);
    }

    [Fact]
    public void CommitAddMember_WelcomeCanBeProcessed()
    {
        // Alice creates a group
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        // Bob creates a key package
        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        // Alice commits to add Bob
        var addProposals = group.ProposeAdd(new[] { bobKp });
        var (_, welcome) = group.Commit(addProposals);
        group.MergePendingCommit();

        Assert.NotNull(welcome);

        // Bob processes the Welcome
        var bobGroup = MlsGroup.ProcessWelcome(
            _cs, welcome!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        Assert.Equal(group.Epoch, bobGroup.Epoch);
        Assert.Equal(group.GroupId, bobGroup.GroupId);
        Assert.Equal(2u, bobGroup.Tree.LeafCount);
        Assert.Equal(1u, bobGroup.MyLeafIndex); // Bob is leaf 1
    }

    [Fact]
    public void MessageEncryptDecrypt_RoundTrips()
    {
        // Alice creates group and adds Bob
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        var addProposals = aliceGroup.ProposeAdd(new[] { bobKp });
        var (_, welcome) = aliceGroup.Commit(addProposals);
        aliceGroup.MergePendingCommit();

        var bobGroup = MlsGroup.ProcessWelcome(
            _cs, welcome!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        // Alice sends a message
        var plaintext = "Hello Bob!"u8.ToArray();
        var encrypted = aliceGroup.EncryptApplicationMessage(plaintext);

        // Bob decrypts it
        var (decrypted, senderLeaf) = bobGroup.DecryptApplicationMessage(encrypted);
        Assert.Equal(plaintext, decrypted);
        Assert.Equal(0u, senderLeaf); // Alice is leaf 0
    }

    [Fact]
    public void BidirectionalMessages_RoundTrips()
    {
        // Setup: Alice creates group, adds Bob
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        var addProposals = aliceGroup.ProposeAdd(new[] { bobKp });
        var (_, welcome) = aliceGroup.Commit(addProposals);
        aliceGroup.MergePendingCommit();

        var bobGroup = MlsGroup.ProcessWelcome(
            _cs, welcome!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        // Alice sends message
        var msg1 = aliceGroup.EncryptApplicationMessage("Alice says hi"u8.ToArray());
        var (dec1, sender1) = bobGroup.DecryptApplicationMessage(msg1);
        Assert.Equal("Alice says hi"u8.ToArray(), dec1);
        Assert.Equal(0u, sender1);

        // Bob sends message back
        var msg2 = bobGroup.EncryptApplicationMessage("Bob says hello"u8.ToArray());
        var (dec2, sender2) = aliceGroup.DecryptApplicationMessage(msg2);
        Assert.Equal("Bob says hello"u8.ToArray(), dec2);
        Assert.Equal(1u, sender2);
    }

    [Fact]
    public void RemoveMember_ViaCommit_Succeeds()
    {
        // Setup: Alice creates group, adds Bob
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        var addProposals = aliceGroup.ProposeAdd(new[] { bobKp });
        var (_, welcome) = aliceGroup.Commit(addProposals);
        aliceGroup.MergePendingCommit();

        Assert.Equal(2u, aliceGroup.Tree.LeafCount);
        Assert.Equal(2, aliceGroup.GetMembers().Count);

        // Alice removes Bob
        var removeProposal = aliceGroup.ProposeRemove(1); // Bob is leaf 1
        var (commitMsg2, _) = aliceGroup.Commit(new List<Proposal> { removeProposal });
        aliceGroup.MergePendingCommit();

        Assert.Equal(2UL, aliceGroup.Epoch);
        Assert.Single(aliceGroup.GetMembers());
    }

    [Fact]
    public void GetMembers_ReturnsCorrectMembers()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var members = aliceGroup.GetMembers();
        Assert.Single(members);
        Assert.Equal(0u, members[0].leafIndex);
        Assert.Equal("alice"u8.ToArray(), members[0].identity);
    }

    [Fact]
    public void ExportSecret_ProducesCorrectLength()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), sigPriv, sigPub);

        var secret = group.ExportSecret("test-label", "context"u8.ToArray(), 48);
        Assert.Equal(48, secret.Length);
    }

    [Fact]
    public void ExportSecret_IsDeterministic()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), sigPriv, sigPub);

        var s1 = group.ExportSecret("label", "ctx"u8.ToArray(), 32);
        var s2 = group.ExportSecret("label", "ctx"u8.ToArray(), 32);
        Assert.Equal(s1, s2);
    }

    [Fact]
    public void MergePendingCommit_WithNoPending_Throws()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), sigPriv, sigPub);
        Assert.Throws<InvalidOperationException>(() => group.MergePendingCommit());
    }

    [Fact]
    public void ClearPendingCommit_AllowsNewCommit()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), sigPriv, sigPub);

        var (_, _) = group.Commit();
        group.ClearPendingCommit();

        // Should be able to commit again without error
        var (_, _) = group.Commit();
        group.MergePendingCommit();
    }
}

// ================================================================
// LeafNodeTBS Signature Verification Tests
// ================================================================

/// <summary>
/// Tests that DotnetMls leaf node signatures are verifiable using the
/// RFC 9420 §7.2 LeafNodeTBS format (with group_id + leaf_index for commit sources).
/// </summary>
public class LeafNodeSignatureTests
{
    private readonly CipherSuite0x0001 _cs = new();

    /// <summary>
    /// After CreateGroup + Commit (AddMember), the creator's leaf node has
    /// Source=Commit. Its signature must verify against a TBS that includes
    /// both group_id and leaf_index per RFC 9420 §7.2.
    /// </summary>
    [Fact]
    public void CommitSourcedLeafNode_SignatureVerifies_WithLeafIndex()
    {
        // Create a group (creator gets Source=KeyPackage initially)
        var identity = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(identity);
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, identity, sigPriv, sigPub);

        // Commit advances the creator's leaf to Source=Commit
        var (commitMsg, welcome) = group.Commit();
        group.MergePendingCommit();

        // Extract the creator's leaf node (leaf index 0)
        var tree = group.Tree;
        var leaf = tree.GetLeaf(0);
        Assert.NotNull(leaf);
        Assert.Equal(LeafNodeSource.Commit, leaf!.Source);

        // Build LeafNodeTBS per RFC 9420 §7.2 (correct format with leaf_index)
        var groupId = group.GroupId;
        uint leafIndex = 0;

        byte[] tbs = TlsCodec.Serialize(writer =>
        {
            writer.WriteOpaqueV(leaf.EncryptionKey);
            writer.WriteOpaqueV(leaf.SignatureKey);
            leaf.Credential.WriteTo(writer);
            leaf.Capabilities.WriteTo(writer);
            writer.WriteUint8((byte)leaf.Source);

            if (leaf.Source == LeafNodeSource.Commit)
            {
                writer.WriteOpaqueV(leaf.ParentHash);
            }

            writer.WriteVectorV(inner =>
            {
                foreach (var ext in leaf.Extensions)
                    ext.WriteTo(inner);
            });

            // Context: group_id + leaf_index (required for Update/Commit per RFC 9420)
            writer.WriteOpaqueV(groupId);
            writer.WriteUint32(leafIndex);
        });

        bool valid = _cs.VerifyWithLabel(leaf.SignatureKey, "LeafNodeTBS", tbs, leaf.Signature);
        Assert.True(valid,
            "Leaf node signature verification failed. " +
            "RFC 9420 §7.2 requires EncryptionKey (post-Encap), ParentHash, group_id, " +
            "and leaf_index in the LeafNodeTBS for commit-sourced leaf nodes.");
    }

    /// <summary>
    /// After AddMember, the Welcome contains a ratchet tree where the creator's
    /// leaf has Source=Commit. The invitee must be able to verify this signature
    /// using the RFC 9420 TBS format.
    /// </summary>
    [Fact]
    public void Sibling_ClampedForNonFullTree()
    {
        // For 3 leaves: Sibling must use clamped right child
        var cp = TreeMath.Copath(0, 3);
        Assert.True(cp.All(n => n < TreeMath.NodeCount(3)),
            $"Copath contains out-of-bounds node: [{string.Join(",", cp)}]");
        Assert.Equal(new uint[] { 2, 4 }, cp); // Bob, Carol
    }

    [Fact]
    public void Commit_ProducesPrivateMessage_ExistingMembersCanProcess()
    {
        // Setup: Alice creates group, adds Bob and Carol
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(_cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        var (carolSigPriv, carolSigPub) = _cs.GenerateSignatureKeyPair();
        var carolKp = MlsGroup.CreateKeyPackage(_cs, "carol"u8.ToArray(), carolSigPriv, carolSigPub,
            out var carolInitPriv, out var carolHpkePriv);

        // Alice adds Bob
        var addBob = aliceGroup.ProposeAdd(new[] { bobKp });
        var (_, welcomeBob) = aliceGroup.Commit(addBob);
        aliceGroup.MergePendingCommit();
        var bobGroup = MlsGroup.ProcessWelcome(_cs, welcomeBob!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        // Alice adds Carol — Bob must process this commit
        var addCarol = aliceGroup.ProposeAdd(new[] { carolKp });
        var (commitMsg, welcomeCarol) = aliceGroup.Commit(addCarol);
        aliceGroup.MergePendingCommit();

        // Commit should be a PrivateMessage (matching Rust MDK / marmot-ts wire format)
        Assert.IsType<PrivateMessage>(commitMsg);

        // Bob processes the PrivateMessage commit
        bobGroup.ProcessCommit(commitMsg);
        Assert.Equal(aliceGroup.Epoch, bobGroup.Epoch);

        // Carol joins via Welcome
        var carolGroup = MlsGroup.ProcessWelcome(_cs, welcomeCarol!, carolKp, carolInitPriv, carolHpkePriv, carolSigPriv);
        Assert.Equal(aliceGroup.Epoch, carolGroup.Epoch);

        // All three can exchange messages
        var msg = aliceGroup.EncryptApplicationMessage("hello from alice"u8.ToArray());
        var (dec1, _) = bobGroup.DecryptApplicationMessage(msg);
        var (dec2, _) = carolGroup.DecryptApplicationMessage(msg);
        Assert.Equal("hello from alice"u8.ToArray(), dec1);
        Assert.Equal("hello from alice"u8.ToArray(), dec2);
    }

    [Fact]
    public void AddMember_WelcomeTree_LeafSignatureVerifies()
    {
        // Create group with Alice
        var aliceId = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(aliceId);
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, aliceId, aliceSigPriv, aliceSigPub);

        // Generate Bob's KeyPackage
        var bobId = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bobId);
        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(_cs, bobId, bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        // Alice adds Bob
        var (commitMsg, welcome) = aliceGroup.Commit(new List<Proposal>
        {
            new AddProposal(bobKp)
        });
        Assert.NotNull(welcome);
        aliceGroup.MergePendingCommit();

        // Extract Alice's tree and verify her leaf signature
        var tree = aliceGroup.Tree;
        var aliceLeaf = tree.GetLeaf(0);
        Assert.NotNull(aliceLeaf);
        Assert.Equal(LeafNodeSource.Commit, aliceLeaf!.Source);

        var groupId = aliceGroup.GroupId;
        uint aliceLeafIndex = 0;

        byte[] tbs = TlsCodec.Serialize(writer =>
        {
            writer.WriteOpaqueV(aliceLeaf.EncryptionKey);
            writer.WriteOpaqueV(aliceLeaf.SignatureKey);
            aliceLeaf.Credential.WriteTo(writer);
            aliceLeaf.Capabilities.WriteTo(writer);
            writer.WriteUint8((byte)aliceLeaf.Source);
            writer.WriteOpaqueV(aliceLeaf.ParentHash);

            writer.WriteVectorV(inner =>
            {
                foreach (var ext in aliceLeaf.Extensions)
                    ext.WriteTo(inner);
            });

            // RFC 9420 §7.2: group_id + leaf_index for commit-sourced leaf
            writer.WriteOpaqueV(groupId);
            writer.WriteUint32(aliceLeafIndex);
        });

        bool valid = _cs.VerifyWithLabel(aliceLeaf.SignatureKey, "LeafNodeTBS", tbs, aliceLeaf.Signature);
        Assert.True(valid,
            "Welcome tree: Alice's commit-sourced leaf signature failed verification. " +
            "DotnetMls SignLeafNode must include leaf_index in the LeafNodeTBS.");
    }

    /// <summary>
    /// External Commit (RFC 9420 §12.4.3.2): Carol joins Alice's group via a
    /// published GroupInfo (carrying external_pub) without a Welcome.
    /// </summary>
    [Fact]
    public void ExternalCommit_CarolJoinsWithoutWelcome_RoundTrips()
    {
        // Alice creates a group, adds Bob via Welcome (so we have 2 members).
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var alice = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        var (_, welcome) = alice.Commit(alice.ProposeAdd(new[] { bobKp }));
        alice.MergePendingCommit();
        var bob = MlsGroup.ProcessWelcome(
            _cs, welcome!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        // Alice publishes a GroupInfo with external_pub; Carol uses it to join.
        var groupInfo = alice.GetGroupInfo();

        var (carolSigPriv, carolSigPub) = _cs.GenerateSignatureKeyPair();
        var (externalCommit, carol) = MlsGroup.JoinExternal(
            _cs, groupInfo, "carol"u8.ToArray(), carolSigPriv, carolSigPub);

        // Alice and Bob process Carol's external commit.
        alice.ProcessCommit(externalCommit);
        bob.ProcessCommit(externalCommit);

        Assert.Equal(alice.Epoch, carol.Epoch);
        Assert.Equal(bob.Epoch, carol.Epoch);
        Assert.Equal(3u, alice.Tree.LeafCount);
        Assert.Equal(3u, bob.Tree.LeafCount);
        Assert.Equal(3u, carol.Tree.LeafCount);
        Assert.Equal(alice.GroupContext.ConfirmedTranscriptHash, carol.GroupContext.ConfirmedTranscriptHash);
        Assert.Equal(alice.GroupContext.TreeHash, carol.GroupContext.TreeHash);

        // Bidirectional messaging after the external commit.
        var msgFromCarol = carol.EncryptApplicationMessage("hello from carol"u8.ToArray());
        var (aliceGot, _) = alice.DecryptApplicationMessage(msgFromCarol);
        Assert.Equal("hello from carol"u8.ToArray(), aliceGot);

        var msgFromBob = bob.EncryptApplicationMessage("hi carol"u8.ToArray());
        var (carolGot, _) = carol.DecryptApplicationMessage(msgFromBob);
        Assert.Equal("hi carol"u8.ToArray(), carolGot);
    }

    /// <summary>
    /// External Commit cipher-suite mismatch must be rejected.
    /// </summary>
    [Fact]
    public void ExternalCommit_MismatchedCipherSuite_Throws()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var alice = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var groupInfo = alice.GetGroupInfo();
        // Pretend GroupInfo is from a different cipher suite.
        groupInfo.GroupContext.CipherSuite = 0xFFFF;

        var (carolSigPriv, carolSigPub) = _cs.GenerateSignatureKeyPair();
        Assert.Throws<InvalidOperationException>(() =>
            MlsGroup.JoinExternal(
                _cs, groupInfo, "carol"u8.ToArray(), carolSigPriv, carolSigPub));
    }
}
