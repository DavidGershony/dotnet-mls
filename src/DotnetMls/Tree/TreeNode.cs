using DotnetMls.Types;

namespace DotnetMls.Tree;

/// <summary>
/// Represents a node in the ratchet tree.
/// A tree node is either a Leaf or a Parent.
/// A null <see cref="TreeNode"/> value in the tree means the slot is blank (unoccupied).
/// </summary>
public abstract class TreeNode
{
    private TreeNode() { }

    /// <summary>
    /// A leaf node in the ratchet tree. A null <see cref="Value"/> means the leaf is blank.
    /// </summary>
    public sealed class Leaf : TreeNode
    {
        /// <summary>
        /// The leaf node data, or null if this leaf is blank.
        /// </summary>
        public LeafNode? Value { get; set; }

        public Leaf() { }

        public Leaf(LeafNode? value)
        {
            Value = value;
        }

        /// <summary>
        /// Creates a deep copy of this leaf node.
        /// Note: LeafNode is treated as a reference-shared object during clone
        /// since it is replaced wholesale during tree operations.
        /// For a full deep copy of the leaf data, the caller should clone the LeafNode separately.
        /// </summary>
        public Leaf Clone()
        {
            // LeafNode is relatively complex; for tree operations it is replaced,
            // not mutated, so sharing the reference is safe.
            return new Leaf(Value);
        }
    }

    /// <summary>
    /// A parent (interior) node in the ratchet tree. A null <see cref="Value"/> means the parent is blank.
    /// </summary>
    public sealed class Parent : TreeNode
    {
        /// <summary>
        /// The parent node data, or null if this parent is blank.
        /// </summary>
        public ParentNode? Value { get; set; }

        public Parent() { }

        public Parent(ParentNode? value)
        {
            Value = value;
        }

        /// <summary>
        /// Creates a deep copy of this parent node.
        /// </summary>
        public Parent Clone()
        {
            return new Parent(Value?.Clone());
        }
    }
}
