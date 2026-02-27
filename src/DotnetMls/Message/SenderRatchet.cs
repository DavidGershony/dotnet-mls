namespace DotnetMls.Message;

/// <summary>
/// Tracks per-sender generation counters for out-of-order message tolerance
/// in MLS private message decryption.
/// <para>
/// When processing PrivateMessages, messages may arrive out of order. This class
/// validates that a received generation number is:
/// <list type="bullet">
///   <item>Not too far ahead of the expected generation (bounded by <c>maxForwardDistance</c>)</item>
///   <item>Not a duplicate of an already-processed generation</item>
///   <item>Not too far behind the current window (bounded by <c>outOfOrderTolerance</c>)</item>
/// </list>
/// </para>
/// <para>
/// The tolerance window allows a small number of recent generations to be processed
/// out of order without advancing the ratchet beyond recovery.
/// </para>
/// </summary>
public sealed class SenderRatchet
{
    /// <summary>
    /// Per-leaf tracking state: the next expected generation and a set of
    /// generations that have already been seen within the tolerance window.
    /// </summary>
    private sealed class LeafState
    {
        /// <summary>
        /// The lowest generation that has not yet been consumed.
        /// All generations below this are considered consumed.
        /// </summary>
        public uint BaseGeneration;

        /// <summary>
        /// Set of generations within [BaseGeneration, BaseGeneration + outOfOrderTolerance + maxForwardDistance)
        /// that have already been processed. This enables detecting duplicates
        /// when messages arrive out of order.
        /// </summary>
        public readonly HashSet<uint> SeenGenerations = new();
    }

    private readonly Dictionary<uint, LeafState> _leafStates = new();
    private readonly int _maxForwardDistance;
    private readonly int _outOfOrderTolerance;

    /// <summary>
    /// Initializes a new SenderRatchet with the specified forward distance
    /// and out-of-order tolerance limits.
    /// </summary>
    /// <param name="maxForwardDistance">
    /// The maximum number of generations a message can be ahead of the current
    /// expected generation before it is rejected. This bounds how far the
    /// secret tree ratchet must advance to process a single message.
    /// Default: 1000.
    /// </param>
    /// <param name="outOfOrderTolerance">
    /// The number of recent generations that are retained in the seen-set
    /// to allow out-of-order delivery. Messages with generations older than
    /// (baseGeneration - outOfOrderTolerance) are rejected. However, since
    /// baseGeneration itself represents the earliest unconsumed generation,
    /// in practice this controls how many "gaps" below the highest seen
    /// generation are tolerated. Default: 5.
    /// </param>
    public SenderRatchet(int maxForwardDistance = 1000, int outOfOrderTolerance = 5)
    {
        if (maxForwardDistance < 0)
            throw new ArgumentOutOfRangeException(nameof(maxForwardDistance),
                "Maximum forward distance must be non-negative.");
        if (outOfOrderTolerance < 0)
            throw new ArgumentOutOfRangeException(nameof(outOfOrderTolerance),
                "Out-of-order tolerance must be non-negative.");

        _maxForwardDistance = maxForwardDistance;
        _outOfOrderTolerance = outOfOrderTolerance;
    }

    /// <summary>
    /// Validates a generation number for a given leaf and records it as seen.
    /// <para>
    /// A generation is considered valid if:
    /// <list type="bullet">
    ///   <item>It has not already been seen (no duplicates)</item>
    ///   <item>It is not more than <c>maxForwardDistance</c> generations ahead of the base</item>
    ///   <item>It is not below the base generation (already consumed)</item>
    /// </list>
    /// After validation, the generation is recorded. If the generation equals the
    /// current base, the base is advanced past any contiguous run of seen generations,
    /// and old entries are pruned from the seen-set.
    /// </para>
    /// </summary>
    /// <param name="leafIndex">The leaf index of the sender.</param>
    /// <param name="generation">The generation number from the decrypted sender data.</param>
    /// <returns>
    /// True if the generation is valid and was successfully recorded.
    /// False if the generation is a duplicate, too far ahead, or already consumed.
    /// </returns>
    public bool ValidateAndAdvance(uint leafIndex, uint generation)
    {
        var state = GetOrCreateState(leafIndex);

        // Reject generations that have already been consumed (below base)
        if (generation < state.BaseGeneration)
            return false;

        // Reject generations that are too far ahead
        if (generation - state.BaseGeneration > (uint)_maxForwardDistance)
            return false;

        // Reject duplicates
        if (state.SeenGenerations.Contains(generation))
            return false;

        // Record this generation
        state.SeenGenerations.Add(generation);

        // If this generation is at the base, advance the base past contiguous seen entries
        if (generation == state.BaseGeneration)
        {
            AdvanceBase(state);
        }

        return true;
    }

    /// <summary>
    /// Gets the current base generation for a leaf. This is the lowest generation
    /// that has not yet been consumed. Returns 0 for leaves that have not been seen.
    /// </summary>
    /// <param name="leafIndex">The leaf index to query.</param>
    /// <returns>The current base generation for the specified leaf.</returns>
    public uint GetGeneration(uint leafIndex)
    {
        if (_leafStates.TryGetValue(leafIndex, out var state))
            return state.BaseGeneration;

        return 0;
    }

    /// <summary>
    /// Advances the base generation past any contiguous run of seen generations
    /// and prunes old entries from the seen-set.
    /// </summary>
    private void AdvanceBase(LeafState state)
    {
        while (state.SeenGenerations.Contains(state.BaseGeneration))
        {
            state.SeenGenerations.Remove(state.BaseGeneration);
            state.BaseGeneration++;
        }

        // Prune any entries that fell below the new base (defensive cleanup)
        PruneOldEntries(state);
    }

    /// <summary>
    /// Removes entries from the seen-set that are below the base generation.
    /// This is a defensive measure to prevent the set from growing unbounded
    /// in edge cases.
    /// </summary>
    private static void PruneOldEntries(LeafState state)
    {
        state.SeenGenerations.RemoveWhere(g => g < state.BaseGeneration);
    }

    /// <summary>
    /// Gets or creates the tracking state for a given leaf index.
    /// </summary>
    private LeafState GetOrCreateState(uint leafIndex)
    {
        if (!_leafStates.TryGetValue(leafIndex, out var state))
        {
            state = new LeafState();
            _leafStates[leafIndex] = state;
        }
        return state;
    }
}
