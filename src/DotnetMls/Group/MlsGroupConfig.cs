namespace DotnetMls.Group;

/// <summary>
/// Configuration options for an MLS group (RFC 9420).
/// Controls message padding, out-of-order tolerance, and forward distance limits.
/// </summary>
public sealed class MlsGroupConfig
{
    /// <summary>
    /// The maximum number of generations a message can be received out of order.
    /// Messages beyond this tolerance window are rejected.
    /// </summary>
    public int OutOfOrderTolerance { get; init; } = 5;

    /// <summary>
    /// The maximum forward distance (in generations) for message processing.
    /// Prevents denial-of-service by limiting how far a ratchet can be advanced.
    /// </summary>
    public int MaxForwardDistance { get; init; } = 1000;

    /// <summary>
    /// Padding bytes appended to encrypted messages.
    /// Can be used to obscure message lengths for traffic analysis resistance.
    /// </summary>
    public byte[] Padding { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// Returns a default configuration.
    /// </summary>
    public static MlsGroupConfig Default => new();
}
