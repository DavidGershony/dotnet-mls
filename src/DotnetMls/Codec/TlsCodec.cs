namespace DotnetMls.Codec;

/// <summary>
/// Static helper for one-shot TLS serialization.
/// </summary>
public static class TlsCodec
{
    /// <summary>
    /// Serializes data by invoking the provided action on a temporary <see cref="TlsWriter"/>
    /// and returning the resulting byte array.
    /// </summary>
    /// <param name="writeAction">An action that writes data to the <see cref="TlsWriter"/>.</param>
    /// <returns>A byte array containing the serialized data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="writeAction"/> is null.</exception>
    public static byte[] Serialize(Action<TlsWriter> writeAction)
    {
        ArgumentNullException.ThrowIfNull(writeAction);

        using var writer = new TlsWriter();
        writeAction(writer);
        return writer.ToArray();
    }
}
