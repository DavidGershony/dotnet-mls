namespace DotnetMls.Codec;

/// <summary>
/// Exception thrown when TLS deserialization encounters malformed or invalid data.
/// </summary>
public sealed class TlsDecodingException : Exception
{
    /// <summary>
    /// Initializes a new instance of <see cref="TlsDecodingException"/> with a message.
    /// </summary>
    /// <param name="message">A description of the decoding error.</param>
    public TlsDecodingException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="TlsDecodingException"/> with a message and inner exception.
    /// </summary>
    /// <param name="message">A description of the decoding error.</param>
    /// <param name="innerException">The exception that caused this decoding error.</param>
    public TlsDecodingException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
