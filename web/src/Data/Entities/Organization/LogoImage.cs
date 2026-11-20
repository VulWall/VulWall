namespace VulWall.Dashboard.Data.Entities.Organization;

/// <summary>The image types a company logo can have, told apart by their magic bytes.</summary>
public static class LogoImage
{
    public const string Png = "image/png";
    public const string Jpeg = "image/jpeg";

    /// <summary>Returns <see cref="Png"/> or <see cref="Jpeg"/> from the file's first bytes, or null for anything else.</summary>
    public static string? Detect(ReadOnlySpan<byte> bytes)
    {
        if (bytes is [0x89, 0x50, 0x4E, 0x47, ..])
            return Png;
        if (bytes is [0xFF, 0xD8, 0xFF, ..])
            return Jpeg;
        return null;
    }
}
