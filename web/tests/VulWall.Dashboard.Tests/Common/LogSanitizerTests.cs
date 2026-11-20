using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Tests.Common;

public class LogSanitizerTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("/assets/42", "/assets/42")]
    [InlineData("/caf\x00e9/\U0001F600", "/caf\x00e9/\U0001F600")] // printable non-ASCII and emoji stay
    [InlineData("/a\nFirst-run setup", "/a?First-run setup")]
    [InlineData("/a\r\nb", "/a??b")]
    [InlineData("/x\u001b]8;;https://evil/\u0007y", "/x?]8;;https://evil/?y")]
    [InlineData("/x\u009by", "/x?y")]          // C1 control (CSI)
    [InlineData("/x\x200Ey", "/x?y")]          // format char (LRM)
    [InlineData("/x\x2028y\x2029z", "/x?y?z")] // line and paragraph separators
    public void Clean_ReplacesUnsafeCharacters(string? input, string expected) =>
        Assert.Equal(expected, LogSanitizer.Clean(input));

    [Fact]
    public void Clean_ReplacesLoneSurrogate() =>
        // Not an [InlineData] case: attribute arguments are stored as UTF-8, which cannot hold a lone surrogate.
        Assert.Equal("/x?y", LogSanitizer.Clean("/x\ud800y"));

    [Fact]
    public void Clean_TruncatesLongValues()
    {
        var result = LogSanitizer.Clean("/" + new string('a', 1000));

        Assert.Equal(LogSanitizer.MaxLength + 3, result.Length);
        Assert.EndsWith("...", result);
    }

    [Fact]
    public void Clean_KeepsValueAtMaxLength()
    {
        var value = new string('a', LogSanitizer.MaxLength);
        Assert.Equal(value, LogSanitizer.Clean(value));
    }
}
