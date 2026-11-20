using VulWall.Dashboard.Assets.Validation;

namespace VulWall.Dashboard.Tests.Assets;

public class EmailDomainMatcherTests
{
    [Fact]
    public void ExactDomainMatch_ImpliesOwnership()
    {
        Assert.True(EmailDomainMatcher.IsOwnershipImpliedByEmail("alice@acme.com", "acme.com"));
    }

    [Fact]
    public void SubdomainOfEmailDomain_ImpliesOwnership()
    {
        Assert.True(EmailDomainMatcher.IsOwnershipImpliedByEmail("x@acme.com", "app.acme.com"));
    }

    [Fact]
    public void DifferentTld_DoesNotImplyOwnership()
    {
        Assert.False(EmailDomainMatcher.IsOwnershipImpliedByEmail("x@acme.io", "acme.com"));
    }

    [Fact]
    public void FreemailSender_DoesNotImplyOwnership()
    {
        Assert.False(EmailDomainMatcher.IsOwnershipImpliedByEmail("bob@gmail.com", "gmail.com"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("notanemail")]
    public void NullOrMalformedEmail_DoesNotImplyOwnership(string? email)
    {
        Assert.False(EmailDomainMatcher.IsOwnershipImpliedByEmail(email, "acme.com"));
    }

    [Fact]
    public void AssetDomainThatMerelyEndsWithEmailDomain_DoesNotImplyOwnership()
    {
        // Anti-substring: "notacme.com" ends with "acme.com" as a string but is a different domain.
        Assert.False(EmailDomainMatcher.IsOwnershipImpliedByEmail("x@acme.com", "notacme.com"));
    }

    [Fact]
    public void MixedCaseEmailAndDomain_ImpliesOwnership()
    {
        Assert.True(EmailDomainMatcher.IsOwnershipImpliedByEmail("Alice@ACME.COM", "acme.com"));
    }

    [Theory]
    [InlineData("alice@")]
    [InlineData("@acme.com")]
    public void EmptyLocalPartOrTrailingAt_DoesNotImplyOwnership(string email)
    {
        Assert.False(EmailDomainMatcher.IsOwnershipImpliedByEmail(email, "acme.com"));
    }

    [Fact]
    public void NewlyBlockedFreemailProvider_DoesNotImplyOwnership()
    {
        Assert.False(EmailDomainMatcher.IsOwnershipImpliedByEmail("x@qq.com", "qq.com"));
    }

    [Fact]
    public void GetOwnableDomain_CorporateEmail_ReturnsDomain()
    {
        Assert.Equal("acme.com", EmailDomainMatcher.GetOwnableDomain("alice@acme.com"));
    }

    [Fact]
    public void GetOwnableDomain_FreemailEmail_ReturnsNull()
    {
        Assert.Null(EmailDomainMatcher.GetOwnableDomain("x@gmail.com"));
    }

    [Fact]
    public void GetOwnableDomain_NullEmail_ReturnsNull()
    {
        Assert.Null(EmailDomainMatcher.GetOwnableDomain(null));
    }

    [Fact]
    public void GetOwnableDomain_NoAtSign_ReturnsNull()
    {
        Assert.Null(EmailDomainMatcher.GetOwnableDomain("notanemail"));
    }

    [Fact]
    public void GetOwnableDomain_EmptyLocalPart_ReturnsNull()
    {
        Assert.Null(EmailDomainMatcher.GetOwnableDomain("@acme.com"));
    }

    [Fact]
    public void GetOwnableDomain_TrailingAt_ReturnsNull()
    {
        Assert.Null(EmailDomainMatcher.GetOwnableDomain("alice@"));
    }

    [Fact]
    public void GetOwnableDomain_SubdomainEmail_ReturnsFullEmailDomain()
    {
        Assert.Equal("sub.corp.com", EmailDomainMatcher.GetOwnableDomain("a@sub.corp.com"));
    }

    [Fact]
    public void GetOwnableDomain_MixedCase_NormalizesToLowercase()
    {
        Assert.Equal("corp.com", EmailDomainMatcher.GetOwnableDomain("Bob@Corp.COM"));
    }

    [Fact]
    public void GetOwnableDomain_SurroundingWhitespaceOnDomain_IsTrimmed()
    {
        // Locks the refactor: the domain part is trimmed before the freemail/match checks.
        Assert.Equal("acme.com", EmailDomainMatcher.GetOwnableDomain("alice@acme.com "));
    }
}
