namespace VulWall.Dashboard.Assets.Services.DomainVerifier;

public interface IDomainVerifier
{
    string GenerateVerificationToken(string domainName, string orgId);
    Task<bool> VerifyDomain(string domain, string orgId);
}