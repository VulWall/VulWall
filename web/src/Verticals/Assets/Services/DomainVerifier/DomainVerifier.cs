using System.Security.Cryptography;
using System.Text;
using DnsClient;
using VulWall.Dashboard.Assets.Constants;

namespace VulWall.Dashboard.Assets.Services.DomainVerifier;

public class DomainVerifier(ILogger<DomainVerifier> logger,
    ILookupClient dnsClient) : IDomainVerifier
{
    public string GenerateVerificationToken(string domainName, string orgId)
    {
        // Create a deterministic token based on the domain and organization
        // Each organization gets a unique token for the same domain
        var dataToHash = $"{domainName}:{orgId}";

        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));
        // Convert to a URL-safe base64 string
        var  base64Hash = Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");

        // Take first 32 characters for a reasonable token length
        return base64Hash.Substring(0, Math.Min(32, base64Hash.Length));
    }

    public async Task<bool> VerifyDomain(string domain, string orgId)
    {
        try
        {
            // Construct the full DNS query name for the TXT record
            var txtRecordFullName = $"{Consts.TxtRecordName}.{domain}";
            var expectedToken = GenerateVerificationToken(domain, orgId);

            var result = await dnsClient.QueryAsync(txtRecordFullName, QueryType.TXT);
            var txtRecords = result.Answers.TxtRecords().ToList();

            foreach (var record in txtRecords)
            {
                // Check each text value in the TXT record
                foreach (var text in record.Text)
                {
                    if (text == expectedToken)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, $"Error verifying domain TXT records for {domain}");
            return false;
        }
    }
}