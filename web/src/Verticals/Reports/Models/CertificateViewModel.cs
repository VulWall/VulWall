namespace VulWall.Dashboard.Reports.Models;

public record CertificateViewModel
{
    public string OrganizationId { get; init; } = string.Empty;
    public string CompanyName { get; init; } = string.Empty;
    public int SecurityScore { get; init; }
    public string MemberSince { get; init; } = string.Empty;
    public DateTime LastVerified { get; init; }
    public DateTime LastAssessment { get; init; }
    public DateTime ValidUntil { get; init; }
    public DateTime NextReview { get; init; }
    public bool HasLogo { get; init; }
    public string QrCodeSvg { get; init; } = string.Empty;
}
