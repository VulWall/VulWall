using System.Security.Claims;
using VulWall.Dashboard.Common.Contracts.Models;

namespace VulWall.Dashboard.Settings.Models;

public sealed record AccountUserViewModel
{
    public string? FirstName   { get; init; }
    public string? LastName    { get; init; }
    public string? FullName    { get; init; }
    public string? Company     { get; init; }
    public string? Industry    { get; init; }
    public string? Website     { get; init; }
    public string? OwnerEmail  { get; init; }
    public string? OrgId       { get; init; }
    public bool HasLogo        { get; init; }

    public static AccountUserViewModel FromClaims(ClaimsPrincipal user)
    {
        return new AccountUserViewModel
        {
            FirstName = user.FindFirst(ClaimTypes.GivenName)?.Value,
            LastName  = user.FindFirst(ClaimTypes.Surname)?.Value,
            FullName  = user.FindFirst("name")?.Value ?? user.Identity?.Name,
            Company   = null,
            Industry  = null,
            Website   = null,
            OrgId     = null
        };
    }
}