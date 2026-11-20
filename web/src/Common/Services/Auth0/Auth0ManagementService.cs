using Auth0.ManagementApi;
using Auth0.ManagementApi.Models;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Common.Services.Auth0.Models;

namespace VulWall.Dashboard.Common.Services.Auth0;

public class Auth0ManagementService(
    ILogger<Auth0ManagementService> logger,
    IHttpClientFactory httpClientFactory) : IAuth0ManagementService
{
    internal const string TokenHttpClientName = "Auth0Token";
    internal const string ManagementHttpClientName = "Auth0Management";

    private readonly string _managementDomain = ServiceSettings.Instance.Auth0ManagementDomain;
    private readonly string _clientId = ServiceSettings.Instance.Auth0ClientId;
    private readonly string _clientSecret = ServiceSettings.Instance.Auth0ClientSecret;

    // cache the management API client token (it expires after 24 hours)
    private static string? _cachedToken;
    private static DateTime _tokenExpiresAt = DateTime.MinValue;
    private static readonly SemaphoreSlim TokenLock = new(1, 1);

    public async Task UpdateUserOrgIdAsync(string auth0UserId, string orgId)
    {
        try
        {
            var client = await GetManagementApiClientAsync();

            var request = new UserUpdateRequest
            {
                AppMetadata = new
                {
                    org_id = orgId
                }
            };

            await client.Users.UpdateAsync(auth0UserId, request);
            logger.LogInformation("Updated Auth0 user {UserId} with org_id: {OrgId}", auth0UserId, orgId);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to update Auth0 user {UserId} metadata", auth0UserId);
            throw;
        }
    }

    public async Task<string?> GetUserOrgIdAsync(string auth0UserId)
    {
        try
        {
            var client = await GetManagementApiClientAsync();
            var user = await client.Users.GetAsync(auth0UserId);

            if (user.AppMetadata != null && user.AppMetadata!.ContainsKey("org_id"))
            {
                return user.AppMetadata!["org_id"]?.ToString();
            }

            return null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get Auth0 user {UserId} metadata", auth0UserId);
            return null;
        }
    }

    public async Task DeleteUserAsync(string auth0UserId)
    {
        try
        {
            var client = await GetManagementApiClientAsync();
            await client.Users.DeleteAsync(auth0UserId);
            logger.LogInformation("Deleted Auth0 user {UserId}", auth0UserId);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to delete Auth0 user {UserId}", auth0UserId);
            throw;
        }
    }

    private async Task<ManagementApiClient> GetManagementApiClientAsync()
    {
        var token = await GetAccessTokenAsync();
        var httpClient = httpClientFactory.CreateClient(ManagementHttpClientName);
        var connection = new HttpClientManagementConnection(httpClient);
        return new ManagementApiClient(token, _managementDomain, connection);
    }

    private async Task<string> GetAccessTokenAsync()
    {
        await TokenLock.WaitAsync();
        try
        {
            // Return cached token if still valid
            if (!string.IsNullOrEmpty(_cachedToken) && DateTime.UtcNow < _tokenExpiresAt)
            {
                return _cachedToken;
            }

            // Get new token using client credentials
            var httpClient = httpClientFactory.CreateClient(TokenHttpClientName);
            var tokenRequest = new
            {
                client_id = _clientId,
                client_secret = _clientSecret,
                audience = $"https://{_managementDomain}/api/v2/",
                grant_type = "client_credentials"
            };

            var response = await httpClient.PostAsJsonAsync(
                $"https://{_managementDomain}/oauth/token",
                tokenRequest
            );

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                logger.LogError("Auth0 token request failed. Status: {StatusCode}, Response: {Response}",
                    response.StatusCode, errorContent);
                throw new InvalidOperationException(
                    $"Failed to obtain Auth0 Management API token. Status: {response.StatusCode}, Response: {errorContent}");
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<Auth0TokenResponse>();

            _cachedToken = tokenResponse?.AccessToken ??
                           throw new InvalidOperationException(
                               "Failed to obtain Auth0 Management API token - no access_token in response");

            // Tokens are valid for 24 hours, cache for 23 hours to be safe
            _tokenExpiresAt = DateTime.UtcNow.AddHours(23);

            return _cachedToken;
        }
        finally
        {
            TokenLock.Release();
        }
    }
}
