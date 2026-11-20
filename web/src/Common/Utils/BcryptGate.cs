namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Bounds concurrent BCrypt work to one per core. Login checks are anonymous, and
/// each BCrypt verify burns ~250 ms of CPU, so without a bound a burst of requests starves the
/// whole app. Callers check their rate limit first, so rejected requests never queue here.
/// </summary>
public static class BcryptGate
{
    private static readonly SemaphoreSlim Slots = new(Environment.ProcessorCount, Environment.ProcessorCount);

    public static async Task<bool> VerifyAsync(string password, string hash)
    {
        await Slots.WaitAsync();
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        finally
        {
            Slots.Release();
        }
    }
}
