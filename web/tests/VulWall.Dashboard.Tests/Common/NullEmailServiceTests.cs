using Microsoft.Extensions.Logging.Abstractions;
using VulWall.Dashboard.Common.Services.Email;

namespace VulWall.Dashboard.Tests.Common;

public class NullEmailServiceTests
{
    [Fact]
    public async Task SendTemplateAsync_ReportsNotSent()
    {
        var service = new NullEmailService(NullLogger<NullEmailService>.Instance);

        var sent = await service.SendTemplateAsync("owner@example.com", EmailTemplate.ScanComplete, new Dictionary<string, object>());

        Assert.False(sent);
    }
}
