using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VulWall.Dashboard.Common;

namespace VulWall.Dashboard.Tests.Common;

public class ErrorControllerTests
{
    private const string InjectedPath =
        "/a First-run setup http://localhost:1/setup?token=AAA\u001b]8;;https://evil/\u0007\nfake line";

    [Fact]
    public void HandleStatusCode_404_LogsAtDebugWithSanitizedPath()
    {
        var logger = new CapturingLogger();
        var controller = CreateController(logger, InjectedPath);

        controller.HandleStatusCode(404);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Debug, entry.Level);
        AssertSafe(entry.Message);
        Assert.Contains("/a First-run setup http://localhost:1/setup?token=AAA?]8;;https://evil/??fake line", entry.Message);
    }

    [Fact]
    public void HandleStatusCode_Non404_LogsAtWarningWithSanitizedPath()
    {
        var logger = new CapturingLogger();
        var controller = CreateController(logger, InjectedPath);

        controller.HandleStatusCode(400);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        AssertSafe(entry.Message);
    }

    [Fact]
    public void Index_StatusCode404_LogsAtDebugWithSanitizedPath()
    {
        var logger = new CapturingLogger();
        var controller = CreateController(logger, InjectedPath);
        controller.Response.StatusCode = 404;

        controller.Index();

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Debug, entry.Level);
        AssertSafe(entry.Message);
    }

    [Fact]
    public void Index_UnhandledException_LogsErrorWithSanitizedPath()
    {
        var logger = new CapturingLogger();
        var controller = CreateController(logger, originalPath: null);
        controller.HttpContext.Features.Set<IExceptionHandlerFeature>(new ExceptionHandlerFeature
        {
            Error = new InvalidOperationException("boom"),
            Path = InjectedPath,
        });
        controller.Response.StatusCode = 500;

        controller.Index();

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, entry.Level);
        AssertSafe(entry.Message);
    }

    private static void AssertSafe(string message) =>
        Assert.DoesNotContain(message, c => char.IsControl(c));

    private static ErrorController CreateController(CapturingLogger logger, string? originalPath)
    {
        var httpContext = new DefaultHttpContext();
        if (originalPath != null)
        {
            httpContext.Features.Set<IStatusCodeReExecuteFeature>(new StatusCodeReExecuteFeature
            {
                OriginalPath = originalPath,
                OriginalPathBase = string.Empty,
            });
        }

        return new ErrorController(logger, new StubHostEnvironment())
        {
            ControllerContext = new ControllerContext { HttpContext = httpContext },
        };
    }

    private sealed class StubHostEnvironment : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "test";
        public string WebRootPath { get; set; } = string.Empty;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class CapturingLogger : ILogger<ErrorController>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
