using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Contracts.Models;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Common;

public class ErrorController(ILogger<ErrorController> logger, IWebHostEnvironment environment)
    : Controller
{
    [Route("/Error")]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Index()
    {
        var exceptionFeature = HttpContext.Features.Get<IExceptionHandlerFeature>();
        var statusCodeFeature = HttpContext.Features.Get<IStatusCodeReExecuteFeature>();

        var statusCode = Response.StatusCode;
        // Activity.Id can come from the client's traceparent header.
        var requestId = LogSanitizer.Clean(Activity.Current?.Id ?? HttpContext.TraceIdentifier);
        var originalPath = LogSanitizer.Clean(
            statusCodeFeature?.OriginalPath ?? exceptionFeature?.Path ?? HttpContext.Request.Path.ToString());

        var model = ErrorViewModel.FromStatusCode(statusCode);
        model.RequestId = requestId;
        model.IsDevelopment = environment.IsDevelopment();

        // Add exception details in development mode
        if (environment.IsDevelopment() && exceptionFeature?.Error != null)
        {
            model.Details = exceptionFeature.Error.ToString();
        }

        // Log the error
        if (exceptionFeature?.Error != null)
        {
            logger.LogError(
                exceptionFeature.Error,
                "Unhandled exception. StatusCode: {StatusCode}, RequestId: {RequestId}, Path: {Path}",
                statusCode,
                requestId,
                originalPath
            );
        }
        else
        {
            logger.Log(
                statusCode == StatusCodes.Status404NotFound ? LogLevel.Debug : LogLevel.Warning,
                "Error page displayed. StatusCode: {StatusCode}, RequestId: {RequestId}, Path: {Path}",
                statusCode,
                requestId,
                originalPath
            );
        }

        return View("Error", model);
    }

    [Route("/Error/{statusCode:int}")]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult HandleStatusCode(int statusCode)
    {
        // Activity.Id can come from the client's traceparent header.
        var requestId = LogSanitizer.Clean(Activity.Current?.Id ?? HttpContext.TraceIdentifier);
        var statusCodeFeature = HttpContext.Features.Get<IStatusCodeReExecuteFeature>();
        var originalPath = LogSanitizer.Clean(statusCodeFeature?.OriginalPath ?? HttpContext.Request.Path.ToString());

        // Create error view model
        var model = ErrorViewModel.FromStatusCode(statusCode);
        model.RequestId = requestId;
        model.IsDevelopment = environment.IsDevelopment();

        // Anyone can request a missing page, so 404s stay out of the default log level.
        logger.Log(
            statusCode == StatusCodes.Status404NotFound ? LogLevel.Debug : LogLevel.Warning,
            "Status code error. StatusCode: {StatusCode}, RequestId: {RequestId}, Path: {Path}",
            statusCode,
            requestId,
            originalPath
        );

        return View("Error", model);
    }

}
