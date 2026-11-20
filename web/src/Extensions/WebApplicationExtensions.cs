using Microsoft.AspNetCore.HttpOverrides;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Extensions;

public static class WebApplicationExtensions
{
    public static void ConfigureDashboardPipeline(this WebApplication app)
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            ForwardLimit = 1
        };
        // A reverse proxy is expected to terminate TLS and forward X-Forwarded-Proto/For headers.
        // Only loopback (the framework default) and the TRUSTED_PROXIES ranges are trusted, so a
        // client that reaches the app directly cannot spoof its IP (rate limiting keys on it).
        foreach (var network in TrustedProxies.Parse(ServiceSettings.Instance.TrustedProxies))
            forwardedHeadersOptions.KnownIPNetworks.Add(network);
        app.UseForwardedHeaders(forwardedHeadersOptions);

        app.Use(async (context, next) =>
        {
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";

            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; " +
                "script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data:; " +
                "frame-src 'self'; " +
                "connect-src 'self'; " +
                "base-uri 'self'; " +
                "form-action 'self'; " +
                "frame-ancestors 'self'";

            await next();
        });

        app.UseExceptionHandler("/Error");
        app.UseStatusCodePagesWithReExecute("/Error/{0}");

        // Before the HTTPS redirect so the container healthcheck works over plain HTTP.
        app.UseHealthChecks("/health");

        // Self-hosted installs often run on plain http://localhost. HSTS and the HTTPS redirect
        // are only safe once TLS is in place, so they follow SECURE_COOKIES.
        if (ServiceSettings.Instance.SecureCookies)
        {
            app.UseHsts();
            app.UseHttpsRedirection();
        }

        app.MapStaticAssets();
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Dashboard}/{action=Index}/{id?}");
    }
}