using System.Text.RegularExpressions;
using Microsoft.AspNetCore.HttpOverrides;
using VulWall.Dashboard.Middleware;

namespace VulWall.Dashboard.Extensions;

public static partial class WebApplicationExtensions
{
    [GeneratedRegex(@"^/[Cc]erts/[a-fA-F0-9]{24}/embed$")]
    private static partial Regex CertEmbedPathRegex();

    public static void ConfigureDashboardPipeline(this WebApplication app)
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            ForwardLimit = 1
        };
        // Railway terminates TLS and forwards as HTTP with X-Forwarded-Proto/For headers.
        // Clear restrictions so Railway's proxy IP is trusted (ForwardLimit=1 prevents spoofing).
        forwardedHeadersOptions.KnownProxies.Clear();
        forwardedHeadersOptions.KnownNetworks.Clear();
        app.UseForwardedHeaders(forwardedHeadersOptions);

        app.Use(async (context, next) =>
        {
            var isEmbedRoute = context.Request.Path.Value != null &&
                CertEmbedPathRegex().IsMatch(context.Request.Path.Value);

            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";

            var frameAncestors = isEmbedRoute
                ? "frame-ancestors *"
                : "frame-ancestors 'self'";

            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; " +
                "script-src 'self' https://cdn.jsdelivr.net https://js.stripe.com; " +
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
                "img-src 'self' data: https://assets.vulwall.com; " +
                "frame-src 'self' https://js.stripe.com; " +
                "connect-src 'self'; " +
                "base-uri 'self'; " +
                "form-action 'self'; " +
                frameAncestors;

            if (isEmbedRoute)
                context.Response.Headers.Remove("X-Frame-Options");

            await next();
        });

        app.UseExceptionHandler("/Error");
        app.UseStatusCodePagesWithReExecute("/Error/{0}");
        
        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseHealthChecks("/health");
        app.MapStaticAssets();
        app.UseRouting();

        app.UseSession();
        app.UseAuthentication();
        app.UseAuthorization();

        // Log successful logins (must be after UseAuthentication)
        app.UseMiddleware<LoginAuditMiddleware>();

        // Create an org for authenticated users who don't have one yet
        app.UseMiddleware<EnsureOrganizationMiddleware>();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Dashboard}/{action=Index}/{id?}");
    }
}