using Microsoft.AspNetCore.Mvc.Razor;

namespace VulWall.Dashboard.Extensions;

public class VerticalViewLocationExpander : IViewLocationExpander
{
    public void PopulateValues(ViewLocationExpanderContext context) 
    {
        // You can add context values here if needed for caching
    }

    public IEnumerable<string> ExpandViewLocations(ViewLocationExpanderContext context, IEnumerable<string> viewLocations)
    {
        // Custom view locations for vertical slice architecture
        var customLocations = new[]
        {
            // Primary pattern: Verticals/{VerticalName}/Views/{ControllerName}/{ViewName}.cshtml
            "/Verticals/{1}/Views/{1}/{0}.cshtml",
            
            // _ViewStart and _ViewImports files in vertical root
            "/Verticals/{1}/Views/{0}.cshtml",
            
            // Shared views within each vertical
            "/Verticals/{1}/Views/Shared/{0}.cshtml",
            
            // Fallback to root shared views (for _Layout, Error, etc.)
            "/Common/Views/{0}.cshtml",
            "/Common/Views/Shared/{0}.cshtml",
            
            // Explicit partial view patterns
            "/Common/Views/Partial/_{0}.cshtml",
        };

        // Return custom locations first, then fall back to default locations
        return customLocations.Union(viewLocations);
    }
}