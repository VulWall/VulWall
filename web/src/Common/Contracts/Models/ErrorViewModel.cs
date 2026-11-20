namespace VulWall.Dashboard.Common.Contracts.Models;

public class ErrorViewModel
{
    public string? RequestId { get; set; }
    public int StatusCode { get; set; }
    public string Title { get; set; } = "Error";
    public string Message { get; set; } = "An error occurred while processing your request.";
    public string PrimaryActionText { get; set; } = "Back to Home";
    public string PrimaryActionHref { get; set; } = "/";
    public string? Details { get; set; }
    public bool IsDevelopment { get; set; }

    public static ErrorViewModel FromStatusCode(int statusCode)
    {
        return statusCode switch
        {
            404 => new ErrorViewModel
            {
                StatusCode = 404,
                Title = "Page Not Found",
                Message = "The page you're looking for doesn't exist or has been moved."
            },
            403 => new ErrorViewModel
            {
                StatusCode = 403,
                Title = "Access Denied",
                Message = "You don't have permission to access this resource."
            },
            401 => new ErrorViewModel
            {
                StatusCode = 401,
                Title = "Unauthorized",
                Message = "You need to log in to access this page."
            },
            500 => new ErrorViewModel
            {
                StatusCode = 500,
                Title = "Internal Server Error",
                Message = "Something went wrong on our end. We're working to fix it."
            },
            _ => new ErrorViewModel
            {
                StatusCode = statusCode,
                Title = "Error",
                Message = "An unexpected error occurred."
            }
        };
    }
}
