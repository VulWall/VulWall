namespace VulWall.Dashboard.Settings.Models;

public class PaymentMethodInfo
{
    public string Last4 { get; set; } = string.Empty;
    public string Brand { get; set; } = string.Empty;
    public long ExpiryMonth { get; set; }
    public long ExpiryYear { get; set; }
}
