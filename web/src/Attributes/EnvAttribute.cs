namespace VulWall.Dashboard.Attributes;

[AttributeUsage(AttributeTargets.Field)]
public class EnvAttribute : Attribute
{
    public string? Name { get; set; }
    public string? Default { get; set; }
    public bool Required { get; set; }
}
