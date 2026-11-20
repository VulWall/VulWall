using System.ComponentModel.DataAnnotations;

namespace VulWall.Dashboard.Assets.Validation;

public class RequiredIfAttribute(string property, object targetValue) : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        var dependentProperty = validationContext.ObjectType.GetProperty(property);
        if (dependentProperty == null)
        {
            return new ValidationResult($"Unknown property: {property}");
        }

        var dependentValue = dependentProperty.GetValue(validationContext.ObjectInstance);

        if (dependentValue?.Equals(targetValue) != true)
        {
            return ValidationResult.Success;
        }
        
        if (value == null || (value is string str && string.IsNullOrWhiteSpace(str)))
        {
            return new ValidationResult(ErrorMessage ?? $"{validationContext.DisplayName} is required");
        }

        return ValidationResult.Success;
    }
}
