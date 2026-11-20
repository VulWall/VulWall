using System.Collections;
using System.Reflection;
using VulWall.Dashboard.Attributes;

namespace VulWall.Dashboard.Common.Utils;

public abstract class EnvLoader
{
    protected EnvLoader()
    {
        var type = GetType();
        var fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.FlattenHierarchy);

        var envVars = Environment.GetEnvironmentVariables()
            .Cast<DictionaryEntry>()
            .ToDictionary(
                entry => entry.Key.ToString()!.ToUpperInvariant(),
                entry => entry.Value?.ToString()
            );

        foreach (var field in fields)
        {
            var attr = field.GetCustomAttribute<EnvAttribute>();
            var envKey = (attr?.Name ?? field.Name).ToUpperInvariant();

            var envValue = envVars.TryGetValue(envKey, out var val) ? val : attr?.Default;
            if (envValue == null)
            {
                if (attr?.Required == true)
                    throw new ArgumentNullException($"Environment variable '{envKey}' is required but not set.");
                continue;
            }

            var isRequired = attr?.Required == true;
            var converted = ConvertValue(envValue, field.FieldType, envKey, isRequired);
            if (converted != null)
                field.SetValue(this, converted);
        }
    }

    private static object? ConvertValue(string raw, Type type, string envKey, bool isRequired)
    {
        try
        {
            if (type == typeof(string)) return raw;
            if (type == typeof(int)) return int.Parse(raw);
            if (type == typeof(bool)) return bool.Parse(raw);
            if (type == typeof(double)) return double.Parse(raw);
        }
        catch (Exception ex)
        {
            if (isRequired)
                throw new InvalidOperationException(
                    $"Environment variable '{envKey}' is required but its value '{raw}' could not be converted to {type.Name}.", ex);

            Console.Error.WriteLine(
                $"[EnvLoader] Warning: could not convert '{envKey}' value '{raw}' to {type.Name}. Field retains its default value.");
        }

        return null;
    }
}
