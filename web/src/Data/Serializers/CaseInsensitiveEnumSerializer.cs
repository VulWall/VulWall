using MongoDB.Bson;
using MongoDB.Bson.Serialization;

namespace VulWall.Dashboard.Data.Serializers;

/// <summary>
/// MongoDB BSON serializer that handles case-insensitive enum deserialization.
/// Allows enum values to be stored in lowercase but deserialized regardless of case.
/// </summary>
/// <typeparam name="TEnum">The enum type to serialize/deserialize</typeparam>
/// <param name="aliases">Extra stored values that map to an enum member (case-insensitive).</param>
public class CaseInsensitiveEnumSerializer<TEnum>(IReadOnlyDictionary<string, TEnum>? aliases = null)
    : MongoDB.Bson.Serialization.Serializers.SerializerBase<TEnum>
    where TEnum : struct, Enum
{
    public override TEnum Deserialize(BsonDeserializationContext context, BsonDeserializationArgs args)
    {
        var type = context.Reader.CurrentBsonType;

        if (type == BsonType.String)
        {
            var value = context.Reader.ReadString();
            if (aliases != null)
            {
                foreach (var (alias, mapped) in aliases)
                {
                    if (string.Equals(alias, value, StringComparison.OrdinalIgnoreCase))
                        return mapped;
                }
            }

            return Enum.TryParse<TEnum>(value, ignoreCase: true, out var result)
                ? result
                : throw new FormatException($"Cannot parse '{value}' to enum type {typeof(TEnum).Name}");
        }

        throw new FormatException($"Cannot deserialize BsonType {type} to enum type {typeof(TEnum).Name}");
    }

    public override void Serialize(BsonSerializationContext context, BsonSerializationArgs args, TEnum value)
    {
        context.Writer.WriteString(value.ToString().ToLowerInvariant());
    }
}
