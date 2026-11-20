namespace VulWall.Dashboard.Data.Abstractions;

public interface IEntity<TId>
{
    TId Id { get; set; }
}
