namespace VulWall.Dashboard.About.Models;

public sealed record VersionRow(string Label, string Value);

/// <summary>Data for the About dialog. <see cref="CopyText"/> is the "Copy system info" block.</summary>
public sealed record AboutInfo(IReadOnlyList<VersionRow> Versions, string CopyText);
