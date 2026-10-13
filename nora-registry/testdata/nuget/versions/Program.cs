// NuGet version normal forms as NuGet itself computes them (NuGet.Versioning): for each
// version string, NuGetVersion.ToNormalizedString() and its lowercase (the form NuGet clients
// put in flat-container URLs), or INVALID.
using NuGet.Versioning;
var inputs = File.ReadAllLines(args[0]);
Console.WriteLine($"# NuGet.Versioning {typeof(NuGetVersion).Assembly.GetName().Version}");
foreach (var v in inputs)
{
    if (NuGetVersion.TryParse(v, out var parsed))
    {
        var normal = parsed.ToNormalizedString();
        Console.WriteLine($"{v}\t{normal}\t{normal.ToLowerInvariant()}");
    }
    else
    {
        Console.WriteLine($"{v}\tINVALID\tINVALID");
    }
}
