using System.Text.Json;
using System.Text.Json.Serialization;

namespace SourceGen;

[JsonSerializable(typeof(Forecast))]
public partial class AppJsonContext : JsonSerializerContext { }

public record Forecast(string Summary, int Temp);

public class Program
{
    public static void Main()
    {
        var f = new Forecast("Hot", 35);
        Console.WriteLine(JsonSerializer.Serialize(f, AppJsonContext.Default.Forecast));
    }
}
