var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => new
{
    App = "apm-demo-app-003",
    Framework = "ASP.NET 8",
    Description = "APM Security Demo — MCP Configuration Violations"
});

app.MapGet("/health", () => new { Status = "healthy" });

app.Run();
