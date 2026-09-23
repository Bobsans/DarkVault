using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);
await builder.Configuration.AddFromDarkVaultAsync();

var app = builder.Build();
// Use builder.Configuration for application services; never return secrets from endpoints.
app.MapGet("/health", () => new { status = "ready" });
await app.RunAsync();
