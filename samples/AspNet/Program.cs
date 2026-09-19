using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);
var server = Environment.GetEnvironmentVariable("DARKVAULT_SERVER") ?? throw new InvalidOperationException("Set DARKVAULT_SERVER.");
var bucket = Environment.GetEnvironmentVariable("DARKVAULT_BUCKET") ?? "app_qa";
var tokenFile = Environment.GetEnvironmentVariable("DARKVAULT_TOKEN_FILE") ?? throw new InvalidOperationException("Set DARKVAULT_TOKEN_FILE.");
var token = (await File.ReadAllTextAsync(tokenFile)).TrimEnd('\r', '\n');
await builder.Configuration.AddFromDarkVaultBucketAsync(server, token, bucket);

var app = builder.Build();
// Use builder.Configuration for application services; never return secrets from endpoints.
app.MapGet("/health", () => new { status = "ready" });
await app.RunAsync();
