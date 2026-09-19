# DarkVault.Extensions.Configuration

Load a complete DarkVault bucket once, before application startup (.NET 10).

```csharp
using Microsoft.Extensions.Configuration;

await builder.Configuration.AddFromDarkVaultBucketAsync(
    "https://vault.example.com", token, "app_qa", cancellationToken);
```

The load is atomic: a failed request or case-insensitive key collision adds no provider.
Keys such as ConnectionStrings:Main work without rewriting. Values remain in process memory;
no disk cache or automatic reload is used. Later configuration providers override earlier ones.
An overload accepting an existing DarkVaultClient supports dependency injection and testing.
