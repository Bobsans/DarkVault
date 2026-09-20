using DarkVault.Server;
using NUnit.Framework;

namespace DarkVault.Server.Tests;

public sealed class VersionTests {
    [Test]
    public async Task VersionDoesNotOpenDataDirectory() {
        var previous = Environment.GetEnvironmentVariable("DARKVAULT_DATA");
        var directory = Path.Combine(Path.GetTempPath(), "darkvault-version-" + Guid.NewGuid());
        try {
            Environment.SetEnvironmentVariable("DARKVAULT_DATA", directory);
            Assert.That(await ServerCommands.RunAsync(["--version"]), Is.Zero);
            Assert.That(Directory.Exists(directory), Is.False);
        } finally { Environment.SetEnvironmentVariable("DARKVAULT_DATA", previous); }
    }
}
