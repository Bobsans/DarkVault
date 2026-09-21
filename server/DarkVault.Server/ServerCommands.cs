using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using DarkVault.Client;

namespace DarkVault.Server;

public static class ServerCommands {
    public static async Task<int> RunAsync(string[] args) {
        try {
            if (args is ["--version"]) {
                Console.WriteLine(typeof(ServerCommands).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                    .Cast<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion);
                return 0;
            }
            if (args.Contains("--help")) {
                Console.WriteLine("""
                    DarkVault
                    --version prints the build version and commit without opening the data directory.
                    Commands: serve (default), bootstrap, reset-password, reset-mfa, verify, rotate-data,
                      rotate-transport [--emergency], backup <new-directory>,
                      create-wrapping-key <new-file>, protect-keyring
                    DARKVAULT_DATA: private directory (default: ./data)
                    ASPNETCORE_URLS: listen URL (default: http://127.0.0.1:8866 behind trusted HTTPS proxy)
                    DARKVAULT_TRUSTED_PROXIES: comma-separated IPs (default: no trusted proxies)
                    DARKVAULT_PUBLIC_ORIGIN: canonical HTTPS origin for WebAuthn (optional)
                    DARKVAULT_KEYRING_KEY_FILE: private wrapping-key file outside DARKVAULT_DATA
                    bootstrap/reset-password read a password without echo from the local terminal.
                    """); return 0;
            }
            var command = args.FirstOrDefault() ?? "serve";
            if (command == "create-wrapping-key") {
                if (args.Length != 2) throw new ArgumentException("Specify a new private wrapping-key file outside the data directory.");
                var generated = RandomNumberGenerator.GetBytes(32);
                try { KeyRing.SavePrivate(args[1], Convert.ToBase64String(generated), overwrite: false); } finally { CryptographicOperations.ZeroMemory(generated); }
                Console.WriteLine("Wrapping key created. Keep a separate secure backup; losing it loses access to the vault."); return 0;
            }
            var directory = Path.GetFullPath(Environment.GetEnvironmentVariable("DARKVAULT_DATA") ?? "data"); SecureDirectory(directory);
            using var processLock = new FileStream(Path.Combine(directory, "server.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var database = Path.Combine(directory, "vault.db"); var keys = Path.Combine(directory, "keyring.json");
            SecureFile(database); SecureFile(keys);
            var wrappingFile = Environment.GetEnvironmentVariable("DARKVAULT_KEYRING_KEY_FILE");
            byte[]? wrappingKey = null;
            if (!string.IsNullOrEmpty(wrappingFile)) {
                var relative = Path.GetRelativePath(directory, Path.GetFullPath(wrappingFile));
                if (!Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar)) throw new InvalidOperationException("Keep the wrapping key outside the vault data directory.");
                if (new FileInfo(wrappingFile).Length > 1024) throw new InvalidOperationException("Invalid wrapping-key file.");
                wrappingKey = Convert.FromBase64String(File.ReadAllText(wrappingFile).Trim());
            }
            KeyRing ring;
            try { ring = new KeyRing(keys, !File.Exists(database), wrappingKey); } finally { if (wrappingKey is not null) CryptographicOperations.ZeroMemory(wrappingKey); }
            using var ringLifetime = ring;
            using var store = new VaultStore(database, ring);
            switch (command) {
                case "bootstrap":
                case "reset-password":
                    var password = ReadPassword("Administrator password: ");
                    if (ReadPassword("Repeat password: ") != password) throw new InvalidOperationException("Passwords differ.");
                    store.SetPassword(password, command == "reset-password"); Console.WriteLine("Administrator configured."); return 0;
                case "verify": store.Verify(); Console.WriteLine("Database and keyring verified."); return 0;
                case "protect-keyring": ring.Protect(); store.Verify(); Console.WriteLine("Keyring protected. Back up the wrapping key separately."); return 0;
                case "reset-mfa":
                    if (store.Login(ReadPassword("Current administrator password: ")) is null) throw new InvalidOperationException("Authentication failed.");
                    store.ResetMfa(); Console.WriteLine("MFA reset. Register a passkey on the next administrator login."); return 0;
                case "rotate-data": store.Reencrypt(); store.Verify(); Console.WriteLine("Data keys rotated and values verified."); return 0;
                case "rotate-transport": ring.RotateTransport(args.Contains("--emergency")); Console.WriteLine("Transport key rotated."); return 0;
                case "backup":
                    if (args.Length != 2 || Directory.Exists(args[1])) throw new ArgumentException("Specify a new backup directory.");
                    SecureDirectory(args[1]);
                    var backupDatabase = Path.Combine(args[1], "vault.db"); store.Backup(backupDatabase); SecureFile(backupDatabase);
                    KeyRing.SavePrivate(Path.Combine(args[1], "keyring.json"), File.ReadAllText(keys));
                    Console.WriteLine("Backup completed. Rotate the data key before writing after a restore."); return 0;
                case "serve":
                    if (store.Administrator is null) throw new InvalidOperationException("Run bootstrap locally before starting the server.");
                    var app = VaultApplication.Build([], store, ring, directory);
                    if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ASPNETCORE_URLS"))) app.Urls.Add("http://127.0.0.1:8866");
                    await app.RunAsync(); return 0;
                default: throw new ArgumentException("Unknown command. Use --help.");
            }
        } catch (Exception ex) {
            // Never print input values or exception details that may contain credentials.
            Console.Error.WriteLine($"DarkVault failed ({ex.GetType().Name}). Check configuration, permissions and --help."); return 1;
        }
    }
    public static void SecureDirectory(string path) {
        path = Path.GetFullPath(path);
        if (path == Path.GetPathRoot(path) || (Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any() && !File.Exists(Path.Combine(path, "keyring.json"))))
            throw new InvalidOperationException("Use an empty directory or an existing DarkVault installation.");
        Directory.CreateDirectory(path);
        if (OperatingSystem.IsWindows()) {
            var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
        } else File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    public static void SecureFile(string path) {
        path = Path.GetFullPath(path);
        if (!File.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Vault data files cannot be symbolic links.");
        if (OperatingSystem.IsWindows()) {
            var security = new FileSecurity(); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        } else File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    private static string ReadPassword(string label) {
        if (Console.IsInputRedirected) throw new InvalidOperationException("An interactive terminal is required.");
        Console.Write(label); var text = new StringBuilder();
        while (true) {
            var k = Console.ReadKey(true); if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); return text.ToString(); }
            if (k.Key == ConsoleKey.Backspace) { if (text.Length > 0) text.Length--; } else if (!char.IsControl(k.KeyChar) && text.Length < 4096) text.Append(k.KeyChar);
        }
    }
}
