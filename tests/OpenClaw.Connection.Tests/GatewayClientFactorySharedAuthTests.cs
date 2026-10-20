using System.Reflection;
using OpenClaw.Shared;

namespace OpenClaw.Connection.Tests;

public sealed class GatewayClientFactorySharedAuthTests
{
    [Theory]
    [InlineData(CredentialResolver.SourceSharedGatewayToken, "token", "shared")]
    [InlineData(CredentialResolver.SourceDeviceToken, "deviceToken", "operator-device")]
    public void SelectedSource_DeterminesAuthField_WithoutDeletingIdentity(
        string source, string field, string expected)
    {
        var root = Environment.GetEnvironmentVariable("OPENCLAW_TEST_SCRATCH")
            ?? (OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenClawTestScratch")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "work"));
        var path = Path.Combine(root, "factory-shared-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        try
        {
            var identity = new DeviceIdentity(path);
            identity.Initialize();
            identity.StoreDeviceTokenForRole("operator", "operator-device");
            identity.StoreDeviceTokenForRole("node", "node-device");
            var before = File.ReadAllBytes(Path.Combine(path, "device-key-ed25519.json"));
            using var lifecycle = new GatewayClientFactory().Create("ws://127.0.0.1:18789",
                new GatewayCredential(source == CredentialResolver.SourceSharedGatewayToken ? "shared" : "operator-device",
                    false, source), path, NullLogger.Instance);
            var method = typeof(OpenClawGatewayClient).GetMethod("BuildAuthPayload",
                BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(method);
            var auth = Assert.IsAssignableFrom<IReadOnlyDictionary<string, string>>(
                method.Invoke(lifecycle.DataClient, null));
            Assert.Single(auth);
            Assert.Equal(expected, auth[field]);
            Assert.Equal(before, File.ReadAllBytes(Path.Combine(path, "device-key-ed25519.json")));
            var reloaded = new DeviceIdentity(path);
            reloaded.Initialize();
            Assert.Equal(identity.DeviceId, reloaded.DeviceId);
            Assert.Equal(identity.PublicKeyBase64Url, reloaded.PublicKeyBase64Url);
            Assert.Equal("node-device", reloaded.NodeDeviceToken);
            Assert.Equal("operator-device", reloaded.DeviceToken);
        }
        finally { Directory.Delete(path, recursive: true); }
    }
}
