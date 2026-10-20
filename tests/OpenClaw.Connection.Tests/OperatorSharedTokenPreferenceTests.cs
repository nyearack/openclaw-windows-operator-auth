using System.Reflection;
using System.Text.Json;
using OpenClaw.Shared;

namespace OpenClaw.Connection.Tests;

public sealed class OperatorSharedTokenPreferenceTests
{
    // Reflection keeps these tests compilable on the pre-fix revision; absence is a test failure.
    private static PropertyInfo Preference => Assert.IsAssignableFrom<PropertyInfo>(
        typeof(GatewayRecord).GetProperty("PreferSharedTokenForOperator"));

    private static GatewayRecord PreferShared(GatewayRecord record, bool value = true)
    {
        Preference.SetValue(record, value);
        return record;
    }

    [Fact]
    public void LegacyRecords_DefaultToDeviceCredential()
    {
        var record = JsonSerializer.Deserialize<GatewayRecord>(
            """{"Id":"legacy","Url":"wss://gateway.example","SharedGatewayToken":"shared"}""")!;
        Assert.Equal(typeof(bool), Preference.PropertyType);
        Assert.False((bool)Preference.GetValue(record)!);
        var resolver = new CredentialResolver(new IdentityReader());
        Assert.Equal("operator-device", resolver.ResolveOperator(record, "unused")!.Token);
    }

    [Fact]
    public void ExplicitPreference_SelectsSharedWithoutChangingNodePrecedence()
    {
        var record = PreferShared(new GatewayRecord
        {
            Id = "preferred", Url = "wss://gateway.example",
            SharedGatewayToken = "shared", BootstrapToken = "bootstrap"
        });
        var resolver = new CredentialResolver(new IdentityReader());
        var result = resolver.ResolveOperatorDetailed(record, "unused");
        Assert.Equal("shared", result.Credential!.Token);
        Assert.Equal(CredentialResolver.SourceSharedGatewayToken, result.Credential.Source);
        Assert.False(result.Credential.IsBootstrapToken);
        Assert.False(result.FallbackUsed);
        Assert.Equal(GatewayCredentialResolutionStatus.Resolved, result.Status);
        Assert.Equal("shared", resolver.ResolveOperator(record, "unused")!.Token);
        var node = resolver.ResolveNodeDetailed(record, "unused");
        Assert.Equal("node-device", node.Credential!.Token);
        Assert.Equal(CredentialResolver.SourceNodeDeviceToken, node.Credential.Source);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PreferenceWithoutUsableSharedToken_DoesNotDowngradeDevice(string? shared)
    {
        var record = PreferShared(new GatewayRecord
        {
            Id = "no-shared", Url = "wss://gateway.example",
            SharedGatewayToken = shared, BootstrapToken = "bootstrap"
        });
        var result = new CredentialResolver(new IdentityReader()).ResolveOperator(record, "unused");
        Assert.Equal("operator-device", result!.Token);
        Assert.Equal(CredentialResolver.SourceDeviceToken, result.Source);
    }

    [Fact]
    public void PreferenceWithoutAnyToken_RemainsMissing()
    {
        var record = PreferShared(new GatewayRecord { Id = "empty", Url = "wss://gateway.example" });
        var result = new CredentialResolver(new IdentityReader(null, null)).ResolveOperatorDetailed(record, "unused");
        Assert.Null(result.Credential);
        Assert.Equal(GatewayCredentialResolutionStatus.Missing, result.Status);
    }

    [Fact]
    public void Registry_RoundTripsPreferenceOnlyChange_WithUnchangedSharedToken()
    {
        // Never use the real tray data root or RAM-backed /tmp for these fixtures.
        var path = Path.Combine(Environment.GetEnvironmentVariable("OPENCLAW_TEST_SCRATCH")
            ?? (OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenClawTestScratch")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "work")),
            "operator-preference-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        try
        {
            var registry = new GatewayRegistry(path);
            registry.AddOrUpdate(new GatewayRecord
            {
                Id = "saved", Url = "wss://gateway.example", SharedGatewayToken = "unchanged"
            });
            registry.SetActive("saved");
            registry.Save();
            registry.UpdateAndSave("saved", old => PreferShared(old with { }));
            var reloaded = new GatewayRegistry(path);
            reloaded.Load();
            Assert.True((bool)Preference.GetValue(reloaded.GetActive()!)!);
            Assert.Equal("unchanged", reloaded.GetActive()!.SharedGatewayToken);
            reloaded.UpdateAndSave("saved", old => PreferShared(old with { }, false));
            registry.Load();
            Assert.False((bool)Preference.GetValue(registry.GetActive()!)!);
            Assert.Equal("unchanged", registry.GetActive()!.SharedGatewayToken);
        }
        finally { Directory.Delete(path, recursive: true); }
    }

    private sealed class IdentityReader(string? operatorToken = "operator-device", string? nodeToken = "node-device")
        : IDeviceIdentityReader
    {
        public string? TryReadStoredDeviceToken(string dataPath) => operatorToken;
        public string? TryReadStoredNodeDeviceToken(string dataPath) => nodeToken;
    }
}
