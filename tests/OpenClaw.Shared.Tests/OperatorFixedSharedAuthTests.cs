using System.Net.WebSockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using OpenClaw.Shared;

namespace OpenClaw.Shared.Tests;

public sealed class OperatorFixedSharedAuthTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task SharedAuth_RemainsSelectedAfterIssuedTokenAndReconnect(bool storedOperator, bool v2)
    {
        var root = Environment.GetEnvironmentVariable("OPENCLAW_TEST_SCRATCH")
            ?? (OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenClawTestScratch")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "work"));
        var path = Path.Combine(root, "fixed-shared-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        try
        {
            var identity = new DeviceIdentity(path);
            identity.Initialize();
            if (storedOperator) identity.StoreDeviceTokenForRole("operator", "old-operator");
            identity.StoreDeviceTokenForRole("node", "preserved-node");
            using var server = new LoopbackWebSocketServer(useManagedWebSocket: true);
            await server.StartAsync();
            using var client = new OpenClawGatewayClient(server.WebSocketUrl, "original-shared",
                NullLogger.Instance, identityPath: path, ignoreStoredDeviceToken: true);
            client.UseV2Signature = v2;
            var handshakeCount = 0;
            var first = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var second = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeSucceeded += (_, _) =>
            {
                if (Interlocked.Increment(ref handshakeCount) == 1) first.TrySetResult();
                else second.TrySetResult();
            };
            await client.ConnectAsync();
            await server.WaitForAcceptedCountAsync(1, TimeSpan.FromSeconds(5));
            var socket = AcceptedSocket(server, 0);
            await CompleteHandshake(socket, identity, v2, "issued-first", first.Task);
            Assert.Equal("issued-first", DeviceIdentity.TryReadStoredDeviceToken(path));
            AssertSharedAuth(client);

            // Exercise the real reconnect lifecycle on the same instance, not a replacement client.
            // ConnectAsync replaces the existing transport and resets handshake state.
            // Do not await graceful DisconnectAsync: this fixture has no close-ack receive loop.
            await client.ConnectAsync();
            await server.WaitForAcceptedCountAsync(2, TimeSpan.FromSeconds(5));
            await CompleteHandshake(AcceptedSocket(server, 1), identity, v2, "issued-second", second.Task);
            AssertSharedAuth(client);
            Assert.Equal("issued-second", DeviceIdentity.TryReadStoredDeviceToken(path));
            var reloaded = new DeviceIdentity(path);
            reloaded.Initialize();
            Assert.Equal(identity.DeviceId, reloaded.DeviceId);
            Assert.Equal(identity.PublicKeyBase64Url, reloaded.PublicKeyBase64Url);
            Assert.Equal("preserved-node", reloaded.NodeDeviceToken);
            Assert.Equal(identity.DeviceId, client.AuthenticatedSigningDeviceId);
        }
        finally { Directory.Delete(path, recursive: true); }
    }

    private static void AssertSharedAuth(OpenClawGatewayClient client)
    {
        var method = typeof(OpenClawGatewayClient).GetMethod("BuildAuthPayload",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var auth = Assert.IsType<Dictionary<string, string>>(method.Invoke(client, null));
        Assert.Single(auth);
        Assert.Equal("original-shared", auth["token"]);
    }

    private static WebSocket AcceptedSocket(LoopbackWebSocketServer server, int index)
    {
        // Existing fixture exposes first-socket I/O only; use its accepted list for reconnect I/O.
        var sockets = Assert.IsType<List<WebSocket>>(typeof(LoopbackWebSocketServer)
            .GetField("_acceptedSockets", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(server));
        lock (sockets) return sockets[index];
    }

    private static async Task CompleteHandshake(WebSocket socket, DeviceIdentity identity, bool v2,
        string issuedToken, Task completed)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Send(socket,
            """{"type":"event","event":"connect.challenge","payload":{"nonce":"shared-regression","ts":1785824000000}}""",
            timeout.Token);
        var buffer = new byte[64 * 1024];
        using var frame = new MemoryStream();
        WebSocketReceiveResult received;
        do
        {
            received = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), timeout.Token);
            Assert.Equal(WebSocketMessageType.Text, received.MessageType);
            frame.Write(buffer, 0, received.Count);
        } while (!received.EndOfMessage);
        using var document = JsonDocument.Parse(frame.ToArray());
        var request = document.RootElement;
        Assert.Equal("connect", request.GetProperty("method").GetString());
        var parameters = request.GetProperty("params");
        var auth = parameters.GetProperty("auth");
        Assert.Single(auth.EnumerateObject());
        Assert.Equal("original-shared", auth.GetProperty("token").GetString());
        Assert.Equal("operator", parameters.GetProperty("role").GetString());
        var device = parameters.GetProperty("device");
        Assert.Equal(identity.DeviceId, device.GetProperty("id").GetString());
        var metadata = parameters.GetProperty("client");
        var scopes = parameters.GetProperty("scopes").EnumerateArray().Select(x => x.GetString()!).ToArray();
        Assert.Contains("operator.admin", scopes);
        var signature = v2
            ? identity.SignConnectPayloadV2(device.GetProperty("nonce").GetString()!, device.GetProperty("signedAt").GetInt64(),
                metadata.GetProperty("id").GetString()!, metadata.GetProperty("mode").GetString()!, "operator", scopes, "original-shared")
            : identity.SignConnectPayloadV3(device.GetProperty("nonce").GetString()!, device.GetProperty("signedAt").GetInt64(),
                metadata.GetProperty("id").GetString()!, metadata.GetProperty("mode").GetString()!, "operator", scopes, "original-shared",
                metadata.GetProperty("platform").GetString()!, metadata.GetProperty("deviceFamily").GetString()!);
        Assert.Equal(signature, device.GetProperty("signature").GetString());
        await Send(socket, JsonSerializer.Serialize(new
        {
            type = "res", id = request.GetProperty("id").GetString(), ok = true,
            payload = new
            {
                type = "hello-ok", protocol = 4,
                auth = new { deviceToken = issuedToken, role = "operator", scopes = new[] { "operator.read" } }
            }
        }), timeout.Token);
        await completed.WaitAsync(timeout.Token);
    }

    private static Task Send(WebSocket socket, string text, CancellationToken token) =>
        socket.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(text)), WebSocketMessageType.Text, true, token);
}
