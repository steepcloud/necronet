const std = @import("std");
const testing = std.testing;
const ipc = @import("ipc");
const msg = @import("messages");
const expectEqual = testing.expectEqual;
const Thread = std.Thread;
const skip_io_tests = true;

const MockIPCPair = struct {
    clientChannel: *ipc.IPCChannel,
    serverChannel: *ipc.IPCChannel,
    
    pub fn init(allocator: std.mem.Allocator) !MockIPCPair {
        // Create two connected channels for testing
        const client_config = ipc.createDefaultConfig();
        const server_config = ipc.createDefaultConfig();
        
        const client = try ipc.IPCChannel.init(allocator, client_config);
        const server = try ipc.IPCChannel.init(allocator, server_config);
        
        return MockIPCPair{
            .clientChannel = client,
            .serverChannel = server,
        };
    }
    
    pub fn deinit(self: *MockIPCPair) void {
        self.clientChannel.deinit();
        self.serverChannel.deinit();
    }
};

// Test helper to create a message
fn createTestMessage() msg.Message {
    return msg.Message{
        .header = .{
            .version = 1,
            .sequence = 1234,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .PacketEvent,
            .payload_size = @sizeOf(msg.PacketEvent),
        },
        .payload = .{
            .PacketEvent = .{
                .flow_id = 1,
                .timestamp = std.time.microTimestamp(),
                .protocol = .TCP,
                .source_ip = .{ 192, 168, 1, 100 },
                .dest_ip = .{ 10, 0, 0, 5 },
                .source_port = 12345,
                .dest_port = 80,
                .packet_size = 1024,
                .flags = .{},
            },
        },
    };
}

test "IPCChannel - create with named pipe config" {
    // Skip on non-Windows platforms if this is platform-specific
    if (@import("builtin").os.tag != .windows) {
        return error.SkipZigTest;
    }
    
    const pipe_path = "test_pipe";
    const config = ipc.createNamedPipeConfig(pipe_path, .Json);
    
    // Instead of actually creating a named pipe, we'll just verify the config
    try testing.expectEqualStrings(config.path.?, pipe_path);
    try testing.expectEqual(config.channel_type, .NamedPipe);
    try testing.expectEqual(config.serialization, .Json);
}

test "IPCConfig - createDefaultConfig" {
    const config = ipc.createDefaultConfig();
    try testing.expectEqual(config.channel_type, .StdIO);
    try testing.expectEqual(config.serialization, .Json);
    try testing.expectEqual(config.buffer_size, 65536);
    try testing.expectEqual(config.path, null);
}

test "IPCConfig - createNamedPipeConfig" {
    const pipe_path = "test_named_pipe";
    const config = ipc.createNamedPipeConfig(pipe_path, .Binary);
    
    try testing.expectEqual(config.channel_type, .NamedPipe);
    try testing.expectEqual(config.serialization, .Binary);
    try testing.expectEqualStrings(config.path.?, pipe_path);
    try testing.expectEqual(config.buffer_size, 1024 * 1024);
}

// Mock test for bidirectional communication using pipes
test "IPCChannel - bidirectional communication with pipes" {
    if (true) return error.SkipZigTest; // Enable this test when you can create actual pipes for testing
    
    const allocator = testing.allocator;
    
    // Setup would create two connected pipes in real implementation
    const client_config = ipc.createNamedPipeConfig("test_client_pipe", .Json);
    const server_config = ipc.createNamedPipeConfig("test_server_pipe", .Json);
    
    var client_channel = try ipc.IPCChannel.init(allocator, client_config);
    defer client_channel.deinit();
    
    var server_channel = try ipc.IPCChannel.init(allocator, server_config);
    defer server_channel.deinit();
    
    // In a real test, we'd send messages between the two channels
    const test_msg = createTestMessage();
    try client_channel.sendMessage(&test_msg);
    
    // And verify receipt
    const received = try server_channel.receiveMessage();
    try testing.expect(received != null);
    try testing.expectEqual(received.?.header.sequence, test_msg.header.sequence);
}

test "IPCServer - initialization" {
    const allocator = testing.allocator;
    
    var server = try ipc.IPCServer.init(allocator);
    defer server.deinit();
    
    try testing.expectEqual(server.is_running, false);
    try testing.expectEqual(server.clients.items.len, 0);
}

test "IPCServer - add client" {
    if (skip_io_tests) return error.SkipZigTest;

    const allocator = testing.allocator;
    
    var server = try ipc.IPCServer.init(allocator);
    defer server.deinit();
    
    const config = ipc.createDefaultConfig();
    const channel = try ipc.IPCChannel.init(allocator, config);
    
    try server.addClient(channel);
    try testing.expectEqual(server.clients.items.len, 1);
    
    // Instead of calling deinit on channel directly, let the server handle it
    // The server's deinit will close all client channels
}

test "IPCServer - broadcast" {
    const allocator = testing.allocator;
    
    var server = try ipc.IPCServer.init(allocator);
    defer server.deinit();
    
    // To properly test broadcasting, we'd need multiple connected clients
    // This is a simplified test that just verifies the API
    var test_msg = createTestMessage();
    try server.broadcast(&test_msg);
}

test "IPCChannel - send packet event" {
    if (skip_io_tests) return error.SkipZigTest;

    const allocator = testing.allocator;
    
    const config = ipc.createDefaultConfig();
    var channel = try ipc.IPCChannel.init(allocator, config);
    defer channel.deinit();
    
    const packet_event = msg.PacketEvent{
        .flow_id = 42,
        .timestamp = std.time.microTimestamp(),
        .protocol = .TCP,
        .source_ip = .{ 192, 168, 1, 100 },
        .dest_ip = .{ 10, 0, 0, 5 },
        .source_port = 12345,
        .dest_port = 80,
        .packet_size = 1024,
        .flags = .{},
    };
    
    try channel.sendPacketEvent(packet_event);
    try testing.expectEqual(channel.stats.messages_sent, 1);
}

test "IPCChannel - send flow update" {
    if (skip_io_tests) return error.SkipZigTest;

    const allocator = testing.allocator;
    
    const config = ipc.createDefaultConfig();
    var channel = try ipc.IPCChannel.init(allocator, config);
    defer channel.deinit();
    
    const flow_update = msg.FlowUpdate{
        .flow_id = 1001,
        .source_ip = .{ 192, 168, 1, 100 },
        .dest_ip = .{ 10, 0, 0, 5 },
        .source_port = 12345,
        .dest_port = 80,
        .protocol = .TCP,
        .state = .Established,
        .packets_per_sec = 10.5,
        .bytes_per_sec = 1024.0,
        .active_time_ms = 5000,
        .last_update = std.time.timestamp(),
        .packet_count = 42,
        .byte_count = 12345,
    };
    
    try channel.sendFlowUpdate(flow_update);
    try testing.expectEqual(channel.stats.messages_sent, 1);
}

test "IPCChannel - send slig alert" {
    if (skip_io_tests) return error.SkipZigTest;

    const allocator = testing.allocator;
    
    const config = ipc.createDefaultConfig();
    var channel = try ipc.IPCChannel.init(allocator, config);
    defer channel.deinit();
    
    const alert = msg.SligAlert{
        .alert_id = 1,
        .flow_id = 1001,
        .severity = .High,
        .category = "Intrusion",
        .message = "Suspicious connection detected",
        .timestamp = std.time.microTimestamp(),
        .source_ip = .{ 192, 168, 1, 100 },
        .dest_ip = .{ 10, 0, 0, 5 },
        .protocol = .TCP,
        .source_port = 12345,
        .dest_port = 80,
        .confidence = 0.95,
        .evidence = null,
    };
    
    try channel.sendSligAlert(alert);
    try testing.expectEqual(channel.stats.messages_sent, 1);
}

// Test error handling conditions
test "IPCChannel - error handling" {
    const allocator = testing.allocator;
    
    // Test with invalid config to trigger errors
    const config = ipc.IPCConfig{
        .channel_type = .NamedPipe,
        .serialization = .Json,
        .path = null, // Invalid - should cause error
        .buffer_size = 1024,
    };
    
    // This should fail with ChannelInitFailed
    const result = ipc.IPCChannel.init(allocator, config);
    try testing.expectError(ipc.IPCError.ChannelInitFailed, result);
}

test "IPCChannel - thread safety with concurrent sends" {
    if (skip_io_tests) return error.SkipZigTest;

    const allocator = testing.allocator;
    const config = ipc.createDefaultConfig();
    var channel = try ipc.IPCChannel.init(allocator, config);
    defer channel.deinit();
    
    const NUM_THREADS = 8;
    const MESSAGES_PER_THREAD = 100;
    var threads: [NUM_THREADS]Thread = undefined;
    
    // Spawn multiple threads all sending messages concurrently
    for (0..NUM_THREADS) |i| {
        threads[i] = try Thread.spawn(.{}, struct {
            fn threadFn(ch: **ipc.IPCChannel, thread_id: usize) !void {
                for (0..MESSAGES_PER_THREAD) |j| {
                    const packet = msg.PacketEvent{
                        .flow_id = @intCast(thread_id * 1000 + j),
                        .timestamp = std.time.microTimestamp(),
                        .protocol = .TCP,
                        .source_ip = .{ 192, 168, 1, @intCast(thread_id) },
                        .dest_ip = .{ 10, 0, 0, 5 },
                        .source_port = @intCast(12345 + j),
                        .dest_port = 80,
                        .packet_size = 1024,
                        .flags = .{},
                    };
                    try ch.*.sendPacketEvent(packet);
                    std.time.sleep(1 * std.time.ns_per_ms); // Small delay to increase race condition likelihood
                }
            }
        }.threadFn, .{&channel, i});
    }
    
    // Wait for all threads to complete
    for (threads) |t| {
        t.join();
    }
    
    // Verify we sent the expected number of messages
    try testing.expectEqual(channel.stats.messages_sent, NUM_THREADS * MESSAGES_PER_THREAD);
}

test "IPCChannel - performance under load" {
    if (true) return error.SkipZigTest; // Uncomment to run stress test
    
    const allocator = testing.allocator;
    const config = ipc.createDefaultConfig();
    var channel = try ipc.IPCChannel.init(allocator, config);
    defer channel.deinit();
    
    const NUM_MESSAGES = 10_000;
    const start_time = std.time.milliTimestamp();
    
    for (0..NUM_MESSAGES) |i| {
        const packet = msg.PacketEvent{
            .flow_id = @intCast(i),
            .timestamp = std.time.microTimestamp(),
            .protocol = .TCP,
            .source_ip = .{192, 168, 1, 1},
            .dest_ip = .{10, 0, 0, 5},
            .source_port = 12345,
            .dest_port = 80,
            .packet_size = 64,
            .flags = .{},
        };
        try channel.sendPacketEvent(packet);
    }
    
    const end_time = std.time.milliTimestamp();
    const elapsed_ms = end_time - start_time;
    
    std.debug.print("Sent {d} messages in {d}ms ({d} msgs/sec)\n", 
        .{NUM_MESSAGES, elapsed_ms, @divFloor(NUM_MESSAGES * 1000, @max(1, elapsed_ms))});
    
    // Ensure we sent everything
    try testing.expectEqual(channel.stats.messages_sent, NUM_MESSAGES);
    
    // Ensure reasonable performance (adjust based on your requirements)
    try testing.expect(elapsed_ms < 5000); // Should take < 5 seconds
}

test "IPCChannel - large message handling" {
    if (skip_io_tests) return error.SkipZigTest;

    const allocator = testing.allocator;
    const config = ipc.createDefaultConfig();
    var channel = try ipc.IPCChannel.init(allocator, config);
    defer channel.deinit();
    
    // Create a large payload
    const PAYLOAD_SIZE = 1024 * 1024; // 1MB
    var large_data = try allocator.alloc(u8, PAYLOAD_SIZE);
    defer allocator.free(large_data);
    
    // Fill with recognizable pattern
    for (0..PAYLOAD_SIZE) |i| {
        large_data[i] = @intCast(i % 256);
    }
    
    // Create a custom message type
    var custom_message = msg.Message{
        .header = .{
            .version = 1,
            .sequence = 9999,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .PacketEvent,
            .payload_size = @sizeOf(msg.PacketEvent),
        },
        .payload = .{
            .PacketEvent = .{
                .flow_id = 9999,
                .timestamp = std.time.microTimestamp(),
                .protocol = .TCP,
                .source_ip = .{192, 168, 1, 100},
                .dest_ip = .{10, 0, 0, 5},
                .source_port = 12345,
                .dest_port = 80,
                .packet_size = PAYLOAD_SIZE,
                .flags = .{},
                .payload = large_data,
            },
        },
    };
    
    try channel.sendMessage(&custom_message);
    try testing.expectEqual(channel.stats.messages_sent, 1);
    
    // Verify stats show correct byte count
    try testing.expect(channel.stats.bytes_sent >= PAYLOAD_SIZE);
}

test "IPCChannel - full duplex communication with mocks" {
    if (skip_io_tests) return error.SkipZigTest;

    const allocator = testing.allocator;
    
    // Create a mock IPC setup with internal pipe/buffer
    var mock_ipc = try MockIPCPair.init(allocator);
    defer mock_ipc.deinit();
    
    // Send from client to server
    const client_msg = createTestMessage();
    try mock_ipc.clientChannel.sendMessage(&client_msg);
    
    // Verify server received it
    const received = try mock_ipc.serverChannel.receiveMessage();
    try testing.expect(received != null);
    try testing.expectEqual(received.?.header.sequence, client_msg.header.sequence);
    
    // Send response from server to client
    var server_msg = createTestMessage();
    server_msg.header.sequence = 5678;
    try mock_ipc.serverChannel.sendMessage(&server_msg);
    
    // Verify client received it
    const response = try mock_ipc.clientChannel.receiveMessage();
    try testing.expect(response != null);
    try testing.expectEqual(response.?.header.sequence, 5678);
}

test "IPCChannel - memory management" {
    if (skip_io_tests) return error.SkipZigTest;

    // Run with leak detection
    const allocator = std.testing.allocator;
    
    // Scope to test proper cleanup
    {
        const config = ipc.createDefaultConfig();
        var channel = try ipc.IPCChannel.init(allocator, config);
        
        // Add multiple messages to internal buffers
        for (0..100) |i| {
            const packet = msg.PacketEvent{
                .flow_id = @intCast(i),
                .timestamp = std.time.microTimestamp(),
                .protocol = .TCP,
                .source_ip = .{192, 168, 1, 1},
                .dest_ip = .{10, 0, 0, 5},
                .source_port = 12345,
                .dest_port = 80,
                .packet_size = 64,
                .flags = .{},
            };
            try channel.sendPacketEvent(packet);
        }
        
        // Proper cleanup should happen here
        channel.deinit();
    }
    
    // If we get here without memory leaks, test passes
}

test "IPCChannel - protocol version compatibility" {
    if (skip_io_tests) return error.SkipZigTest;
    
    const allocator = testing.allocator;
    const config = ipc.createDefaultConfig();
    var channel = try ipc.IPCChannel.init(allocator, config);
    defer channel.deinit();
    
    // Test current version message (should succeed)
    var current_msg = createTestMessage();
    try channel.sendMessage(&current_msg);
    
    // Test older version message (if you support backward compatibility)
    var old_msg = createTestMessage();
    old_msg.header.version = 0;
    try channel.sendMessage(&old_msg);
    
    // Test future version message (should be rejected if validation is strict)
    var future_msg = createTestMessage();
    future_msg.header.version = 99;
    const future_result = channel.sendMessage(&future_msg);
    
    // Adjust expectations based on your compatibility policy
    try testing.expectError(ipc.IPCError.InvalidMessage, future_result);
}