const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const messages = @import("messages");
const common = @import("common");
const detection = @import("detection");
const capture = @import("backend");

// Mock backend types needed for tests
fn createMockPacketInfo() capture.PacketInfo {
    return .{
        .timestamp_sec = 1650000000,
        .timestamp_usec = 500000,
        .protocol = .TCP,
        .source_ip = .{ 192, 168, 1, 10 },
        .dest_ip = .{ 10, 20, 30, 40 },
        .source_port = 12345,
        .dest_port = 443,
        .original_len = 1024,
        .captured_len = 64,
        .checksum = 0,
        .payload = &[_]u8{
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0a,
            0x0a, 0x14, 0x1e, 0x28,
            // TCP header (20+ bytes)
            0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x12, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
        .tcp_flags = 0,
        .ip_flags = 0,
        .flow_id = null,
    };
}

fn createMockDetectionAlert() detection.Alert {
    return .{
        .id = 12345,
        .timestamp = 1650000000,
        .flow_id = 9876,
        .severity = .High, 
        .category = "Intrusion",
        .message = "Suspicious SSH connection",
        .protocol = .TCP,
        .source_ip = .{ 192, 168, 1, 10 },
        .dest_ip = .{ 10, 20, 30, 40 },
        .source_port = 22,
        .dest_port = 52100,
    };
}

test "Message structure sizes and alignment" {
    // Verify sizes are as expected to catch unexpected changes
    try testing.expectEqual(@sizeOf(u16), @sizeOf(@TypeOf(messages.PROTOCOL_VERSION)));
    try testing.expectEqual(@sizeOf(u8), @sizeOf(messages.MessageType));
    try testing.expectEqual(24, @sizeOf(messages.MessageHeader));
    
    // Verify packed structs are properly optimized
    try testing.expectEqual(2, @sizeOf(messages.PacketEvent.PacketFlags));

    // Check proper alignment to avoid ABI issues
    try testing.expect(@alignOf(messages.Message) >= 8);
}

test "MessageType enum values" {
    // Ensure enum values are stable for binary compatibility
    try testing.expectEqual(0, @intFromEnum(messages.MessageType.Hello));
    try testing.expectEqual(1, @intFromEnum(messages.MessageType.Heartbeat));
    try testing.expectEqual(2, @intFromEnum(messages.MessageType.Shutdown));
    try testing.expectEqual(3, @intFromEnum(messages.MessageType.Error));
    try testing.expectEqual(4, @intFromEnum(messages.MessageType.PacketEvent));
    try testing.expectEqual(5, @intFromEnum(messages.MessageType.FlowUpdate));
    try testing.expectEqual(6, @intFromEnum(messages.MessageType.SligAlert));
    try testing.expectEqual(7, @intFromEnum(messages.MessageType.DetectionStats));
    try testing.expectEqual(8, @intFromEnum(messages.MessageType.ConfigUpdate));
    try testing.expectEqual(9, @intFromEnum(messages.MessageType.CaptureControl));
    try testing.expectEqual(10, @intFromEnum(messages.MessageType.FilterUpdate));
}

test "Factory functions create valid messages" {
    const allocator = testing.allocator;
    
    // Test Hello message creation
    {
        const client_name = "Test Client";
        const msg = messages.createHelloMsg(1, client_name, 1, 0x00000001);
        
        try testing.expectEqual(messages.MessageType.Hello, msg.header.msg_type);
        try testing.expectEqual(@as(u16, 1), msg.header.version);
        try testing.expectEqual(@as(u64, 1), msg.header.sequence);
        try testing.expectEqual(@as(u32, @sizeOf(messages.HelloPayload) + client_name.len), msg.header.payload_size);
        
        try testing.expectEqualStrings(client_name, msg.payload.Hello.client_name);
        try testing.expectEqual(@as(u16, 1), msg.payload.Hello.client_version);
        try testing.expectEqual(@as(u32, 0x00000001), msg.payload.Hello.capabilities);
    }
    
    // Test Heartbeat message creation
    {
        const msg = messages.createHeartbeatMsg(2, 60);
        
        try testing.expectEqual(messages.MessageType.Heartbeat, msg.header.msg_type);
        try testing.expectEqual(@as(u64, 2), msg.header.sequence);
        try testing.expectEqual(@as(u32, @sizeOf(messages.HeartbeatPayload)), msg.header.payload_size);
        
        try testing.expectEqual(@as(u64, 60), msg.payload.Heartbeat.uptime_seconds);
    }
    
    // Test Shutdown message creation
    {
        const reason = "System maintenance";
        const msg = messages.createShutdownMsg(3, reason, true);
        
        try testing.expectEqual(messages.MessageType.Shutdown, msg.header.msg_type);
        try testing.expectEqual(@as(u64, 3), msg.header.sequence);
        try testing.expectEqual(@as(u32, @sizeOf(messages.ShutdownPayload) + reason.len), msg.header.payload_size);
        
        try testing.expectEqualStrings(reason, msg.payload.Shutdown.reason);
        try testing.expectEqual(true, msg.payload.Shutdown.restart);
    }
    
    // Test PacketEvent message creation
    {
        const event = messages.PacketEvent{
            .flow_id = 12345,
            .timestamp = std.time.microTimestamp(),
            .protocol = .TCP,
            .source_ip = .{ 192, 168, 1, 10 },
            .dest_ip = .{ 10, 20, 30, 40 },
            .source_port = 12345,
            .dest_port = 443,
            .packet_size = 1024,
            .flags = .{
                .syn = true,
                .ack = true,
            },
        };
        
        const msg = messages.createPacketEventMsg(4, event);
        
        try testing.expectEqual(messages.MessageType.PacketEvent, msg.header.msg_type);
        try testing.expectEqual(@as(u64, 4), msg.header.sequence);
        try testing.expectEqual(@as(u32, @sizeOf(messages.PacketEvent)), msg.header.payload_size);
        
        const payload = msg.payload.PacketEvent;
        try testing.expectEqual(event.flow_id, payload.flow_id);
        try testing.expectEqual(event.protocol, payload.protocol);
        try testing.expectEqual(event.source_port, payload.source_port);
        try testing.expectEqual(event.dest_port, payload.dest_port);
        try testing.expectEqual(event.packet_size, payload.packet_size);
        try testing.expectEqual(event.flags.syn, payload.flags.syn);
        try testing.expectEqual(event.flags.ack, payload.flags.ack);
    }
    
    // Test SligAlert message creation
    {
        var alert = try messages.fromDetectionAlert(allocator, createMockDetectionAlert());
        defer alert.deinit(allocator);
        
        var msg = try messages.createSligAlertMsg(5, alert, allocator);
        defer msg.deinit(allocator);

        try testing.expectEqual(messages.MessageType.SligAlert, msg.header.msg_type);
        try testing.expectEqual(@as(u64, 5), msg.header.sequence);
        
        const payload = msg.payload.SligAlert;
        try testing.expectEqual(alert.alert_id, payload.alert_id);
        try testing.expectEqual(alert.flow_id, payload.flow_id);
        try testing.expectEqualStrings(alert.category, payload.category);
        try testing.expectEqualStrings(alert.message, payload.message);
    }
    
    // Test FlowUpdate message creation
    {
        const flow = messages.FlowUpdate{
            .flow_id = 12345,
            .protocol = .TCP,
            .source_ip = .{ 192, 168, 1, 10 },
            .dest_ip = .{ 10, 20, 30, 40 },
            .source_port = 12345,
            .dest_port = 443,
            .active_time_ms = 60000,
            .packet_count = 100,
            .byte_count = 150000,
            .packets_per_sec = 1.67,
            .bytes_per_sec = 2500.0,
            .state = .Established,
            .last_update = std.time.timestamp(),
        };
        
        const msg = messages.createFlowUpdateMsg(6, flow);
        
        try testing.expectEqual(messages.MessageType.FlowUpdate, msg.header.msg_type);
        try testing.expectEqual(@as(u64, 6), msg.header.sequence);
        try testing.expectEqual(@as(u32, @sizeOf(messages.FlowUpdate)), msg.header.payload_size);
        
        const payload = msg.payload.FlowUpdate;
        try testing.expectEqual(flow.flow_id, payload.flow_id);
        try testing.expectEqual(flow.protocol, payload.protocol);
        try testing.expectEqual(flow.packet_count, payload.packet_count);
        try testing.expectEqual(flow.state, payload.state);
    }
    
    // Test Error message creation
    {
        const error_info = messages.ErrorInfo{
            .code = .CaptureInitFailed,
            .component = "capture",
            .message = "Failed to initialize packet capture",
            .recoverable = false,
        };
        
        const msg = messages.createErrorMsg(7, error_info);
        
        try testing.expectEqual(messages.MessageType.Error, msg.header.msg_type);
        try testing.expectEqual(@as(u64, 7), msg.header.sequence);
        
        const payload = msg.payload.Error;
        try testing.expectEqual(error_info.code, payload.code);
        try testing.expectEqualStrings(error_info.component, payload.component);
        try testing.expectEqualStrings(error_info.message, payload.message);
        try testing.expectEqual(error_info.recoverable, payload.recoverable);
    }

    // Test DetectionStats message creation
    {
        const stats = messages.DetectionStats{
            .uptime_seconds = 3600,
            .packets_analyzed = 100000,
            .flows_tracked = 500,
            .alerts_generated = 10,
            .rules_loaded = 250,
            .memory_usage_kb = 8192,
            .slig_status = .Patrolling,
        };
        
        const msg = messages.createDetectionStatsMsg(8, stats);
        
        try testing.expectEqual(messages.MessageType.DetectionStats, msg.header.msg_type);
        try testing.expectEqual(@as(u64, 8), msg.header.sequence);
        try testing.expectEqual(@as(u32, @sizeOf(messages.DetectionStats)), msg.header.payload_size);
        
        const payload = msg.payload.DetectionStats;
        try testing.expectEqual(stats.uptime_seconds, payload.uptime_seconds);
        try testing.expectEqual(stats.packets_analyzed, payload.packets_analyzed);
        try testing.expectEqual(stats.flows_tracked, payload.flows_tracked);
        try testing.expectEqual(stats.alerts_generated, payload.alerts_generated);
        try testing.expectEqual(stats.slig_status, payload.slig_status);
    }
}

test "Message JSON serialization and deserialization round-trip" {
    const allocator = testing.allocator;
    
    // Create message with various field types to test serialization
    var original_msg = blk: {
        var alert = try messages.fromDetectionAlert(allocator, createMockDetectionAlert());
        defer alert.deinit(allocator);

        const msg = try messages.createSligAlertMsg(42, alert, allocator);
        break :blk msg;
    };
    defer original_msg.deinit(allocator);

    // Serialize to JSON
    const json_data = try messages.toJson(&original_msg, allocator);
    defer allocator.free(json_data);
    
    // Verify JSON contains expected fields
    try testing.expect(mem.indexOf(u8, json_data, "\"alert_id\"") != null);
    try testing.expect(mem.indexOf(u8, json_data, "\"category\"") != null);
    try testing.expect(mem.indexOf(u8, json_data, "\"Intrusion\"") != null);
    
    // Deserialize back
    var deserialized_msg = try messages.fromJson(json_data, allocator);
    defer deserialized_msg.deinit(allocator);
    
    // Compare original with deserialized
    try testing.expectEqual(original_msg.header.version, deserialized_msg.header.version);
    try testing.expectEqual(original_msg.header.sequence, deserialized_msg.header.sequence);
    try testing.expectEqual(original_msg.header.msg_type, deserialized_msg.header.msg_type);
    
    const orig_payload = original_msg.payload.SligAlert;
    const deser_payload = deserialized_msg.payload.SligAlert;
    try testing.expectEqual(orig_payload.alert_id, deser_payload.alert_id);
    try testing.expectEqualStrings(orig_payload.category, deser_payload.category);
    try testing.expectEqualStrings(orig_payload.message, deser_payload.message);
}

test "Message validation of well-formed messages" {
    // Create and test typical well-formed messages
    const hello_msg = messages.createHelloMsg(1, "TestClient", 1, 0);
    try testing.expect(messages.validate(&hello_msg) == null);
    
    const heartbeat_msg = messages.createHeartbeatMsg(2, 60);
    try testing.expect(messages.validate(&heartbeat_msg) == null);
    
    const packet_event = messages.PacketEvent{
        .flow_id = 12345,
        .timestamp = std.time.microTimestamp(),
        .protocol = .TCP,
        .source_ip = .{ 192, 168, 1, 10 },
        .dest_ip = .{ 10, 20, 30, 40 },
        .source_port = 12345,
        .dest_port = 80,
        .packet_size = 1024,
        .flags = .{},
    };
    const packet_msg = messages.createPacketEventMsg(3, packet_event);
    try testing.expect(messages.validate(&packet_msg) == null);
}

test "Message validation detects malformed messages" {
    const allocator = testing.allocator;
    
    // Test message with incorrect protocol version
    {
        var invalid_version = messages.createHelloMsg(1, "TestClient", 1, 0);
        invalid_version.header.version = 99; // Wrong version
        
        const result = messages.validate(&invalid_version);
        try testing.expect(result != null);
        try testing.expectEqual(messages.ErrorInfo.ErrorCode.ProtocolMismatch, result.?.code);
    }
    
    // Test message with undersized payload
    {
        var invalid_payload_size = messages.createHelloMsg(1, "TestClient", 1, 0);
        invalid_payload_size.header.payload_size = 1; // Too small
        
        const result = messages.validate(&invalid_payload_size);
        try testing.expect(result != null);
        try testing.expectEqual(messages.ErrorInfo.ErrorCode.MessageCorrupted, result.?.code);
    }
    
    // Test Hello message with empty client name
    {
        var invalid_hello = messages.createHelloMsg(1, "", 1, 0);
        
        const result = messages.validate(&invalid_hello);
        try testing.expect(result != null);
        try testing.expectEqual(messages.ErrorInfo.ErrorCode.MessageCorrupted, result.?.code);
    }
    
    // Test SligAlert with empty category/message
    {
        var alert = try messages.fromDetectionAlert(allocator, createMockDetectionAlert());
        defer alert.deinit(allocator);
        
        var msg = try messages.createSligAlertMsg(5, alert, allocator);
        const original_category = msg.payload.SligAlert.category;
        
        // Empty out the category and verify it fails validation
        allocator.free(msg.payload.SligAlert.category);
        msg.payload.SligAlert.category = try allocator.dupe(u8, "");
        
        var result = messages.validate(&msg);
        try testing.expect(result != null);
        
        // Restore category, empty message
        msg.payload.SligAlert.category = original_category;
        allocator.free(msg.payload.SligAlert.message);
        msg.payload.SligAlert.message = try allocator.dupe(u8, "");
        
        result = messages.validate(&msg);
        try testing.expect(result != null);
    }
    
    // Test flow update with inconsistent state
    {
        const flow = messages.FlowUpdate{
            .flow_id = 12345,
            .protocol = .TCP,
            .source_ip = .{ 192, 168, 1, 10 },
            .dest_ip = .{ 10, 20, 30, 40 },
            .source_port = 12345,
            .dest_port = 443,
            .active_time_ms = 60000,
            .packet_count = 0, // No packets
            .byte_count = 0,
            .packets_per_sec = 0,
            .bytes_per_sec = 0,
            .state = .Established,
            .last_update = std.time.timestamp(),
        };
        
        var msg = messages.createFlowUpdateMsg(6, flow);
        
        const result = messages.validate(&msg);
        try testing.expect(result != null);
        try testing.expectEqual(messages.ErrorInfo.ErrorCode.MessageCorrupted, result.?.code);
        try testing.expect(result.?.recoverable); // This should be a recoverable error
    }
}

test "fromDetectionAlert conversion function" {
    const allocator = testing.allocator;
    
    // Create a detection alert
    const detection_alert = createMockDetectionAlert();
    
    // Convert to SligAlert
    var slig_alert = try messages.fromDetectionAlert(allocator, detection_alert);
    defer slig_alert.deinit(allocator);
    
    // Verify fields were correctly copied/converted
    try testing.expectEqual(detection_alert.id, slig_alert.alert_id);
    try testing.expectEqual(detection_alert.flow_id.?, slig_alert.flow_id);
    try testing.expectEqual(detection_alert.protocol, slig_alert.protocol);
    try testing.expectEqual(detection_alert.source_port, slig_alert.source_port);
    try testing.expectEqual(detection_alert.dest_port, slig_alert.dest_port);
    try testing.expectEqualSlices(u8, &detection_alert.source_ip, &slig_alert.source_ip);
    try testing.expectEqualSlices(u8, &detection_alert.dest_ip, &slig_alert.dest_ip);
    try testing.expectEqualStrings(detection_alert.category, slig_alert.category);
    try testing.expectEqualStrings(detection_alert.message, slig_alert.message);
}

test "packetEventFromCaptureInfo conversion" {
    // Create mock packet info
    const packet_info = createMockPacketInfo();
    const flow_id: u64 = 98765;
    
    // Convert to PacketEvent
    const packet_event = messages.packetEventFromCaptureInfo(&packet_info, flow_id);
    
    // Verify fields
    try testing.expectEqual(flow_id, packet_event.flow_id);
    try testing.expectEqual(@as(i64, packet_info.timestamp_sec) * 1_000_000 + @as(i64, packet_info.timestamp_usec), 
                           packet_event.timestamp);
    try testing.expectEqual(packet_info.protocol, packet_event.protocol);
    try testing.expectEqual(packet_info.source_port, packet_event.source_port);
    try testing.expectEqual(packet_info.dest_port, packet_event.dest_port);
    try testing.expectEqualSlices(u8, &packet_info.source_ip, &packet_event.source_ip);
    try testing.expectEqualSlices(u8, &packet_info.dest_ip, &packet_event.dest_ip);
    try testing.expectEqual(packet_info.original_len, packet_event.packet_size);
    
    // Test flag extraction from TCP header
    try testing.expect(packet_event.flags.syn);  // Flag should be set based on packet data
    try testing.expect(packet_event.flags.ack);  // Flag should be set based on packet data
}

test "Binary serialization of Hello message" {
    const allocator = testing.allocator;
    
    // Create a Hello message
    const client_name = "TestClient";
    const original_msg = messages.createHelloMsg(1, client_name, 1, 0x00000001);
    
    // Serialize to binary
    const binary_data = try messages.toBinary(&original_msg, allocator);
    defer allocator.free(binary_data);
    
    // Deserialize from binary
    var deserialized_msg = try messages.fromBinary(binary_data, allocator);
    defer deserialized_msg.deinit(allocator);
    
    // Compare
    try testing.expectEqual(original_msg.header.version, deserialized_msg.header.version);
    try testing.expectEqual(original_msg.header.sequence, deserialized_msg.header.sequence);
    try testing.expectEqual(original_msg.header.msg_type, deserialized_msg.header.msg_type);
    
    try testing.expectEqualStrings(
        original_msg.payload.Hello.client_name,
        deserialized_msg.payload.Hello.client_name
    );
    try testing.expectEqual(
        original_msg.payload.Hello.client_version,
        deserialized_msg.payload.Hello.client_version
    );
    try testing.expectEqual(
        original_msg.payload.Hello.capabilities,
        deserialized_msg.payload.Hello.capabilities
    );
}

test "Message memory management" {
    const allocator = testing.allocator;
    
    // Allocate and free string fields
    {
        var alert = messages.SligAlert{
            .alert_id = 1,
            .flow_id = 2,
            .timestamp = std.time.timestamp(),
            .severity = .Medium,
            .category = try allocator.dupe(u8, "Test Category"),
            .message = try allocator.dupe(u8, "Test Message"),
            .protocol = .TCP,
            .source_ip = .{ 1, 2, 3, 4 },
            .dest_ip = .{ 5, 6, 7, 8 },
            .source_port = 1234,
            .dest_port = 5678,
            .confidence = 1.0,
            .evidence = try allocator.dupe(u8, "Test Evidence"),
        };
        
        // Ensure proper deallocation works
        alert.deinit(allocator);
    }
    
    // Test message deinit properly cleans up
    {
        var msg = messages.Message{
            .header = .{
                .version = 1,
                .sequence = 1,
                .timestamp = std.time.microTimestamp(),
                .msg_type = .Hello,
                .payload_size = 100,
            },
            .payload = .{
                .Hello = .{
                    .client_version = 1,
                    .client_name = try allocator.dupe(u8, "TestClient"),
                    .capabilities = 0,
                }
            },
        };
        
        msg.deinit(allocator);
    }
    
    // No explicit assert needed - if we get this far without crash, deinit worked
}

test "Error handling for binary deserialization" {
    const allocator = testing.allocator;
    
    // Test empty data
    {
        const empty_data = [_]u8{};
        try testing.expectError(error.InvalidMessageFormat, messages.fromBinary(&empty_data, allocator));
    }
    
    // Test truncated header
    {
        const truncated_header = [_]u8{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        try testing.expectError(error.InvalidMessageFormat, messages.fromBinary(&truncated_header, allocator));
    }
    
    // Test wrong version
    {
        var good_msg = messages.createHelloMsg(1, "TestClient", 1, 0);
        var bin_data = try messages.toBinary(&good_msg, allocator);
        defer allocator.free(bin_data);
        
        // Modify version
        bin_data[0] = 0x99;
        bin_data[1] = 0x99;
        
        try testing.expectError(error.ProtocolVersionMismatch, messages.fromBinary(bin_data, allocator));
    }
    
    // Test truncated payload
    {
        var good_msg = messages.createHelloMsg(1, "TestClient", 1, 0);
        var bin_data = try messages.toBinary(&good_msg, allocator);
        defer allocator.free(bin_data);
        
        // Cut off the payload
        const truncated = bin_data[0..@sizeOf(messages.MessageHeader) + 4];
        
        try testing.expectError(error.MessageTruncated, messages.fromBinary(truncated, allocator));
    }
}

test "calculateMessageSize is accurate" {
    const allocator = testing.allocator;
    
    // Test Hello message
    {
        const client_name = "TestClient";
        const msg = messages.createHelloMsg(1, client_name, 1, 0);
        const expected_size = @sizeOf(messages.MessageHeader) + @sizeOf(messages.HelloPayload) + client_name.len;
        try testing.expectEqual(expected_size, messages.calculateMessageSize(&msg));
    }
    
    // Test SligAlert with evidence
    {
        var alert = try messages.fromDetectionAlert(allocator, createMockDetectionAlert());
        alert.evidence = try allocator.dupe(u8, "Evidence data");
        defer alert.deinit(allocator);
        
        var msg = try messages.createSligAlertMsg(1, alert, allocator);
        defer msg.deinit(allocator);

        const expected_size = @sizeOf(messages.MessageHeader) + @sizeOf(messages.SligAlert) + 
                            alert.category.len + alert.message.len + alert.evidence.?.len;
        
        try testing.expectEqual(expected_size, messages.calculateMessageSize(&msg));
    }
}

test "testJsonRoundTrip utility function" {
    const allocator = testing.allocator;
    
    // Create a test message
    const original_msg = messages.createHeartbeatMsg(42, 3600);
    
    // Round-trip it
    var round_tripped = try messages.testJsonRoundTrip(original_msg, allocator);
    defer round_tripped.deinit(allocator);
    
    // Verify it's the same
    try testing.expectEqual(original_msg.header.sequence, round_tripped.header.sequence);
    try testing.expectEqual(original_msg.header.msg_type, round_tripped.header.msg_type);
    try testing.expectEqual(
        original_msg.payload.Heartbeat.uptime_seconds, 
        round_tripped.payload.Heartbeat.uptime_seconds
    );
}

test "Edge cases in binary serialization" {
    const allocator = testing.allocator;
    
    // Test handling of very small messages
    {
        const msg = messages.createHeartbeatMsg(0, 0);
        const bin_data = try messages.toBinary(&msg, allocator);
        defer allocator.free(bin_data);
        
        // Verify minimum size
        try testing.expect(bin_data.len >= @sizeOf(messages.MessageHeader));
    }
}