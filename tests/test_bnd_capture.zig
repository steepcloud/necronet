const std = @import("std");
const testing = std.testing;
const capture = @import("backend");
const common = @import("common");

// Test allocator
var test_allocator = std.testing.allocator;

// --- Tests for getInterfaces ---
test "getInterfaces basic functionality" {
    // This test interacts with the system, ensure Npcap/libpcap is installed
    // It might fail in CI environments without network interfaces.
    const interfaces = try capture.getInterfaces(test_allocator);
    defer {
        for (interfaces) |iface| {
            test_allocator.free(iface.name);
            if (iface.description) |desc| test_allocator.free(desc);
        }
        test_allocator.free(interfaces);
    }
    // We expect at least one interface on most systems, but allow zero for CI
    std.debug.print("Found {} interfaces.\n", .{interfaces.len});
    // try testing.expect(interfaces.len > 0); // This might be too strict
}

// --- Tests for parsePacketInfo ---

// Mock pcap header for tests
fn mockPcapHeader(caplen: u32, origlen: u32) capture.c.struct_pcap_pkthdr {
    return .{
        .ts = .{ .tv_sec = 1234567890, .tv_usec = 987654 }, // Added usec
        .caplen = caplen,
        .len = origlen,
    };
}

test "parsePacketInfo - valid TCP packet" {
    // Static mock data
    const mock_packet_data_static: [62]u8 = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Dest MAC
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // Src MAC
        0x08, 0x00, // EtherType IPv4
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x3e, // Version/IHL, ToS, Total Length (62)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x06, 0x00, 0x00, // TTL (64), Protocol (6=TCP), Checksum
        192, 168, 1, 100, // Source IP
        8, 8, 8, 8, // Dest IP
        // TCP Header (20 bytes)
        0xc0, 0x01, // Source Port (49153)
        0x00, 0x50, // Dest Port (80)
        0x00, 0x00, 0x00, 0x01, // Seq Num
        0x00, 0x00, 0x00, 0x02, // Ack Num
        0x50, 0x02, 0x20, 0x00, // Header Len/Flags, Window Size
        0x12, 0x34, 0x00, 0x00, // Checksum (0x1234), Urgent Ptr
        // Payload (8 bytes)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    };

    // Determine required alignment (use EthernetHeader as it's the first cast)
    const alignment = @alignOf(capture.EthernetHeader);
    // Allocate aligned memory
    const aligned_packet_buffer = try test_allocator.alignedAlloc(u8, alignment, mock_packet_data_static.len);
    defer test_allocator.free(aligned_packet_buffer); // Ensure it's freed

    // Copy the static data into the aligned buffer
    @memcpy(aligned_packet_buffer, &mock_packet_data_static);

    const header = mockPcapHeader(@intCast(aligned_packet_buffer.len), @intCast(aligned_packet_buffer.len));

    // Pass the pointer from the aligned buffer
    const packet_info = try capture.parsePacketInfo(header, aligned_packet_buffer.ptr);

    // Check it's not null (parsing succeeded)
    try testing.expect(packet_info != null);
    const info = packet_info.?;

    try testing.expect(info.payload != null);
    if (info.payload) |payload| {
        try testing.expectEqualSlices(u8, &[_]u8{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}, payload);   
    }

    // Assertions (remain the same)
    try testing.expectEqual(common.Protocol.TCP, info.protocol);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &info.source_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 8, 8, 8 }, &info.dest_ip);
    try testing.expectEqual(@as(u16, 49153), info.source_port);
    try testing.expectEqual(@as(u16, 80), info.dest_port);
    try testing.expectEqual(@as(u32, 62), info.captured_len);
    try testing.expectEqual(@as(u32, 62), info.original_len);
    try testing.expectEqual(@as(i64, 1234567890), info.timestamp_sec);
    try testing.expectEqual(@as(i64, 987654), info.timestamp_usec);
    try testing.expectEqual(@as(u16, 0x1234), info.checksum);
}

test "parsePacketInfo - valid UDP packet" {
    // Static mock data
    const mock_packet_data_static: [46]u8 = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00, // Eth
        // IP Header (20 bytes)
        0x45, 0x00, 0x00, 0x2e, // Version/IHL, ToS, Total Length (46)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x11, 0x00, 0x00, // TTL (64), Protocol (17=UDP), Checksum
        192, 168, 1, 101, // Source IP
        8, 8, 4, 4, // Dest IP
        // UDP Header (8 bytes)
        0xd0, 0x01, // Source Port (53249)
        0x00, 0x35, // Dest Port (53)
        0x00, 0x0c, // Length (12 = 8 UDP + 4 Payload)
        0x56, 0x78, // Checksum (0x5678)
        // Payload (4 bytes)
        0xde, 0xad, 0xbe, 0xef,
    };

    // Allocate aligned buffer
    const alignment = @alignOf(capture.EthernetHeader);
    const aligned_packet_buffer = try test_allocator.alignedAlloc(u8, alignment, mock_packet_data_static.len);
    defer test_allocator.free(aligned_packet_buffer);
    @memcpy(aligned_packet_buffer, &mock_packet_data_static);

    const header = mockPcapHeader(@intCast(aligned_packet_buffer.len), @intCast(aligned_packet_buffer.len));
    // Use aligned buffer pointer
    const packet_info = try capture.parsePacketInfo(header, aligned_packet_buffer.ptr);

    try testing.expect(packet_info != null);
    const info = packet_info.?;

    try testing.expect(info.payload != null);
    if (info.payload) |payload| {
        try testing.expectEqualSlices(u8, &[_]u8{0xde, 0xad, 0xbe, 0xef}, payload);
    }

    try testing.expectEqual(common.Protocol.UDP, info.protocol);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 101 }, &info.source_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 8, 4, 4 }, &info.dest_ip);
    try testing.expectEqual(@as(u16, 53249), info.source_port);
    try testing.expectEqual(@as(u16, 53), info.dest_port);
    // Use aligned buffer length in assertions
    try testing.expectEqual(@as(u32, 46), info.captured_len);
    try testing.expectEqual(@as(u32, 46), info.original_len);
    try testing.expectEqual(@as(i64, 1234567890), info.timestamp_sec);
    try testing.expectEqual(@as(i64, 987654), info.timestamp_usec);
    try testing.expectEqual(@as(u16, 0x5678), info.checksum);
}

test "parsePacketInfo - ICMP packet" {
    // Static mock data
     const mock_packet_data_static: [42]u8 = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00, // Eth
        // IP Header (20 bytes)
        0x45, 0x00, 0x00, 0x2a, // Version/IHL, ToS, Total Length (42)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x01, 0x00, 0x00, // TTL (64), Protocol (1=ICMP), Checksum
        192, 168, 1, 102, // Source IP
        1, 1, 1, 1, // Dest IP
        // ICMP Header (8 bytes, Type=8, Code=0 for Echo Request)
        0x08, 0x00, 0xab, 0xcd, // Type, Code, Checksum (placeholder)
        0x00, 0x01, 0x00, 0x01, // Identifier, Sequence Number
    };

    // Allocate aligned buffer
    const alignment = @alignOf(capture.EthernetHeader);
    const aligned_packet_buffer = try test_allocator.alignedAlloc(u8, alignment, mock_packet_data_static.len);
    defer test_allocator.free(aligned_packet_buffer);
    @memcpy(aligned_packet_buffer, &mock_packet_data_static);

    const header = mockPcapHeader(@intCast(aligned_packet_buffer.len), @intCast(aligned_packet_buffer.len));
    // Use aligned buffer pointer
    const packet_info = try capture.parsePacketInfo(header, aligned_packet_buffer.ptr);

    try testing.expect(packet_info != null);
    const info = packet_info.?;
    try testing.expectEqual(common.Protocol.ICMP, info.protocol);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 102 }, &info.source_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 1, 1, 1 }, &info.dest_ip);
    try testing.expectEqual(@as(u16, 8), info.source_port);
    try testing.expectEqual(@as(u16, 0), info.dest_port);
    // using aligned buffer length in assertions
    try testing.expectEqual(@as(u32, 42), info.captured_len);
    try testing.expectEqual(@as(u32, 42), info.original_len);
    try testing.expectEqual(@as(i64, 1234567890), info.timestamp_sec);
    try testing.expectEqual(@as(i64, 987654), info.timestamp_usec);
    try testing.expectEqual(@as(u16, 0xabcd), info.checksum);

    // checking ICMP payload (would be empty in this case)
    try testing.expect(info.payload != null);
    if (info.payload) |payload| {
        try testing.expectEqual(@as(usize, 0), payload.len);
    }
}

test "parsePacketInfo - ICMP with payload" {
    // Static mock data with ICMP echo request + payload
    const mock_packet_data_static: [50]u8 = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00, // Eth
        // IP Header (20 bytes)
        0x45, 0x00, 0x00, 0x32, // Version/IHL, ToS, Total Length (50)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x01, 0x00, 0x00, // TTL (64), Protocol (1=ICMP), Checksum
        192, 168, 1, 102, // Source IP
        1, 1, 1, 1, // Dest IP
        // ICMP Header (8 bytes)
        0x08, 0x00, 0xab, 0xcd, // Type, Code, Checksum
        0x00, 0x01, 0x00, 0x01, // Identifier, Sequence Number
        // ICMP Payload (8 bytes - common in ping packet)
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };

    // alloc aligned buffer and set up as in other tests
    const alignment = @alignOf(capture.EthernetHeader);
    const aligned_packet_buffer = try test_allocator.alignedAlloc(u8, alignment, mock_packet_data_static.len);
    defer test_allocator.free(aligned_packet_buffer);
    @memcpy(aligned_packet_buffer, &mock_packet_data_static);

    const header = mockPcapHeader(@intCast(aligned_packet_buffer.len), @intCast(aligned_packet_buffer.len));
    const packet_info = try capture.parsePacketInfo(header, aligned_packet_buffer.ptr);

    try testing.expect(packet_info != null);
    const info = packet_info.?;
    
    // basic protocol assertions
    try testing.expectEqual(common.Protocol.ICMP, info.protocol);
    try testing.expectEqual(@as(u16, 8), info.source_port); // ICMP type 8
    try testing.expectEqual(@as(u16, 0), info.dest_port);   // ICMP code 0
    
    // payload check
    try testing.expect(info.payload != null);
    if (info.payload) |payload| {
        try testing.expectEqualSlices(u8, 
            &[_]u8{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}, 
            payload
        );
    }
}

test "parsePacketInfo - packet too small (Ethernet)" {
    const mock_packet_data: [10]u8 = undefined; // Less than Eth header
    const header = mockPcapHeader(@intCast(mock_packet_data.len), @intCast(mock_packet_data.len));
    // This case returns null, not an error
    const packet_info = try capture.parsePacketInfo(header, &mock_packet_data);
    try testing.expect(packet_info == null);
}

test "parsePacketInfo - packet too small (IP)" {
    // Static mock data
    const mock_packet_data_static: [20]u8 = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, // Dest MAC
        0x06,0x07,0x08,0x09,0x0a,0x0b, // Src MAC
        0x08,0x00, // EthType IPv4
        0x45, 0x00, 0x00, 0x14, // IP (incomplete)
        0x00, 0x01,
    };

    // Allocate aligned buffer
    const alignment = @alignOf(capture.EthernetHeader);
    const aligned_packet_buffer = try test_allocator.alignedAlloc(u8, alignment, mock_packet_data_static.len);
    defer test_allocator.free(aligned_packet_buffer);
    @memcpy(aligned_packet_buffer, &mock_packet_data_static);

    const header = mockPcapHeader(@intCast(aligned_packet_buffer.len), @intCast(aligned_packet_buffer.len));
    // Use aligned buffer pointer
    const packet_info = capture.parsePacketInfo(header, aligned_packet_buffer.ptr);

    try testing.expectError(capture.Error.InvalidPacketHeader, packet_info);
}


test "parsePacketInfo - packet too small (TCP)" {
    // Static mock data
    const mock_packet_data_static: [40]u8 = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00, // Eth
        // IP Header (20 bytes)
        0x45, 0x00, 0x00, 0x28, // Version/IHL, ToS, Total Length (40)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x06, 0x00, 0x00, // TTL (64), Protocol (6=TCP), Checksum
        192, 168, 1, 100, // Source IP
        8, 8, 8, 8, // Dest IP
        // TCP Header (only 6 bytes provided)
        0xc0, 0x01, 0x00, 0x50, // Source Port, Dest Port
        0x00, 0x00, // Start of Seq Num
    };

    // Allocate aligned buffer
    const alignment = @alignOf(capture.EthernetHeader);
    const aligned_packet_buffer = try test_allocator.alignedAlloc(u8, alignment, mock_packet_data_static.len);
    defer test_allocator.free(aligned_packet_buffer);
    @memcpy(aligned_packet_buffer, &mock_packet_data_static);

    const header = mockPcapHeader(@intCast(aligned_packet_buffer.len), @intCast(aligned_packet_buffer.len));
    // Use aligned buffer pointer
    const packet_info = capture.parsePacketInfo(header, aligned_packet_buffer.ptr);

    try testing.expectError(capture.Error.InvalidPacketHeader, packet_info);
}


test "parsePacketInfo - non-IPv4 packet" {
    // Static mock data (only need Ethernet header part)
    const mock_packet_data_static: [60]u8 = blk: { // Use a block to initialize
        var data: [60]u8 = undefined;
        const eth_header = [_]u8{
            0x00,0x01,0x02,0x03,0x04,0x05, // Dest MAC
            0x06,0x07,0x08,0x09,0x0a,0x0b, // Src MAC
            0x86, 0xDD, // EtherType IPv6
        };
        @memcpy(data[0..eth_header.len], &eth_header);
        // Fill rest with something if needed, or leave undefined
        break :blk data;
    };

    // Allocate aligned buffer
    const alignment = @alignOf(capture.EthernetHeader);
    const aligned_packet_buffer = try test_allocator.alignedAlloc(u8, alignment, mock_packet_data_static.len);
    defer test_allocator.free(aligned_packet_buffer);
    @memcpy(aligned_packet_buffer, &mock_packet_data_static);

    const header = mockPcapHeader(@intCast(aligned_packet_buffer.len), @intCast(aligned_packet_buffer.len));
    // Use aligned buffer pointer
    const packet_info = try capture.parsePacketInfo(header, aligned_packet_buffer.ptr);

    try testing.expect(packet_info == null);
}

// --- Tests for CaptureSession ---
// Placeholder test needs updating for snapshot_len
test "CaptureSession init/deinit (placeholder)" {
    // This test requires mocking pcap_open_live to actually pass.
    // For now, we just verify the error behavior
    const result = capture.CaptureSession.init(
        test_allocator, 
        "fake_device_name", 
        false, // Not promiscuous 
        1000,  // 1 sec timeout
        65535  // Standard snapshot length
    );
    
    try testing.expectError(capture.Error.CaptureInitFailed, result);
    
    // Note: We can't call .deinit() because we don't have a session
    // If we implement mocking later, we'd want to test both init and deinit
}
