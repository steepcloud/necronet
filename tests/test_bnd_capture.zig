const std = @import("std");
const testing = std.testing;
const capture = @import("backend"); // Assuming backend is added as a module in build.zig for tests
const common = @import("common"); // Assuming common is added as a module

// Test allocator
var test_allocator = std.testing.allocator;

// --- Tests for getInterfaces ---

// Basic test: Check if getInterfaces runs without crashing and returns a slice.
// More specific tests are hard without mocking pcap_findalldevs.
test "getInterfaces basic functionality" {
    const interfaces = try capture.getInterfaces(test_allocator);
    defer {
        for (interfaces) |iface| {
            test_allocator.free(iface.name);
            if (iface.description) |desc| test_allocator.free(desc);
        }
        test_allocator.free(interfaces);
    }
    // We expect at least one interface on most systems
    try testing.expect(interfaces.len > 0);
}

// --- Tests for parsePacketInfo ---
// This function is well-suited for unit testing with mock data.

// Mock pcap header for tests
fn mockPcapHeader(len: u32) capture.c.struct_pcap_pkthdr {
    return .{
        .ts = .{ .tv_sec = 1234567890, .tv_usec = 0 },
        .caplen = len,
        .len = len,
    };
}

test "parsePacketInfo - valid TCP packet" {
    // Mocking Ethernet + IPv4 + TCP header
    // Dest MAC | Src MAC | EtherType | IPv4 Header ... | TCP Header ...
    // Size: 6 (dst) + 6 (src) + 2 (type) + 20 (ip) + 20 (tcp) + 8 (payload)
    // Total: 62 bytes
    const mock_packet_data: [62]u8 = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Dest MAC
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // Src MAC
        0x08, 0x00, // EtherType IPv4
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x28, // Version/IHL, ToS, Total Length (40)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x06, 0x00, 0x00, // TTL (64), Protocol (6=TCP), Checksum
        192, 168, 1, 100, // Source IP
        8, 8, 8, 8, // Dest IP
        // TCP Header (min 20 bytes, using 20 here)
        0xc0, 0x01, // Source Port (49153)
        0x00, 0x50, // Dest Port (80)
        0x00, 0x00, 0x00, 0x01, // Seq Num
        0x00, 0x00, 0x00, 0x02, // Ack Num
        0x50, 0x02, 0x20, 0x00, // Header Len/Flags (ACK), Window Size
        0x00, 0x00, 0x00, 0x00, // Checksum, Urgent Ptr
        // Payload (8 bytes to reach total length 40)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    };
    const header = mockPcapHeader(@intCast(mock_packet_data.len));
    const packet_info = capture.parsePacketInfo(header, &mock_packet_data);

    try testing.expect(packet_info != null);
    const info = packet_info.?;
    try testing.expectEqual(common.Protocol.TCP, info.protocol);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &info.source_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 8, 8, 8 }, &info.dest_ip);
    try testing.expectEqual(@as(u16, 49153), info.source_port);
    try testing.expectEqual(@as(u16, 80), info.dest_port);
    try testing.expectEqual(@as(usize, mock_packet_data.len), info.size);
    try testing.expectEqual(@as(i64, 1234567890), info.timestamp);
}

test "parsePacketInfo - valid UDP packet" {
    // Mock Ethernet + IPv4 + UDP header
    const mock_packet_data: [42]u8 = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00, // Eth
        0x45, 0x00, 0x00, 0x1c, // IP: Version/IHL, ToS, Total Length (28)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x11, 0x00, 0x00, // TTL (64), Protocol (17=UDP), Checksum
        192, 168, 1, 101, // Source IP
        8, 8, 4, 4, // Dest IP
        // UDP Header (8 bytes)
        0xd0, 0x01, // Source Port (53249)
        0x00, 0x35, // Dest Port (53)
        0x00, 0x08, // Length (8)
        0x00, 0x00, // Checksum
        // No payload needed for this test
    };
     const header = mockPcapHeader(@intCast(mock_packet_data.len));
    const packet_info = capture.parsePacketInfo(header, &mock_packet_data);

    try testing.expect(packet_info != null);
    const info = packet_info.?;
    try testing.expectEqual(common.Protocol.UDP, info.protocol);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 101 }, &info.source_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 8, 4, 4 }, &info.dest_ip);
    try testing.expectEqual(@as(u16, 53249), info.source_port);
    try testing.expectEqual(@as(u16, 53), info.dest_port);
    try testing.expectEqual(@as(usize, mock_packet_data.len), info.size);
}


test "parsePacketInfo - ICMP packet" {
     const mock_packet_data: [42]u8 = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00, // Eth
        0x45, 0x00, 0x00, 0x1c, // IP: Version/IHL, ToS, Total Length (28)
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Frag Offset
        0x40, 0x01, 0x00, 0x00, // TTL (64), Protocol (1=ICMP), Checksum
        192, 168, 1, 102, // Source IP
        1, 1, 1, 1, // Dest IP
        // ICMP Header (Type=8, Code=0 for Echo Request)
        0x08, 0x00, 0x00, 0x00, // Type, Code, Checksum
        0x00, 0x01, 0x00, 0x01, // Identifier, Sequence Number
    };
     const header = mockPcapHeader(@intCast(mock_packet_data.len));
    const packet_info = capture.parsePacketInfo(header, &mock_packet_data);

    try testing.expect(packet_info != null);
    const info = packet_info.?;
    try testing.expectEqual(common.Protocol.ICMP, info.protocol);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 102 }, &info.source_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 1, 1, 1 }, &info.dest_ip);
    try testing.expectEqual(@as(u16, 0), info.source_port); // Ports are 0 for ICMP
    try testing.expectEqual(@as(u16, 0), info.dest_port);
    try testing.expectEqual(@as(usize, mock_packet_data.len), info.size);
}

test "parsePacketInfo - packet too small" {
    const mock_packet_data: [10]u8 = undefined; // Less than Eth+IP header
    const header = mockPcapHeader(@intCast(mock_packet_data.len));
    const packet_info = capture.parsePacketInfo(header, &mock_packet_data);
    try testing.expect(packet_info == null);
}

test "parsePacketInfo - non-IPv4 packet" {
    var mock_packet_data: [60]u8 = undefined;
    const eth_header = [_]u8{
        0x00,0x01,0x02,0x03,0x04,0x05, // Dest MAC
        0x06,0x07,0x08,0x09,0x0a,0x0b, // Src MAC
        0x86, 0xDD, // EtherType IPv6
        // ... rest doesn't matter for this test
    };
    @memcpy(mock_packet_data[0..eth_header.len], &eth_header);

    const header = mockPcapHeader(@intCast(mock_packet_data.len));
    const packet_info = capture.parsePacketInfo(header, &mock_packet_data);
    // expect null because parsePacketInfo currently only handles IPv4 (EtherType 0x0800)
    try testing.expect(packet_info == null);
}

// --- Tests for CaptureSession ---
// Testing init, setFilter, capturePacket is harder as they interact with the OS/libpcap.
// You might need more advanced techniques like mocking the C functions if you want
// deep unit tests for these. For now, the end-to-end test in main.zig covers them.

// Example placeholder test (won't actually capture)
// test "CaptureSession init/deinit (placeholder)" {
//     // This test doesn't do much without mocking, just checks creation/deletion
//     const fake_device = "fake_device_name";
//     var session = try capture.CaptureSession.init(test_allocator, fake_device, false, 0);
//     defer session.deinit();
//     try testing.expect(session.handle != null); // This would fail without mocking pcap_open_live
// }
