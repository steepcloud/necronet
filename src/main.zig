const std = @import("std");
const capture = @import("backend");
const common = @import("common");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // List available interfaces
    const interfaces = try capture.getInterfaces(allocator);
    defer {
        for (interfaces) |iface| {
            allocator.free(iface.name);
            if (iface.description) |desc| {
                allocator.free(desc);
            }
        }
        allocator.free(interfaces);
    }

    std.debug.print("Available interfaces:\n", .{});
    for (interfaces, 0..) |iface, i| {
        std.debug.print("{d}: {s} {s} {s}\n", .{
            i, 
            iface.name, 
            if (iface.is_loopback) "(loopback)" else "",
            if (iface.description) |desc| desc else "",
        });
    }

    // Ask user to select an interface
    std.debug.print("\nSelect interface number: ", .{});
    const stdin = std.io.getStdIn().reader();
    var buf: [10]u8 = undefined;
    const if_input = try stdin.readUntilDelimiterOrEof(buf[0..], '\n');
    if (if_input == null) {
        std.debug.print("No input received.\n", .{});
        return;
    }

    const input = if_input.?;

    const trimmed_input = std.mem.trim(u8, input, " \r\n\t");
    if (trimmed_input.len == 0) {
        std.debug.print("Empty input.\n", .{});
        return;
    }
    const selected_index = try std.fmt.parseInt(usize, trimmed_input, 10);

    if (selected_index >= interfaces.len) {
        std.debug.print("Invalid selection\n", .{});
        return;
    }

    const selected_interface = interfaces[selected_index];
    std.debug.print("Starting capture on {s}...\n", .{selected_interface.name});

    std.debug.print("\nEnter packet filter (examples: ip, tcp, udp port 53, host 192.168.1.1, etc.)\n", .{});
    std.debug.print("Leave blank for no filter: ", .{});

    // Read filter input
    var filter_buf: [256]u8 = undefined;
    const filter_input = try stdin.readUntilDelimiterOrEof(filter_buf[0..], '\n');
    if (filter_input == null) {
        std.debug.print("No input received, using no filter.\n", .{});
    }

    // Process the filter
    const filter_text = if (filter_input) |f| std.mem.trim(u8, f, " \r\n\t") else "";
    const filter = if (filter_text.len > 0) filter_text else blk: {
        std.debug.print("No filter specified, capturing all packets\n", .{});
        break :blk "";
    };

    // Start capture
    var session = try capture.CaptureSession.init(
        allocator,
        selected_interface.name,
        true,  // promiscuous mode
        1000,   // timeout in ms
        65535 // snapshot length
    );
    defer session.deinit();


    std.debug.print("Applying filter: {s}\n", .{filter});
    try session.setFilter(filter);

    // Capture packets in a loop
    std.debug.print("Press Ctrl+C to stop capturing\n\n", .{});
    while (true) {
        const if_packet = try session.capturePacket();
        if (if_packet) |packet| {
            // If a packet was captured and parsed, print its info
            printPacketInfo(packet);
        } else {
            // Handle timeout or non-IP packets (if filter is "ip")
            // You could add a small sleep here if desired to prevent busy-waiting on timeout
            // std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
}

fn printPacketInfo(packet: capture.PacketInfo) void {
    // Protocol-specific display
    switch (packet.protocol) {
        .TCP, .UDP => {
            std.debug.print("{s} {d}.{d}.{d}.{d}:{d} -> {d}.{d}.{d}.{d}:{d} [{d} bytes]\n", 
                .{
                    @tagName(packet.protocol),
                    packet.source_ip[0], packet.source_ip[1], packet.source_ip[2], packet.source_ip[3],
                    packet.source_port,
                    packet.dest_ip[0], packet.dest_ip[1], packet.dest_ip[2], packet.dest_ip[3],
                    packet.dest_port,
                    packet.captured_len, // Fixed: was packet.size
                }
            );
        },
        .ICMP => {
            // For ICMP, we store type and code in source_port and dest_port fields
            const icmp_type = packet.source_port;
            const icmp_code = packet.dest_port;
            std.debug.print("ICMP {d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d} [Type: {d}, Code: {d}, {d} bytes]\n", 
                .{
                    packet.source_ip[0], packet.source_ip[1], packet.source_ip[2], packet.source_ip[3],
                    packet.dest_ip[0], packet.dest_ip[1], packet.dest_ip[2], packet.dest_ip[3],
                    icmp_type, icmp_code,
                    packet.captured_len,
                }
            );
        },
        else => {
            std.debug.print("{s} {d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d} [{d} bytes]\n", 
                .{
                    @tagName(packet.protocol),
                    packet.source_ip[0], packet.source_ip[1], packet.source_ip[2], packet.source_ip[3],
                    packet.dest_ip[0], packet.dest_ip[1], packet.dest_ip[2], packet.dest_ip[3],
                    packet.captured_len,
                }
            );
        }
    }

    // Display payload information if available
    if (packet.payload) |payload| {
        if (payload.len > 0) {
            std.debug.print("  Payload: {d} bytes", .{payload.len});
            
            // Display first 16 bytes of payload (or less if payload is smaller)
            const display_len = @min(payload.len, 16);
            std.debug.print(" | First {d} bytes: ", .{display_len});
            
            for (payload[0..display_len]) |byte| {
                std.debug.print("{X:0>2} ", .{byte});
            }
            
            // If we have more data, show that it continues
            if (payload.len > 16) {
                std.debug.print("...", .{});
            }
            
            std.debug.print("\n", .{});
        }
    }
}