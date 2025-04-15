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
    const input = try stdin.readUntilDelimiterOrEof(buf[0..], '\n');
    const selected_index = try std.fmt.parseInt(usize, std.mem.trim(u8, input.?, " \r\n\t"), 10);

    if (selected_index >= interfaces.len) {
        std.debug.print("Invalid selection\n", .{});
        return;
    }

    const selected_interface = interfaces[selected_index];
    std.debug.print("Starting capture on {s}...\n", .{selected_interface.name});

    // Start capture
    var session = try capture.CaptureSession.init(
        allocator,
        selected_interface.name,
        true,  // promiscuous mode
        1000   // timeout in ms
    );
    defer session.deinit();

    // Optional: set a filter (e.g., "tcp or udp")
    try session.setFilter("ip");

    // Capture packets in a loop
    std.debug.print("Press Ctrl+C to stop capturing\n\n", .{});
    while (true) {
        if (try session.capturePacket()) |packet| {
            printPacketInfo(packet);
        }
    }
}

fn printPacketInfo(packet: capture.PacketInfo) void {
    std.debug.print("{s} {d}.{d}.{d}.{d}:{d} -> {d}.{d}.{d}.{d}:{d} [{d} bytes]\n", 
        .{
            @tagName(packet.protocol),
            packet.source_ip[0], packet.source_ip[1], packet.source_ip[2], packet.source_ip[3],
            packet.source_port,
            packet.dest_ip[0], packet.dest_ip[1], packet.dest_ip[2], packet.dest_ip[3],
            packet.dest_port,
            packet.size,
        }
    );
}