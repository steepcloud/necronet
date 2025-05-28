const std = @import("std");
const capture = @import("backend");
const detection = @import("detection");
const parser = @import("parser");
const common = @import("common");
const ipc = @import("ipc");

var enable_gui = true;

// init alert counters
var total_packets: u32 = 0;
var alert_count: u32 = 0;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // skipping first argument (executable name)
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--no-gui")) {
            enable_gui = false;
            std.debug.print("GUI disabled, running in CLI mode\n", .{});
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("Necronet - Oddworld-themed Network Security Monitor\n\n", .{});
            std.debug.print("Usage: necronet [options]\n\n", .{});
            std.debug.print("Options:\n", .{});
            std.debug.print("  --no-gui     Run in CLI mode without GUI\n", .{});
            std.debug.print("  --help, -h   Show this help message\n", .{});
            return;
        }
    }
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

    // init detection engine
    var engine = try detection.DetectionEngine.init(allocator);
    defer engine.deinit();

    // init IPC for GUI communication
    var ipc_server: ?*ipc.IPCServer = null;
    defer if (ipc_server) |server| server.deinit();

    if (enable_gui) {
        ipc_server = try ipc.IPCServer.init(allocator);
        std.debug.print("IPC server initialized for UI communication\n", .{});

        const ui = @import("ui");
        _ = try std.Thread.spawn(.{}, ui.main, .{allocator});
        std.debug.print("UI launched in separate thread\n", .{});
    }

    // load default detection rules
    try engine.loadDefaultRules();

    // Capture packets in a loop
    std.debug.print("Press Ctrl+C to stop capturing\n\n", .{});
    std.debug.print("Starting packet capture with intrusion detection...\n", .{});
    
    while (true) {
        const packet_data = try session.captureRawPacket();

        if (packet_data) |data| {
            // parsing packet
            const pcap_header = data.header;
            const packet_bytes = data.packet_data[0..data.header.caplen];

            // get the parsed packet info
            const packet_info = try capture.parsePacketInfo(pcap_header, packet_bytes.ptr);
            
            if (packet_info) |packet| {
                total_packets += 1;

                // displaying packet info
                printPacketInfo(packet);

                // running the packet through the detection engine
                if (try engine.analyzePacket(packet, packet_bytes)) |alert| {
                    alert_count += 1;

                    // printing alert info
                    printAlert(alert);

                    @constCast(&alert).deinit(allocator);
                }

                if (enable_gui and ipc_server != null) {
                    const flow_id = getFlowId(packet);

                    const msg = @import("messages");
                    
                    // only send alert message if there is an alert for this packet
                    if (try engine.analyzePacket(packet, packet_bytes)) |alert_result| {
                        const slig_alert = try msg.SligAlert.fromDetectionAlert(alert_result, allocator);
                        const alert_msg = try msg.createSligAlertMsg(alert_count, slig_alert, allocator);

                        _ = ipc_server.?.broadcast(&alert_msg) catch |err| {
                            std.log.warn("Failed to send alert: {}", .{err});
                        };
                        
                        @constCast(&alert_result).deinit(allocator);
                    }
                    
                    const packet_event = msg.PacketEvent{
                        .flow_id = flow_id,
                        .timestamp = std.time.timestamp(),
                        .protocol = packet.protocol,
                        .source_ip = packet.source_ip,
                        .source_port = packet.source_port,
                        .dest_ip = packet.dest_ip,
                        .dest_port = packet.dest_port,
                        .packet_size = packet.captured_len,
                        .flags = .{
                            .syn = (packet.tcp_flags & 0x02) != 0,
                            .ack = (packet.tcp_flags & 0x10) != 0,
                            .fin = (packet.tcp_flags & 0x01) != 0,
                            .rst = (packet.tcp_flags & 0x04) != 0,
                            .psh = (packet.tcp_flags & 0x08) != 0,
                            .urg = (packet.tcp_flags & 0x20) != 0,
                            .fragmented = (packet.ip_flags & 0x01) != 0,
                            .retransmission = false, // TODO: implement retransmission detection
                        },
                        .payload = null, // not sending full payload to UI
                    };

                    // send packet event to UI
                    const ipc_msg = msg.createPacketEventMsg(total_packets, packet_event);
                    _ = ipc_server.?.broadcast(&ipc_msg) catch |err| {
                        std.log.warn("Failed to send packet event: {}", .{err});
                    };
                }

                // status update every 100 packets
                if (total_packets % 100 == 0) {
                    std.debug.print("\n--- Stats: {d} packets processed, {d} alerts generated ---\n\n", 
                        .{total_packets, alert_count});
                }
            }

            allocator.free(data.packet_data);
        } else {
            // no packet available (timeout)
            std.time.sleep(10 * std.time.ns_per_ms); // small sleep to prevent CPU hogging
        }
    }
}

fn printPacketInfo(packet: capture.PacketInfo) void {
    if (enable_gui) {
        if (total_packets % 1000 == 0) {
            std.debug.print("\n--- Stats: {d} packets processed, {d} alerts generated ---\n\n", 
                .{total_packets, alert_count});
        }
        return;
    }

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
                    packet.captured_len,
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

            // --- Protocol parser integration ---
            if (parser.parsePacket(std.heap.page_allocator, packet, payload) catch null) |proto_parser| {
                defer proto_parser.deinit(std.heap.page_allocator);

                // HTTP
                if (packet.protocol == .TCP and (packet.dest_port == 80 or packet.dest_port == 8080)) {
                    const http: *parser.HttpParser = @fieldParentPtr("base", proto_parser);
                    if (http.is_request and http.method.len > 0 and http.uri.len > 0) {
                        std.debug.print("  HTTP Request: {s} {s}\n", .{http.method, http.uri});
                    } else if (!http.is_request and http.status_code.len > 0 and http.reason_phrase.len > 0) {
                        std.debug.print("  HTTP Response: {s} {s}\n", .{http.status_code, http.reason_phrase});
                    }
                } else if ((packet.protocol == .TCP or packet.protocol == .UDP) and (packet.dest_port == 53 or packet.source_port == 53)) {
                    // DNS
                    const dns: *parser.DnsParser = @fieldParentPtr("base", proto_parser);
                    if (dns.questions.items.len > 0) {
                        std.debug.print("  DNS Questions:\n", .{});
                        for (dns.questions.items) |q| {
                            std.debug.print("    {s} (type {d})\n", .{q.name, q.type});
                        }
                    }
                    if (dns.answers.items.len > 0) {
                        std.debug.print("  DNS Answers:\n", .{});
                        for (dns.answers.items) |a| {
                            std.debug.print("    {s} (type {d})", .{a.name, a.type});
                            if (a.type == 1 or a.type == 28 or a.type == 5) { // A, AAAA, CNAME
                                std.debug.print(" -> {s}", .{a.data});
                            } else if (a.data.len > 0) {
                                std.debug.print(" [RDATA: ", .{});
                                for (a.data) |b| std.debug.print("{X:0>2} ", .{b});
                                std.debug.print("]", .{});
                            }
                            std.debug.print("\n", .{});
                        }
                    }
                }
            }
        }
    }
}

fn printAlert(alert: detection.Alert) void {
    if (enable_gui) {
        std.debug.print("\n[!] ALERT: {s}\n", .{alert.message});
        return;
    }
    // get severity color
    const color = switch (alert.severity) {
        .Low => "\x1b[34m", // blue
        .Medium => "\x1b[33m", // yellow
        .High => "\x1b[31m", // red
        .Critical => "\x1b[35m", // magenta
    };

    const reset = "\x1b[0m";

    // printing alert with colored severity
    std.debug.print("\n{s}[!] ALERT [{s}] ID: {d} [!]{s}\n", .{
        color, @tagName(alert.severity), alert.id, reset
    });

    std.debug.print("Category: {s}\n", .{alert.category});
    std.debug.print("Message: {s}\n", .{alert.message});
    
    // printing timestamp as human-readable date
    //const timestamp_seconds = @as(u64, @intCast(alert.timestamp));
    //const timestamp_nanos = timestamp_seconds * std.time.ns_per_s;
    
    var buffer: [64]u8 = undefined;
    const timestamp_str = if (alert.timestamp >= 0) blk: {
        const epoch_seconds = @as(u64, @intCast(alert.timestamp));
            
        const secs_per_day = 86400;
        const secs_per_hour = 3600;
        const secs_per_min = 60;

        // calc year (approx.)
        const days_since_epoch = epoch_seconds / secs_per_day;
        const years_since_epoch = days_since_epoch / 365;
        const year = 1970 + years_since_epoch;
            
        const day_secs = epoch_seconds % secs_per_day;
        const hours = day_secs / secs_per_hour;
        const mins = (day_secs % secs_per_hour) / secs_per_min;
        const secs = day_secs % secs_per_min;
            
        // YYYY-MM-DD HH:MM:SS
        break :blk std.fmt.bufPrint(&buffer, "{d}-??-?? {d:0>2}:{d:0>2}:{d:0>2}",
            .{ year, hours, mins, secs }) catch "unknown time";
    } else "before 1970";
    
    std.debug.print("Time: {s}\n", .{timestamp_str});
    std.debug.print("Source: {d}.{d}.{d}.{d}:{d}\n", .{
        alert.source_ip[0], alert.source_ip[1], alert.source_ip[2], alert.source_ip[3], 
        alert.source_port
    });
    std.debug.print("Destination: {d}.{d}.{d}.{d}:{d}\n", .{
        alert.dest_ip[0], alert.dest_ip[1], alert.dest_ip[2], alert.dest_ip[3], 
        alert.dest_port
    });
    std.debug.print("Protocol: {s}\n", .{@tagName(alert.protocol)});
    std.debug.print("{s}------------------------------------------{s}\n", .{color, reset});
}

fn getFlowId(packet: capture.PacketInfo) u64 {
    var hasher = std.hash.Wyhash.init(0);
    
    // Hash source and destination
    std.hash.autoHash(&hasher, packet.source_ip);
    std.hash.autoHash(&hasher, packet.dest_ip);
    std.hash.autoHash(&hasher, packet.source_port);
    std.hash.autoHash(&hasher, packet.dest_port);
    std.hash.autoHash(&hasher, @intFromEnum(packet.protocol));
    
    return hasher.final();
}