const std = @import("std");
const Allocator = std.mem.Allocator;
const common = @import("common");

const c = @cImport({
    @cInclude("pcap_wrapper.h");
});

pub const Error = error{
    NoDevicesFound,
    DeviceNotFound,
    CaptureInitFailed,
    SetFilterFailed,
    PacketCaptureFailed,
};

pub const Interface = struct {
    name: []const u8,
    description: ?[]const u8,
    is_loopback: bool,
};

pub const PacketInfo = struct {
    source_ip: [4]u8,
    dest_ip: [4]u8,
    source_port: u16,
    dest_port: u16,
    protocol: common.Protocol,
    size: usize,
    timestamp: i64,
};

pub const CaptureSession = struct {
    handle: ?*c.pcap_t,
    device_name: []const u8,
    allocator: Allocator,

    // Creates a new capture session for the specified device
    pub fn init(allocator: Allocator, device_name: []const u8, promiscuous: bool, timeout_ms: u32) !CaptureSession {
        var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        
        const handle = c.pcap_open_live(
            @ptrCast(device_name.ptr), 
            65535,  // Snapshot length (max packet size)
            if (promiscuous) 1 else 0, 
            @intCast(timeout_ms), 
            &errbuf
        );
        
        if (handle == null) {
            std.debug.print("Failed to open device {s}: {s}\n", .{device_name, errbuf});
            return Error.CaptureInitFailed;
        }
        
        return CaptureSession{
            .handle = handle,
            .device_name = try allocator.dupe(u8, device_name),
            .allocator = allocator,
        };
    }
    
    // Clean up resources
    pub fn deinit(self: *CaptureSession) void {
        if (self.handle) |handle| {
            c.pcap_close(handle);
            self.handle = null;
        }
        self.allocator.free(self.device_name);
    }
    
    // Set a BPF filter
    pub fn setFilter(self: *CaptureSession, filter_str: []const u8) !void {
        var bpf: c.struct_bpf_program = undefined;
        
        // Compile the filter
        if (c.pcap_compile(self.handle, &bpf, @ptrCast(filter_str.ptr), 1, 0) < 0) {
            std.debug.print("Failed to compile filter: {s}\n", .{c.pcap_geterr(self.handle)});
            return Error.SetFilterFailed;
        }
        
        // Apply the filter
        if (c.pcap_setfilter(self.handle, &bpf) < 0) {
            std.debug.print("Failed to set filter: {s}\n", .{c.pcap_geterr(self.handle)});
            c.pcap_freecode(&bpf);
            return Error.SetFilterFailed;
        }
        
        c.pcap_freecode(&bpf);
    }
    
    // Capture a single packet and parse its info
    pub fn capturePacket(self: *CaptureSession) !?PacketInfo {
        var header: ?*c.struct_pcap_pkthdr = undefined;
        var packet: ?*const u8 = undefined;
        
        const res = c.pcap_next_ex(self.handle, &header, &packet);
        
        if (res <= 0) {
            // Timeout or error
            if (res < 0) {
                return Error.PacketCaptureFailed;
            }
            return null;
        }
        
        // Parse basic packet info (for IPv4 packets)
        return parsePacketInfo((header.?).*, @as([*]const u8, @ptrCast(packet.?)));
    }
};

// Get a list of available network interfaces
pub fn getInterfaces(allocator: Allocator) ![]Interface {
    var err_buf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var dev_list: [*c]c.pcap_if_t = undefined;
    
    if (c.pcap_findalldevs(&dev_list, &err_buf) < 0) {
        std.debug.print("Error finding devices: {s}\n", .{err_buf});
        return Error.NoDevicesFound;
    }
    defer c.pcap_freealldevs(dev_list);
    
    var interface_list = std.ArrayList(Interface).init(allocator);
    errdefer interface_list.deinit();
    
    var current_dev = dev_list;
    while (current_dev != null) : (current_dev = current_dev.*.next) {
        const dev = current_dev.*;
        if (dev.name == null) continue;
        const name = try allocator.dupe(u8, std.mem.span(dev.name));
        errdefer allocator.free(name);
        
        var description: ?[]u8 = null;
        if (dev.description != null) {
            description = try allocator.dupe(u8, std.mem.span(dev.description));
            errdefer if (description) |d| allocator.free(d);
        }
        
        try interface_list.append(Interface{
            .name = name,
            .description = description,
            .is_loopback = (dev.flags & c.PCAP_IF_LOOPBACK) != 0,
        });
    }
    
    return interface_list.toOwnedSlice();
}

// Helper function to parse packet info
fn parsePacketInfo(header: c.struct_pcap_pkthdr, packet: [*]const u8) ?PacketInfo {
    // Skip packets that are too small to contain Ethernet + IP headers
    if (header.len < 14 + 20) return null;
    
    // Skip non-IP packets (check EtherType field)
    const ethertype = (@as(u16, packet[12]) << 8) | packet[13];
    if (ethertype != 0x0800) return null; // 0x0800 is IPv4
    
    // Parse IP header
    const ip_header = packet[14..];
    const ip_header_len = (ip_header[0] & 0x0F) * 4;
    
    // Skip packets with invalid IP header
    if (ip_header_len < 20) return null;
    
    // Parse protocol
    const protocol = ip_header[9];
    var protocol_type: common.Protocol = .Unknown;
    
    // Source and destination IP
    const source_ip: [4]u8 = .{ip_header[12], ip_header[13], ip_header[14], ip_header[15]};
    const dest_ip: [4]u8 = .{ip_header[16], ip_header[17], ip_header[18], ip_header[19]};
    
    // Default ports
    var source_port: u16 = 0;
    var dest_port: u16 = 0;
    
    // Transport layer header starts after IP header
    const transport_header = ip_header[ip_header_len..];
    
    // Parse TCP or UDP
    if (protocol == 6) { // TCP
        protocol_type = .TCP;
        if (header.len >= 14 + ip_header_len + 4) { // Enough space for TCP ports
            source_port = (@as(u16, transport_header[0]) << 8) | transport_header[1];
            dest_port = (@as(u16, transport_header[2]) << 8) | transport_header[3];
        }
    } else if (protocol == 17) { // UDP
        protocol_type = .UDP;
        if (header.len >= 14 + ip_header_len + 4) { // Enough space for UDP ports
            source_port = (@as(u16, transport_header[0]) << 8) | transport_header[1];
            dest_port = (@as(u16, transport_header[2]) << 8) | transport_header[3];
        }
    } else if (protocol == 1) { // ICMP
        protocol_type = .ICMP;
    }
    
    return PacketInfo{
        .source_ip = source_ip,
        .dest_ip = dest_ip,
        .source_port = source_port,
        .dest_port = dest_port,
        .protocol = protocol_type,
        .size = header.len,
        .timestamp = header.ts.tv_sec,
    };
}