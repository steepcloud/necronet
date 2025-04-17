const std = @import("std");
const Endian = std.builtin.Endian;
const Allocator = std.mem.Allocator;
const common = @import("common");
const log = std.log.scoped(.capture);

pub const c = @cImport({
    @cInclude("pcap_wrapper.h");
});

pub const Error = error{
    NoDevicesFound,
    DeviceNotFound,
    CaptureInitFailed,
    SetFilterFailed,
    PacketCaptureFailed,
    InvalidPacketHeader,
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
    captured_len: u32, // caplen
    original_len: u32, // len
    timestamp_sec: i64,
    timestamp_usec: i64, // for precision
    checksum: u16,
    payload: ?[]const u8,
};

pub const EthernetHeader = extern struct {
    dest_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: u16, // Big Endian

    pub fn etherType(self: EthernetHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.ether_type));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

pub const IpV4Header = extern struct {
    version_ihl: u8, // version: 4 bits, ihl: 4 bits
    dscp_ecn: u8, // dscp: 6 bits, ecn: 2 bits
    total_length: u16, // Big Endian
    identification: u16, // Big Endian
    flags_fragment_offset: u16, // flags: 3 bits, fragment offset: 13 bits
    ttl: u8,
    protocol: u8,
    checksum: u16, // Big Endian
    source_ip: [4]u8, // Network order (Big Endian conceptually)
    dest_ip: [4]u8, // Network order

    pub fn ihl(self: IpV4Header) u8 {
        return self.version_ihl & 0x0F;
    }

    pub fn headerLength(self: IpV4Header) u8 {
        return self.ihl() * 4;
    }

    pub fn totalLength(self: IpV4Header) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.total_length));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

pub const TcpHeader = extern struct {
    source_port: u16, // Big Endian
    dest_port: u16, // Big Endian
    sequence_number: u32, // Big Endian
    ack_number: u32, // Big Endian
    data_offset_reserved_flags: u16, // Big Endian: Data Offset (4), Reserved (3), NS(1), CWR(1), ECE(1), URG(1), ACK(1), PSH(1), RST(1), SYN(1), FIN(1)
    window_size: u16, // Big Endian
    checksum: u16, // Big Endian
    urgent_pointer: u16, // Big Endian
    // Options follow here, variable length

    pub fn sourcePort(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.source_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    pub fn destPort(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.dest_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    pub fn sequenceNumber(self: TcpHeader) u32 {
        const ptr = @as(*const [4]u8, @ptrCast(&self.sequence_number));
        return std.mem.readInt(u32, ptr, Endian.big);
    }
    pub fn ackNumber(self: TcpHeader) u32 {
        const ptr = @as(*const [4]u8, @ptrCast(&self.ack_number));
        return std.mem.readInt(u32, ptr, Endian.big);
    }
    // Helper to get Data Offset (header length in 32-bit words)
    pub fn dataOffset(self: TcpHeader) u4 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.data_offset_reserved_flags));
        const val = std.mem.readInt(u16, ptr, Endian.big);
        return @intCast(val >> 12); // Top 4 bits
    }
    // Helper to get header length in bytes
    pub fn headerLength(self: TcpHeader) u8 {
        return @as(u8, self.dataOffset()) * 4;
    }
    // Individual flag helpers
    pub fn flags(self: TcpHeader) u9 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.data_offset_reserved_flags));
        const val = std.mem.readInt(u16, ptr, Endian.big);
        return @intCast(val & 0x1FF); // Lower 9 bits
    }
    pub fn flagFIN(self: TcpHeader) bool { return (self.flags() & 0x001) != 0; }
    pub fn flagSYN(self: TcpHeader) bool { return (self.flags() & 0x002) != 0; }
    pub fn flagRST(self: TcpHeader) bool { return (self.flags() & 0x004) != 0; }
    pub fn flagPSH(self: TcpHeader) bool { return (self.flags() & 0x008) != 0; }
    pub fn flagACK(self: TcpHeader) bool { return (self.flags() & 0x010) != 0; }
    pub fn flagURG(self: TcpHeader) bool { return (self.flags() & 0x020) != 0; }
    pub fn flagECE(self: TcpHeader) bool { return (self.flags() & 0x040) != 0; }
    pub fn flagCWR(self: TcpHeader) bool { return (self.flags() & 0x080) != 0; }
    pub fn flagNS(self: TcpHeader) bool { return (self.flags() & 0x100) != 0; }

    pub fn windowSize(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.window_size));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    pub fn getChecksum(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.checksum));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    pub fn urgentPointer(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.urgent_pointer));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

pub const UdpHeader = extern struct {
    source_port: u16, // Big Endian
    dest_port: u16, // Big Endian
    length: u16, // Big Endian - Length of UDP header + data
    checksum: u16, // Big Endian

    pub fn sourcePort(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.source_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    pub fn destPort(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.dest_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    // Returns length of UDP header + UDP data
    pub fn getLength(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.length));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    pub fn getChecksum(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.checksum));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

pub const CaptureSession = struct {
    handle: ?*c.pcap_t,
    device_name: []const u8,
    allocator: Allocator,

    // Creates a new capture session for the specified device
    pub fn init(
        allocator: Allocator, 
        device_name: []const u8, 
        promiscuous: bool, 
        timeout_ms: u32,
        snapshot_len: u32
    ) !CaptureSession {
        var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        
        const handle = c.pcap_open_live(
            @ptrCast(device_name.ptr),
            @intCast(snapshot_len),
            if (promiscuous) 1 else 0,
            @intCast(timeout_ms),
            &errbuf,
        );
        
        if (handle == null) {
            log.err("Failed to open device {s}: {s}\n", .{device_name, errbuf});
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
    
    pub fn setFilter(self: *CaptureSession, filter_str: []const u8) !void {
        // expand shorthand filters to proper BPF syntax
        const expanded_filter = try expandFilterExpression(filter_str, self.allocator);
        defer self.allocator.free(expanded_filter);

        // convert to null-terminated string
        const c_filter = try self.allocator.dupeZ(u8, expanded_filter);
        defer self.allocator.free(c_filter);

        // compile the filter expression
        var program: c.struct_bpf_program = undefined;

        // using netmask for proper filter compilation (PCAP requires this)
        const netmask: c.bpf_u_int32 = 0xffffff00; // 255.255.255.0

        const result = c.pcap_compile(self.handle, &program, c_filter.ptr, 1, netmask);
        if (result < 0) {
            const err_msg = c.pcap_geterr(self.handle);
            log.err("Failed to compile filter: {s}\n", .{err_msg});
            return Error.SetFilterFailed;
        }
        defer c.pcap_freecode(&program);
        
        // Apply the filter
        const set_result = c.pcap_setfilter(self.handle, &program);
        if (set_result < 0) {
            const err_msg = c.pcap_geterr(self.handle);
            log.err("Failed to set filter: {s}\n", .{err_msg});
            return Error.SetFilterFailed;
        }

        if (!std.mem.eql(u8, filter_str, expanded_filter)) {
            log.info("Expanded filter '{s}' to '{s}'\n", .{filter_str, expanded_filter});
        }
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

pub const IcmpHeader = extern struct {
    type: u8,
    code: u8,
    checksum: u16, // Big Endian
    rest_of_header: u32, // Big Endian, contents vary by type/c_longdouble

    pub fn getType(self: IcmpHeader) u8 {
        return self.type;
    }

    pub fn getCode(self: IcmpHeader) u8 {
        return self.code;
    }

    pub fn getChecksum(self: IcmpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.checksum));
        return std.mem.readInt(u16, ptr, Endian.big);
    }

    pub fn getId(self: IcmpHeader) u16 {
        // for echo request/reply (types 0 and 8), first 2 bytes of rest_of_header is ID
        if (self.type == 0 or self.type == 8) {
            const ptr = @as(*const [4]u8, @ptrCast(&self.rest_of_header));
            return std.mem.readInt(u16, ptr[0..2], Endian.big);
        }
        return 0;
    }

    pub fn getSeq(self: IcmpHeader) u16 {
        // for echo request/reply (types 0 and 8), last 2 bytes of rest_of_header is sequence
        if (self.type == 0 or self.type == 8) {
            const ptr = @as(*const [4]u8, @ptrCast(&self.rest_of_header));
            return std.mem.readInt(u16, ptr[2..4], Endian.big);
        }
        return 0;
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
pub fn parsePacketInfo(header: c.struct_pcap_pkthdr, packet_data: [*]const u8) !?PacketInfo {
    const caplen = header.caplen; // Use captured length for bounds checks

    // Check minimum length for Ethernet header
    if (caplen < @sizeOf(EthernetHeader)) return null;

    // Use @ptrCast to view the start of packet_data as an EthernetHeader
    // WARNING: Assumes sufficient alignment from pcap.
    var eth_header_aligned: EthernetHeader = undefined;
    @memcpy(std.mem.asBytes(&eth_header_aligned), packet_data[0..@sizeOf(EthernetHeader)]);
    const eth_header = &eth_header_aligned;

    // Check EtherType for IPv4
    if (eth_header.etherType() != 0x0800) return null; // Not IPv4

    // Check length for minimum IPv4 header
    const ip_offset = @sizeOf(EthernetHeader);
    if (caplen < ip_offset + @sizeOf(IpV4Header)) {
        log.debug("Packet too short for IPv4 header (caplen: {}, required: {})", 
                .{ caplen, ip_offset + @sizeOf(IpV4Header) });
        return Error.InvalidPacketHeader;
    }

    var ip_header_aligned: IpV4Header = undefined;
    @memcpy(std.mem.asBytes(&ip_header_aligned), packet_data[ip_offset..ip_offset+@sizeOf(IpV4Header)]);
    const ip_header = &ip_header_aligned;

    // Validate IP header length field against captured length
    const ip_hdr_len_bytes = ip_header.headerLength();
    if (ip_hdr_len_bytes < 20 or caplen < ip_offset + ip_hdr_len_bytes) {
        // Invalid header length or packet too short for declared header length
        log.debug("Invalid IP header length ({}) or insufficient captured data ({})", .{ ip_hdr_len_bytes, caplen });
        return Error.InvalidPacketHeader;
    }

    var protocol_type: common.Protocol = .Unknown;
    var source_port: u16 = 0;
    var dest_port: u16 = 0;
    var transport_checksum: u16 = 0;

    const transport_offset = ip_offset + ip_hdr_len_bytes;

    switch (ip_header.protocol) {
        6 => { // TCP
            protocol_type = .TCP;
            // Check length for minimum TCP header (fixed part)
            if (caplen >= transport_offset + @sizeOf(TcpHeader)) {
                var tcp_header_aligned: TcpHeader = undefined;
                @memcpy(std.mem.asBytes(&tcp_header_aligned), packet_data[transport_offset..transport_offset+@sizeOf(TcpHeader)]);
                const tcp_header = &tcp_header_aligned;

                // Optional: Validate TCP header length against captured length
                const tcp_hdr_len_bytes = tcp_header.headerLength();
                if (tcp_hdr_len_bytes < 20 or caplen < transport_offset + tcp_hdr_len_bytes) {
                    log.debug("Invalid TCP header length ({}) or insufficient captured data ({})", .{ tcp_hdr_len_bytes, caplen });
                    return Error.InvalidPacketHeader;
                }

                source_port = tcp_header.sourcePort();
                dest_port = tcp_header.destPort();
                transport_checksum = tcp_header.getChecksum();
            } else {
                log.debug("Packet too short for TCP header (caplen: {}, required: {})", .{ caplen, transport_offset + @sizeOf(TcpHeader) });
                return Error.InvalidPacketHeader; // Packet too short for fixed TCP header part
            }
        },
        17 => { // UDP
            protocol_type = .UDP;
            // Check length for UDP header
            if (caplen >= transport_offset + @sizeOf(UdpHeader)) {
                var udp_header_aligned: UdpHeader = undefined;
                @memcpy(std.mem.asBytes(&udp_header_aligned), packet_data[transport_offset..transport_offset+@sizeOf(UdpHeader)]);
                const udp_header = &udp_header_aligned;
                
                source_port = udp_header.sourcePort();
                dest_port = udp_header.destPort();
                transport_checksum = udp_header.getChecksum();
            } else {
                log.debug("Packet too short for UDP header (caplen: {}, required: {})", .{ caplen, transport_offset + @sizeOf(UdpHeader) });
                return Error.InvalidPacketHeader;
            }
        },
        1 => { // ICMP
            protocol_type = .ICMP;
            // Parsing ICMP header fields
            if (caplen >= transport_offset + @sizeOf(IcmpHeader)) {
                var icmp_header_aligned: IcmpHeader = undefined;
                @memcpy(std.mem.asBytes(&icmp_header_aligned),
                packet_data[transport_offset..transport_offset+@sizeOf(IcmpHeader)]);
                const icmp_header = &icmp_header_aligned;

                // we don't have ports for ICMP, but instead we can store
                // the type and code in the source_port and dest_port fields
                // for use in detection rules
                source_port = icmp_header.getType();
                dest_port = icmp_header.getCode();
                transport_checksum = icmp_header.getChecksum();
            } else {
                log.debug("Packet too short for ICMP header (caplen : {}, required: {})",
                    .{ caplen, transport_offset + @sizeOf(IcmpHeader) });
                return Error.InvalidPacketHeader;
            }
        },
        else => {
             log.debug("Unknown IP protocol: {}", .{ip_header.protocol});
        },
    }

    var payload_offset: usize = 0;
    var payload_length: usize = 0;

    switch(protocol_type) {
        .TCP => {
            if (caplen >= transport_offset + @sizeOf(TcpHeader)) {
                var tcp_header_aligned: TcpHeader = undefined;
                @memcpy(std.mem.asBytes(&tcp_header_aligned), 
                    packet_data[transport_offset..transport_offset+@sizeOf(TcpHeader)]);
                const tcp_header = &tcp_header_aligned;

                payload_offset = transport_offset + tcp_header.headerLength();
                if (payload_offset < caplen) {
                    payload_length = caplen - payload_offset;
                }
            }
        },
        .UDP => {
            payload_offset = transport_offset + @sizeOf(UdpHeader);
            if (payload_offset < caplen) {
                payload_length = caplen - payload_offset;
            }
        },
        .ICMP => {
            payload_offset = transport_offset + @sizeOf(IcmpHeader);
            if (payload_offset < caplen) {
                payload_length = caplen - payload_offset;
            }
        },
        else => {},
    }

    // extract payload slice (always creating a slice, even if length is 0)
    const payload_slice = if (payload_length > 0) 
        packet_data[payload_offset..payload_offset+payload_length]
    else if (payload_offset > 0)
        @as([*]const u8, @ptrCast(&packet_data[payload_offset]))[0..0] // empty slice at the current offset
    else 
        &[_]u8{}; // generic empty slice if we have no valid offset

    return PacketInfo{
        .source_ip = ip_header.source_ip,
        .dest_ip = ip_header.dest_ip,
        .source_port = source_port,
        .dest_port = dest_port,
        .protocol = protocol_type,
        .captured_len = caplen,
        .original_len = header.len,
        .timestamp_sec = header.ts.tv_sec,
        .timestamp_usec = header.ts.tv_usec,
        .checksum = transport_checksum,
        .payload = payload_slice,
    };
}

fn expandFilterExpression(filter: []const u8, allocator: Allocator) ![]const u8 {
    // Common shorthands and their proper BPF expressions
    if (std.mem.eql(u8, filter, "dns")) {
        return allocator.dupe(u8, "udp port 53 or tcp port 53");
    } else if (std.mem.eql(u8, filter, "http")) {
        return allocator.dupe(u8, "tcp port 80");
    } else if (std.mem.eql(u8, filter, "https")) {
        return allocator.dupe(u8, "tcp port 443");
    } else if (std.mem.eql(u8, filter, "web")) {
        return allocator.dupe(u8, "tcp port 80 or tcp port 443");
    } else if (std.mem.eql(u8, filter, "ssh")) {
        return allocator.dupe(u8, "tcp port 22");
    } else if (std.mem.eql(u8, filter, "telnet")) {
        return allocator.dupe(u8, "tcp port 23");
    } else if (std.mem.eql(u8, filter, "ftp")) {
        return allocator.dupe(u8, "tcp port 21");
    } else if (std.mem.eql(u8, filter, "smtp")) {
        return allocator.dupe(u8, "tcp port 25");
    } else if (std.mem.eql(u8, filter, "mail")) {
        return allocator.dupe(u8, "tcp port 25 or tcp port 110 or tcp port 143");
    } else if (std.mem.eql(u8, filter, "dhcp")) {
        return allocator.dupe(u8, "udp port 67 or udp port 68");
    } else if (std.mem.eql(u8, filter, "ntp")) {
        return allocator.dupe(u8, "udp port 123");
    } else if (std.mem.eql(u8, filter, "snmp")) {
        return allocator.dupe(u8, "udp port 161");
    }
    
    // If not a known shorthand, return the original filter
    return allocator.dupe(u8, filter);
}