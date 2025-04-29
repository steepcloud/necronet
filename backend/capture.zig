///////////////////////////////////////////////////////////////////////////////
// Network Packet Capture Module
//
// This module provides an interface to the pcap library for capturing and 
// analyzing network packets. It includes functionality for:
//   - Discovering network interfaces
//   - Capturing raw packets from network interfaces
//   - Parsing packet headers (Ethernet, IPv4, TCP, UDP, ICMP)
//   - Extracting packet metadata and payload
//
// The implementation handles network byte order conversions and provides
// structured access to network protocol fields while abstracting away the
// lower-level pcap C interface.
///////////////////////////////////////////////////////////////////////////////

const std = @import("std");
const Endian = std.builtin.Endian;
const Allocator = std.mem.Allocator;
const common = @import("common");
const log = std.log.scoped(.capture);

pub const c = @cImport({
    @cInclude("pcap_wrapper.h");
});

/// Error types specific to packet capture operations
pub const Error = error{
    NoDevicesFound, // no network interfaces were found
    DeviceNotFound, // the requested network device could not be found
    CaptureInitFailed, // failed to initialize the packet capture session
    SetFilterFailed, // failed to set the capture filter
    PacketCaptureFailed, // error occured during packet capture
    InvalidPacketHeader, // packet header is malformed or truncated
};

/// Represents a network interface available for packet capture
pub const Interface = struct {
    name: []const u8, // system identifier for the interface
    description: ?[]const u8, // human-readable description (may be null)
    is_loopback: bool, // whether this is a loopback interface
};

/// Raw packet data as returned directly from pcap
pub const RawPacketData = struct {
    header: c.struct_pcap_pkthdr, // metadata about the captured packet
    packet_data: []u8, // raw binary packet data
};

/// Parsed information about a captured network packet
pub const PacketInfo = struct {
    source_ip: [4]u8, // source IPv4 address in network byte order
    dest_ip: [4]u8, // destination IPv4 address in network byte order
    source_port: u16, // source port (TCP/UDP) or type (ICMP)
    dest_port: u16, // destination port (TCP/UDP) or code (ICMP)
    protocol: common.Protocol, // protocol type (TCP, UDP, ICMP, etc.)
    captured_len: u32, // length of captured packet data (may be truncated)
    original_len: u32, // original length of packet on wire
    timestamp_sec: i64, // timestamp seconds component
    timestamp_usec: i64, // timestamp microseconds component
    checksum: u16, // transport layer checksum
    payload: ?[]const u8, // protocol payload data (application layer)
    tcp_flags: u8 = 0, // TCP flags (SYN, ACK, etc.)
    ip_flags: u8 = 0, // IP flags (fragmentation, etc.)
    flow_id: ?u64 = null, // optional flow ID for tracking related packets
};

/// Ethernet frame header structure
pub const EthernetHeader = extern struct {
    dest_mac: [6]u8, // destination MAC address
    src_mac: [6]u8, // source MAC address
    ether_type: u16, // ethernet type field in network byte order

    /// Get the EtherType value in host byte order
    pub fn etherType(self: EthernetHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.ether_type));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

/// IPv4 packet header structure
pub const IpV4Header = extern struct {
    version_ihl: u8, // version: 4 bits, ihl: 4 bits
    dscp_ecn: u8, // dscp: 6 bits, ecn: 2 bits
    total_length: u16, // total length in network byte order
    identification: u16, // identification field in network byte order
    flags_fragment_offset: u16, // flags: 3 bits, fragment offset: 13 bits
    ttl: u8, // time to live
    protocol: u8, // protocol number (TCP=6, UDP=17, ICMP=1)
    checksum: u16, // header checksum in network byte order
    source_ip: [4]u8, // source IP adddress in network byte order
    dest_ip: [4]u8, // destination IP address in network byte order

    /// Get the Internet Header Length value (4 bits)
    pub fn ihl(self: IpV4Header) u8 {
        return self.version_ihl & 0x0F;
    }

    /// Get the header length in bytes
    pub fn headerLength(self: IpV4Header) u8 {
        return self.ihl() * 4;
    }

    /// Get the total length in host byte order
    pub fn totalLength(self: IpV4Header) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.total_length));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

/// TCP header structure
pub const TcpHeader = extern struct {
    source_port: u16, // source port in network byte order
    dest_port: u16, // destination port in network byte order
    sequence_number: u32, // sequence number in network byte order
    ack_number: u32, // acknowledgment number in network byte order
    data_offset_reserved_flags: u16, // Big Endian: Data Offset (4), Reserved (3), NS(1), CWR(1), ECE(1), URG(1), ACK(1), PSH(1), RST(1), SYN(1), FIN(1)
    window_size: u16, // window size in network byte order
    checksum: u16, // checksum in network byte order
    urgent_pointer: u16, // urgent pointer in network byte order

    /// Get source port in host byte order
    pub fn sourcePort(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.source_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }

    /// Get destination port in host byte order
    pub fn destPort(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.dest_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }

    /// Get sequence number in host byte order
    pub fn sequenceNumber(self: TcpHeader) u32 {
        const ptr = @as(*const [4]u8, @ptrCast(&self.sequence_number));
        return std.mem.readInt(u32, ptr, Endian.big);
    }

    /// Get acknowledgment number in host byte order
    pub fn ackNumber(self: TcpHeader) u32 {
        const ptr = @as(*const [4]u8, @ptrCast(&self.ack_number));
        return std.mem.readInt(u32, ptr, Endian.big);
    }
    
    /// Get the data offset value (header length in 32-bit words)
    pub fn dataOffset(self: TcpHeader) u4 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.data_offset_reserved_flags));
        const val = std.mem.readInt(u16, ptr, Endian.big);
        return @intCast(val >> 12); // top 4 bits
    }

    /// Get TCP header length in bytes
    pub fn headerLength(self: TcpHeader) u8 {
        return @as(u8, self.dataOffset()) * 4;
    }
    
    /// Get all TCP flags as a 9-bit value
    pub fn flags(self: TcpHeader) u9 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.data_offset_reserved_flags));
        const val = std.mem.readInt(u16, ptr, Endian.big);
        return @intCast(val & 0x1FF); // lower 9 bits
    }

    /// Get the TCP flags as individual boolean values
    pub fn flagFIN(self: TcpHeader) bool { return (self.flags() & 0x001) != 0; }
    pub fn flagSYN(self: TcpHeader) bool { return (self.flags() & 0x002) != 0; }
    pub fn flagRST(self: TcpHeader) bool { return (self.flags() & 0x004) != 0; }
    pub fn flagPSH(self: TcpHeader) bool { return (self.flags() & 0x008) != 0; }
    pub fn flagACK(self: TcpHeader) bool { return (self.flags() & 0x010) != 0; }
    pub fn flagURG(self: TcpHeader) bool { return (self.flags() & 0x020) != 0; }
    pub fn flagECE(self: TcpHeader) bool { return (self.flags() & 0x040) != 0; }
    pub fn flagCWR(self: TcpHeader) bool { return (self.flags() & 0x080) != 0; }
    pub fn flagNS(self: TcpHeader) bool { return (self.flags() & 0x100) != 0; }

    /// Get the window size in host byte order
    pub fn windowSize(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.window_size));
        return std.mem.readInt(u16, ptr, Endian.big);
    }

    /// Get checksum in host byte order
    pub fn getChecksum(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.checksum));
        return std.mem.readInt(u16, ptr, Endian.big);
    }

    /// Get urgent pointer in host byte order
    pub fn urgentPointer(self: TcpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.urgent_pointer));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

/// UDP header structure
pub const UdpHeader = extern struct {
    source_port: u16, // source port in network byte order
    dest_port: u16, // destination port in network byte order
    length: u16, // Big Endian - Length of UDP header + data (network byte order)
    checksum: u16, // checksum in network byte order

    /// Get source port in host byte order
    pub fn sourcePort(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.source_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    
    /// Get destination port in host byte order
    pub fn destPort(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.dest_port));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
    
    /// Get total length of UDP header and data in host byte order
    pub fn getLength(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.length));
        return std.mem.readInt(u16, ptr, Endian.big);
    }

    /// Get checksum in host byte order
    pub fn getChecksum(self: UdpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.checksum));
        return std.mem.readInt(u16, ptr, Endian.big);
    }
};

/// Active packet capture session
pub const CaptureSession = struct {
    handle: ?*c.pcap_t, // handle to pcap capture session
    device_name: []const u8, // name of the capture device
    allocator: Allocator, // memory allocator for this session

    /// Creates a new packet capture session on the specified network interface
    ///
    /// Parameters:
    ///   allocator: Memory allocator for managing resources
    ///   device_name: Network interface name to capture from
    ///   promiscuous: Whether to enable promiscuous mode
    ///   timeout_ms: Capture timeout in milliseconds
    ///   snapshot_len: Maximum number of bytes to capture per packet
    ///
    /// Returns:
    ///   A new CaptureSession or an error if initialization fails
    pub fn init(
        allocator: Allocator, 
        device_name: []const u8, 
        promiscuous: bool, 
        timeout_ms: u32,
        snapshot_len: u32
    ) !CaptureSession {
        var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        
        // open the device for live capture
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
    
    /// Cleans up resources used by the capture session
    pub fn deinit(self: *CaptureSession) void {
        if (self.handle) |handle| {
            c.pcap_close(handle);
            self.handle = null;
        }
        self.allocator.free(self.device_name);
    }
    
    /// Sets a BPF filter on the capture session to control which packets are captured
    ///
    /// This function supports both standard BPF filter syntax and common shorthand
    /// expressions like "dns", "http", etc.
    ///
    /// Parameters:
    ///   filter_str: BPF filter expression or shorthand term
    ///
    /// Returns:
    ///   Error if the filter cannot be compiled or applied
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
        
        // apply the filter
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
    
    /// Captures a single packet and parses it into a structured format
    ///
    /// Returns:
    ///   - PacketInfo containing parsed packet data
    ///   - null if timeout occurred with no packets available
    ///   - Error if capture failed or packet parsing failed
    pub fn capturePacket(self: *CaptureSession) !?PacketInfo {
        var header: ?*c.struct_pcap_pkthdr = undefined;
        var packet: ?*const u8 = undefined;
        
        const res = c.pcap_next_ex(self.handle, &header, &packet);
        
        if (res <= 0) {
            // timeout or error
            if (res < 0) {
                return Error.PacketCaptureFailed;
            }
            return null;
        }
        
        // parse basic packet info (for IPv4 packets)
        return parsePacketInfo((header.?).*, @as([*]const u8, @ptrCast(packet.?)));
    }

    /// Captures a single raw packet without parsing
    ///
    /// Returns:
    ///   - RawPacketData containing unparsed packet and header
    ///   - null if timeout occurred with no packets available
    ///   - Error if capture failed
    pub fn captureRawPacket(self: *CaptureSession) !?RawPacketData {
        var header: ?*c.struct_pcap_pkthdr = null;
        var packet_data: [*c]const u8 = null;

        // capture a packet
        const result = c.pcap_next_ex(self.handle, &header, &packet_data);
        
        if (result == 0) {
            // timeout
            return null;
        } else if (result < 0) {
            const err_msg = c.pcap_geterr(self.handle);
            log.err("Failed to capture packet: {s}", .{err_msg});
            return Error.PacketCaptureFailed;
        }

        if (header == null or packet_data == null) {
            log.debug("Received null packet", .{});
            return null;
        }

        // alloc memory for the packet data and copy it
        const caplen = header.?.caplen;
        const data_copy = try self.allocator.alloc(u8, caplen);
        @memcpy(data_copy, packet_data[0..caplen]);

        return RawPacketData{
            .header = header.?.*, 
            .packet_data = data_copy,
        };
    }
};

/// ICMP header structure
pub const IcmpHeader = extern struct {
    type: u8, // ICMP message type
    code: u8, // ICMP message code
    checksum: u16, // checksum in network byte order
    rest_of_header: u32, // remainder of header (varies by type/code)

    /// Get the ICMP message type
    pub fn getType(self: IcmpHeader) u8 {
        return self.type;
    }

    /// Get the ICMP message code
    pub fn getCode(self: IcmpHeader) u8 {
        return self.code;
    }

    /// Get the checksum in host byte order
    pub fn getChecksum(self: IcmpHeader) u16 {
        const ptr = @as(*const [2]u8, @ptrCast(&self.checksum));
        return std.mem.readInt(u16, ptr, Endian.big);
    }

    /// Get the identifier for echo request/reply messages
    pub fn getId(self: IcmpHeader) u16 {
        // for echo request/reply (types 0 and 8), first 2 bytes of rest_of_header is ID
        if (self.type == 0 or self.type == 8) {
            const ptr = @as(*const [4]u8, @ptrCast(&self.rest_of_header));
            return std.mem.readInt(u16, ptr[0..2], Endian.big);
        }
        return 0;
    }

    /// Get the sequence number for echo request/reply messages
    pub fn getSeq(self: IcmpHeader) u16 {
        // for echo request/reply (types 0 and 8), last 2 bytes of rest_of_header is sequence
        if (self.type == 0 or self.type == 8) {
            const ptr = @as(*const [4]u8, @ptrCast(&self.rest_of_header));
            return std.mem.readInt(u16, ptr[2..4], Endian.big);
        }
        return 0;
    }
};

/// Get a list of all available network interfaces on the system
///
/// Parameters:
///   allocator: Memory allocator for the returned interface list
///
/// Returns:
///   Slice of Interface structs, caller owns the memory
///
/// Errors:
///   NoDevicesFound if no interfaces are available or an error occurs
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

/// Parses raw packet data into a structured PacketInfo
///
/// This function handles the complexities of network protocol parsing,
/// extracting headers and payload data from Ethernet, IP, TCP, UDP, and ICMP
/// packets. It manages endianness conversions and provides a clean interface
/// to packet metadata.
///
/// Parameters:
///   header: pcap packet header with timing and size information
///   packet_data: Raw packet bytes from the capture
///
/// Returns:
///   Parsed PacketInfo or null if the packet is not of a supported type
///   May return error if packet is malformed or truncated
pub fn parsePacketInfo(header: c.struct_pcap_pkthdr, packet_data: [*]const u8) !?PacketInfo {
    const caplen = header.caplen; // use captured length for bounds checks

    // check minimum length for Ethernet header
    if (caplen < @sizeOf(EthernetHeader)) return null;

    // @ptrCast to view the start of packet_data as an EthernetHeader
    // WARNING: Assumes sufficient alignment from pcap.
    var eth_header_aligned: EthernetHeader = undefined;
    @memcpy(std.mem.asBytes(&eth_header_aligned), packet_data[0..@sizeOf(EthernetHeader)]);
    const eth_header = &eth_header_aligned;

    // check EtherType for IPv4
    if (eth_header.etherType() != 0x0800) return null; // not IPv4

    // check length for minimum IPv4 header
    const ip_offset = @sizeOf(EthernetHeader);
    if (caplen < ip_offset + @sizeOf(IpV4Header)) {
        log.debug("Packet too short for IPv4 header (caplen: {}, required: {})", 
                .{ caplen, ip_offset + @sizeOf(IpV4Header) });
        return Error.InvalidPacketHeader;
    }

    var ip_header_aligned: IpV4Header = undefined;
    @memcpy(std.mem.asBytes(&ip_header_aligned), packet_data[ip_offset..ip_offset+@sizeOf(IpV4Header)]);
    const ip_header = &ip_header_aligned;

    // validate IP header length field against captured length
    const ip_hdr_len_bytes = ip_header.headerLength();
    if (ip_hdr_len_bytes < 20 or caplen < ip_offset + ip_hdr_len_bytes) {
        // invalid header length or packet too short for declared header length
        log.debug("Invalid IP header length ({}) or insufficient captured data ({})", .{ ip_hdr_len_bytes, caplen });
        return Error.InvalidPacketHeader;
    }

    var protocol_type: common.Protocol = .Unknown;
    var source_port: u16 = 0;
    var dest_port: u16 = 0;
    var transport_checksum: u16 = 0;

    const transport_offset = ip_offset + ip_hdr_len_bytes;

    // parse transport layer based on IP protocol field
    switch (ip_header.protocol) {
        6 => { // TCP
            protocol_type = .TCP;
            // check length for minimum TCP header (fixed part)
            if (caplen >= transport_offset + @sizeOf(TcpHeader)) {
                var tcp_header_aligned: TcpHeader = undefined;
                @memcpy(std.mem.asBytes(&tcp_header_aligned), packet_data[transport_offset..transport_offset+@sizeOf(TcpHeader)]);
                const tcp_header = &tcp_header_aligned;

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
                return Error.InvalidPacketHeader; // packet too short for fixed TCP header part
            }
        },
        17 => { // UDP
            protocol_type = .UDP;
            // check length for UDP header
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
            // parsing ICMP header fields
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

    // extract payload and protocol-specific flags
    var payload_offset: usize = 0;
    var payload_length: usize = 0;
    var tcp_flags: u8 = 0;
    var ip_flags: u8 = 0;

    switch(protocol_type) {
        .TCP => {
            if (caplen >= transport_offset + @sizeOf(TcpHeader)) {
                var tcp_header_aligned: TcpHeader = undefined;
                @memcpy(std.mem.asBytes(&tcp_header_aligned), 
                    packet_data[transport_offset..transport_offset+@sizeOf(TcpHeader)]);
                const tcp_header = &tcp_header_aligned;

                // calculate payload offset and length
                payload_offset = transport_offset + tcp_header.headerLength();
                if (payload_offset < caplen) {
                    payload_length = caplen - payload_offset;
                }
                
                // extract TCP flags
                if (tcp_header.flagFIN()) tcp_flags |= 0x01;
                if (tcp_header.flagSYN()) tcp_flags |= 0x02;
                if (tcp_header.flagRST()) tcp_flags |= 0x04;
                if (tcp_header.flagPSH()) tcp_flags |= 0x08;
                if (tcp_header.flagACK()) tcp_flags |= 0x10;
                if (tcp_header.flagURG()) tcp_flags |= 0x20;
                if (tcp_header.flagECE()) tcp_flags |= 0x40;
                if (tcp_header.flagCWR()) tcp_flags |= 0x80;
                
                // extract IP flags from the IP header
                const ip_flags_frag = std.mem.readInt(u16, std.mem.asBytes(&ip_header.flags_fragment_offset), Endian.big);
                if ((ip_flags_frag & 0x4000) != 0) ip_flags |= 0x01; // don't fragment
                if ((ip_flags_frag & 0x2000) != 0) ip_flags |= 0x02; // more fragments
                if ((ip_flags_frag & 0x1FFF) != 0) ip_flags |= 0x04; // fragment offset (if non-zero)
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
        .tcp_flags = tcp_flags,
        .ip_flags = ip_flags,
    };
}

/// Expands shorthand filter expressions to full BPF syntax
///
/// This helper function makes it easier to use common filter patterns
/// by allowing simple terms like "dns" or "http" instead of requiring
/// the full BPF filter syntax.
///
/// Parameters:
///   filter: Filter string to potentially expand
///   allocator: Memory allocator for the returned string
///
/// Returns:
///   The expanded filter expression (caller owns the memory)
fn expandFilterExpression(filter: []const u8, allocator: Allocator) ![]const u8 {
    // common shorthands and their proper BPF expressions
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
    
    // if not a known shorthand, return the original filter
    return allocator.dupe(u8, filter);
}