const std = @import("std");
const Allocator = std.mem.Allocator;
const capture = @import("backend");
const common = @import("common");
const log = std.log.scoped(.detection);

pub const Error = error{
    InitializationFailed,
    RuleParsingFailed,
    DetectionFailed,
    MemoryError,
};

/// Severity level for detection events
pub const AlertSeverity = enum {
    Low,
    Medium,
    High,
    Critical,
};

/// Represents a detection event/alert
pub const Alert = struct {
    /// Unique identifier for this alert
    id: u32,
    /// When the alert was generated
    timestamp: i64,
    /// Alert severity level
    severity: AlertSeverity,
    /// Alert category (e.g. "Anomaly", "Signature", "DoS")
    category: []const u8,
    /// Human-readable description
    message: []const u8,
    /// Source IP address
    source_ip: [4]u8,
    /// Destination IP address
    dest_ip: [4]u8,
    /// Source port
    source_port: u16,
    /// Destination port
    dest_port: u16,
    /// Protocol type
    protocol: common.Protocol,
    
    /// Free memory allocated for alert fields
    pub fn deinit(self: *Alert, allocator: Allocator) void {
        allocator.free(self.category);
        allocator.free(self.message);
    }
};

/// A rule for detecting suspicious network behavior
pub const DetectionRule = struct {
    /// Unique identifier for this rule
    id: u32,
    /// Rule is enabled or disabled
    enabled: bool,
    /// Human-readable name
    name: []const u8,
    /// Severity if triggered
    severity: AlertSeverity,
    /// Rule condition - implemented as a function pointer to keep this extensible
    /// Returns true if the rule matches the packet
    condition: *const fn(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool,
    /// Message template for alerts
    message_template: []const u8,
    requires_conn_state: bool,
    
    pub fn deinit(self: *DetectionRule, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.message_template);
    }
};

/// Connection tracking key
pub const ConnectionKey = struct {
    source_ip: [4]u8,
    dest_ip: [4]u8,
    source_port: u16,
    dest_port: u16,
    protocol: common.Protocol,

    pub fn init(packet: capture.PacketInfo) ConnectionKey {
        return ConnectionKey{
            .source_ip = packet.source_ip,
            .dest_ip = packet.dest_ip,
            .source_port = packet.source_port,
            .dest_port = packet.dest_port,
            .protocol = packet.protocol,
        };
    }

    pub fn hash(self: ConnectionKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, self.source_ip);
        std.hash.autoHash(&hasher, self.dest_ip);
        std.hash.autoHash(&hasher, self.source_port);
        std.hash.autoHash(&hasher, self.dest_port);
        std.hash.autoHash(&hasher, self.protocol);
        return hasher.final();
    }

    pub fn eql(self: ConnectionKey, other: ConnectionKey) bool {
        return std.mem.eql(u8, &self.source_ip, &other.source_ip) and
            std.mem.eql(u8, &self.dest_ip, &other.dest_ip) and
            self.source_port == other.source_port and
            self.dest_port == other.dest_port and
            self.protocol == other.protocol;
    }
};

/// TCP flags for stateful tracking
pub const TcpFlags = struct {
    syn: bool = false,
    ack: bool = false,
    fin: bool = false,
    rst: bool = false,
    psh: bool = false,
    urg: bool = false,

    pub fn fromPacket(packet_data: []const u8, tcp_header_offset: usize) TcpFlags {
        if (packet_data.len < tcp_header_offset + 14) return TcpFlags{};

        const flags_byte = packet_data[tcp_header_offset + 13];
        return TcpFlags{
            .fin = (flags_byte & 0x01) != 0,
            .syn = (flags_byte & 0x02) != 0,
            .rst = (flags_byte & 0x04) != 0,
            .psh = (flags_byte & 0x08) != 0,
            .ack = (flags_byte & 0x10) != 0,
            .urg = (flags_byte & 0x20) != 0,
        };
    }
};

/// Connection state for stateful analysis
pub const ConnectionState = struct {
    key: ConnectionKey,
    first_seen: i64,
    last_seen: i64,
    packet_count: u32,
    byte_count: u64,
    packets_per_second: f32,
    bytes_per_second: f32,
    tcp_state: TcpConnectionState,
    payload_sample: ?[]u8 = null,
    
    pub fn deinit(self: *ConnectionState, allocator: Allocator) void {
        if (self.payload_sample) |sample| {
            allocator.free(sample);
            self.payload_sample = null;
        }
    }
};

/// TCP connection states for protocol state machine
pub const TcpConnectionState = enum {
    Unknown,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
};

/// Tracks connection states for stateful analysis
pub const ConnectionTracker = struct {
    allocator: Allocator,
    connections: std.AutoHashMap(u64, ConnectionState),
    last_cleanup: i64,
    cleanup_interval: i64,
    connection_timeout: i64,
    max_connections: usize,
    
    pub fn init(allocator: Allocator) !ConnectionTracker {
        return ConnectionTracker{
            .allocator = allocator,
            .connections = std.AutoHashMap(u64, ConnectionState).init(allocator),
            .last_cleanup = std.time.timestamp(),
            .cleanup_interval = 60, // seconds
            .connection_timeout = 300, // seconds
            .max_connections = 10000,
        };
    }
    
    pub fn deinit(self: *ConnectionTracker) void {
        var it = self.connections.valueIterator();
        while (it.next()) |conn_state| {
            conn_state.deinit(self.allocator);
        }
        self.connections.deinit();
    }
    
    /// Update connection state with new packet
    pub fn trackPacket(self: *ConnectionTracker, packet: capture.PacketInfo, packet_data: []const u8) !*ConnectionState {
        const key = ConnectionKey.init(packet);
        const hash_key = key.hash();
        
        const now = std.time.timestamp();
        
        // Check if periodic cleanup is needed
        if (now - self.last_cleanup > self.cleanup_interval) {
            try self.cleanupStaleConnections();
            self.last_cleanup = now;
        }

        // Get or create connection state
        if (self.connections.getPtr(hash_key)) |conn| {
            // Update existing connection
            const time_diff = now - conn.last_seen;
            
            // Update packet and byte counters
            conn.packet_count += 1;
            conn.byte_count += packet.captured_len;
            conn.last_seen = now;
            
            // Update rate calculations with exponential moving average
            if (time_diff > 0) {
                const alpha: f32 = 0.3; // Smoothing factor
                const packets_per_second = @as(f32, 1) / @as(f32, @floatFromInt(time_diff));
                const bytes_per_second = @as(f32, @floatFromInt(packet.captured_len)) / @as(f32, @floatFromInt(time_diff));
                
                conn.packets_per_second = (1 - alpha) * conn.packets_per_second + alpha * packets_per_second;
                conn.bytes_per_second = (1 - alpha) * conn.bytes_per_second + alpha * bytes_per_second;
            }
            
            // Update TCP state machine if applicable
            if (packet.protocol == .TCP) {
                const tcp_header_offset = @sizeOf(capture.EthernetHeader) + @sizeOf(capture.IpV4Header);
                if (packet_data.len >= tcp_header_offset) {
                    const tcp_flags = TcpFlags.fromPacket(packet_data, tcp_header_offset);
                    conn.tcp_state = self.updateTcpState(conn.tcp_state, tcp_flags);
                }
            }
            
            // Sample payload for pattern matching (just store the first N bytes)
            if (conn.payload_sample == null and packet.captured_len > 0) {
                const payload_offset = @sizeOf(capture.EthernetHeader) + @sizeOf(capture.IpV4Header);
                if (packet.protocol == .TCP) {
                    const tcp_header_size = @sizeOf(capture.TcpHeader);
                    if (packet_data.len > payload_offset + tcp_header_size) {
                        const sample_size = @min(64, packet_data.len - payload_offset - tcp_header_size);
                        conn.payload_sample = try self.allocator.dupe(u8, packet_data[payload_offset + tcp_header_size..payload_offset + tcp_header_size + sample_size]);
                    }
                } else if (packet.protocol == .UDP) {
                    const udp_header_size = @sizeOf(capture.UdpHeader);
                    if (packet_data.len > payload_offset + udp_header_size) {
                        const sample_size = @min(64, packet_data.len - payload_offset - udp_header_size);
                        conn.payload_sample = try self.allocator.dupe(u8, packet_data[payload_offset + udp_header_size..payload_offset + udp_header_size + sample_size]);
                    }
                }
            }
            
            return conn;
        } else {
            // Check if we've reached max connections before adding
            if (self.connections.count() >= self.max_connections) {
                // Force cleanup of stale connections
                try self.cleanupStaleConnections();
                
                // If still at capacity, remove oldest connection
                if (self.connections.count() >= self.max_connections) {
                    var oldest_key: u64 = 0;
                    var oldest_time: i64 = now;
                    
                    var it = self.connections.iterator();
                    while (it.next()) |entry| {
                        if (entry.value_ptr.last_seen < oldest_time) {
                            oldest_time = entry.value_ptr.last_seen;
                            oldest_key = entry.key_ptr.*;
                        }
                    }
                    
                    if (oldest_key != 0) {
                        if (self.connections.getPtr(oldest_key)) |old_conn| {
                            old_conn.deinit(self.allocator);
                        }
                        _ = self.connections.remove(oldest_key);
                    }
                }
            }
            
            // Create new connection state
            var initial_tcp_state = TcpConnectionState.Unknown;
            if (packet.protocol == .TCP) {
                const tcp_header_offset = @sizeOf(capture.EthernetHeader) + @sizeOf(capture.IpV4Header);
                if (packet_data.len >= tcp_header_offset) {
                    const tcp_flags = TcpFlags.fromPacket(packet_data, tcp_header_offset);
                    if (tcp_flags.syn and !tcp_flags.ack) {
                        initial_tcp_state = .SynSent;
                    }
                }
            }
            
            var new_state = ConnectionState{
                .key = key,
                .first_seen = now,
                .last_seen = now,
                .packet_count = 1,
                .byte_count = packet.captured_len,
                .packets_per_second = 0,
                .bytes_per_second = 0,
                .tcp_state = initial_tcp_state,
            };
            
            // Sample payload for new connection
            const payload_offset = @sizeOf(capture.EthernetHeader) + @sizeOf(capture.IpV4Header);
            if (packet.protocol == .TCP) {
                const tcp_header_size = @sizeOf(capture.TcpHeader);
                if (packet_data.len > payload_offset + tcp_header_size) {
                    const sample_size = @min(64, packet_data.len - payload_offset - tcp_header_size);
                    new_state.payload_sample = try self.allocator.dupe(u8, packet_data[payload_offset + tcp_header_size..payload_offset + tcp_header_size + sample_size]);
                }
            } else if (packet.protocol == .UDP) {
                const udp_header_size = @sizeOf(capture.UdpHeader);
                if (packet_data.len > payload_offset + udp_header_size) {
                    const sample_size = @min(64, packet_data.len - payload_offset - udp_header_size);
                    new_state.payload_sample = try self.allocator.dupe(u8, packet_data[payload_offset + udp_header_size..payload_offset + udp_header_size + sample_size]);
                }
            }
            
            try self.connections.put(hash_key, new_state);
            return self.connections.getPtr(hash_key).?;
        }
    }
    
    /// Update TCP state machine
    fn updateTcpState(self: *ConnectionTracker, current_state: TcpConnectionState, flags: TcpFlags) TcpConnectionState {
        _ = self; // unused
        
        return switch (current_state) {
            .Unknown => if (flags.syn and !flags.ack) .SynSent else .Unknown,
            .SynSent => if (flags.syn and flags.ack) .SynReceived else current_state,
            .SynReceived => if (flags.ack) .Established else current_state,
            .Established => if (flags.fin) .FinWait1 else current_state,
            .FinWait1 => if (flags.fin and flags.ack) .FinWait2 else current_state,
            .FinWait2 => if (flags.ack) .TimeWait else current_state,
            .CloseWait => if (flags.fin) .LastAck else current_state,
            .LastAck => if (flags.ack) .Closed else current_state,
            .TimeWait => if (flags.ack) .Closed else current_state,
            .Closing => if (flags.ack) .TimeWait else current_state,
            .Closed => .Closed,
        };
    }
    
    /// Remove stale connections
    fn cleanupStaleConnections(self: *ConnectionTracker) !void {
        const now = std.time.timestamp();
        
        var keys_to_remove = std.ArrayList(u64).init(self.allocator);
        defer keys_to_remove.deinit();
        
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            const conn = entry.value_ptr;
            
            // Check if connection is stale
            if (now - conn.last_seen > self.connection_timeout) {
                try keys_to_remove.append(entry.key_ptr.*);
            }
        }
        
        // Remove stale connections
        for (keys_to_remove.items) |key| {
            if (self.connections.getPtr(key)) |conn| {
                conn.deinit(self.allocator);
            }
            _ = self.connections.remove(key);
        }
    }
};

/// Manager for all detection activities
pub const DetectionEngine = struct {
    allocator: Allocator,
    rules: std.ArrayList(DetectionRule),
    alert_counter: std.atomic.Value(u32),
    connection_tracker: ConnectionTracker,
    
    /// Initialize a new detection engine
    pub fn init(allocator: Allocator) !DetectionEngine {
        return DetectionEngine{
            .allocator = allocator,
            .rules = std.ArrayList(DetectionRule).init(allocator),
            .alert_counter = std.atomic.Value(u32).init(1), // Start from 1
            .connection_tracker = try ConnectionTracker.init(allocator),
        };
    }
    
    /// Clean up all resources
    pub fn deinit(self: *DetectionEngine) void {
        for (self.rules.items) |*rule| {
            rule.deinit(self.allocator);
        }
        self.rules.deinit();
        self.connection_tracker.deinit();
    }
    
    /// Add a detection rule
    pub fn addRule(self: *DetectionEngine, rule: DetectionRule) !void {
        try self.rules.append(rule);
    }
    
    /// Analyze a packet and return any alerts generated
    pub fn analyzePacket(
        self: *DetectionEngine, 
        packet_info: capture.PacketInfo,
        packet_data: []const u8,
    ) !?Alert {
        // Tracking connection state
        const conn_state = try self.connection_tracker.trackPacket(packet_info, packet_data);

        // Checking stateless rules
        if (try self.checkStatelessRules(packet_info)) |alert| {
            return alert;
        }

        // Checking stateful rules using connection state
        return try self.checkStatefulRules(packet_info, conn_state);
    }

    fn checkStatelessRules(
        self: *DetectionEngine,
        packet_info: capture.PacketInfo
    ) !?Alert {
        // Check each enabled rule
        for (self.rules.items) |rule| {
            if (!rule.enabled or rule.requires_conn_state) continue;
            
            // If the rule condition matches, generate an alert
            if (rule.condition(packet_info, null)) {
                return try self.createAlert(rule, packet_info);
            }
        }
        return null;
    }

    fn checkStatefulRules(
        self: *DetectionEngine,
        packet_info: capture.PacketInfo,
        conn_state: *ConnectionState
    ) !?Alert {
        for (self.rules.items) |rule| {
            if (!rule.enabled or !rule.requires_conn_state) continue;

            if (rule.condition(packet_info, conn_state)) {
                return try self.createAlert(rule, packet_info);
            }
        }
        return null;
    }

    fn createAlert(
        self: *DetectionEngine,
        rule: DetectionRule,
        packet_info: capture.PacketInfo
    ) !Alert {
        // get next alert ID
        const alert_id = self.alert_counter.fetchAdd(1, .monotonic);
        
        const source_ip_str = try std.fmt.allocPrint(
            self.allocator,
            "{d}.{d}.{d}.{d}",
            .{
                packet_info.source_ip[0], packet_info.source_ip[1],
                packet_info.source_ip[2], packet_info.source_ip[3]
            }
        );
        defer self.allocator.free(source_ip_str);

        const dest_ip_str = try std.fmt.allocPrint(
            self.allocator, 
            "{d}.{d}.{d}.{d}",
            .{
                packet_info.dest_ip[0], packet_info.dest_ip[1],
                packet_info.dest_ip[2], packet_info.dest_ip[3]
            }
        );
        defer self.allocator.free(dest_ip_str);
        
        const source_port_str = try std.fmt.allocPrint(
        self.allocator, "{d}", .{packet_info.source_port}
        );
        defer self.allocator.free(source_port_str);
        
        const dest_port_str = try std.fmt.allocPrint(
            self.allocator, "{d}", .{packet_info.dest_port}
        );
        defer self.allocator.free(dest_port_str);
        
        const protocol_str = @tagName(packet_info.protocol);
                
        const message = try std.fmt.allocPrint(
            self.allocator,
            "Connection from {s}:{s} to {s}:{s} using {s} triggered rule: {s}",
            .{
                source_ip_str,
                source_port_str,
                dest_ip_str,
                dest_port_str,
                protocol_str,
                rule.name,
            }
        );

        const category = try self.allocator.dupe(u8, rule.name);
                
        // Create and return the alert
        return Alert{
            .id = alert_id,
            .timestamp = std.time.timestamp(),
            .severity = rule.severity,
            .category = category,
            .message = message,
            .source_ip = packet_info.source_ip,
            .dest_ip = packet_info.dest_ip,
            .source_port = packet_info.source_port,
            .dest_port = packet_info.dest_port,
            .protocol = packet_info.protocol,
        };
    }
    
    /// Load predefined rules
    pub fn loadDefaultRules(self: *DetectionEngine) !void {
        // Suspicious port detection
        try self.addRule(DetectionRule{
            .id = 1001,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Suspicious Port Access"),
            .severity = .Medium,
            .condition = detectSuspiciousPort,
            .message_template = try self.allocator.dupe(
                u8, 
                "Connection from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d} using {s} on suspicious port"
            ),
            .requires_conn_state = false,
        });
        
        // Traffic rate detection rules
        try self.addRule(DetectionRule{
            .id = 1002,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "High Packet Rate"),
            .severity = .Medium,
            .condition = detectLargePacket,
            .message_template = try self.allocator.dupe(
                u8, 
                "Large packet detected from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d} using {s}"
            ),
            .requires_conn_state = true,
        });

        try self.addRule(DetectionRule{
            .id = 1003,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "High Bandwidth Usage"),
            .severity = .Medium,
            .condition = detectHighBandwidth,
            .message_template = try self.allocator.dupe(
                u8, 
                "High bandwidth usage from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d} using {s}"
            ),
            .requires_conn_state = true,
        });

        // SYN flood detection
        try self.addRule(DetectionRule{
            .id = 1004,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Potential SYN Flood"),
            .severity = .High,
            .condition = detectSynFlood,
            .message_template = try self.allocator.dupe(
                u8, 
                "Potential SYN flood from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });

        // Port scan detection
        try self.addRule(DetectionRule{
            .id = 1005,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Potential Port Scan"),
            .severity = .Medium,
            .condition = detectPortScan,
            .message_template = try self.allocator.dupe(
                u8, 
                "Potential port scan from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });

        // Payload pattern detection
        try self.addRule(DetectionRule{
            .id = 1006,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Malicious Payload"),
            .severity = .High,
            .condition = detectPayloadPattern,
            .message_template = try self.allocator.dupe(
                u8, 
                "Malicious payload detected from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d} using {s}"
            ),
            .requires_conn_state = true,
        });

        // Protocol anomaly detection
        try self.addRule(DetectionRule{
            .id = 1007,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "HTTP Protocol Anomaly"),
            .severity = .Medium,
            .condition = detectHttpAnomaly,
            .message_template = try self.allocator.dupe(
                u8, 
                "HTTP protocol anomaly from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });

        try self.addRule(DetectionRule{
            .id = 1008,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "DNS Protocol Anomaly"),
            .severity = .Medium,
            .condition = detectDnsAnomaly,
            .message_template = try self.allocator.dupe(
                u8, 
                "DNS protocol anomaly from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });

        // Large packet detection (simpler version)
        try self.addRule(DetectionRule{
            .id = 1009,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Large Packet"),
            .severity = .Low,
            .condition = detectLargePacket,
            .message_template = try self.allocator.dupe(
                u8, 
                "Large packet detected from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d} using {s}"
            ),
            .requires_conn_state = false,
        });
    }
};

/// Payload signature for pattern matching
pub const PayloadSignature = struct {
    id: u32,
    name: []const u8,
    pattern: []const u8,
    category: []const u8,
    severity: AlertSeverity,
};

const PAYLOAD_SIGNATURES = [_]PayloadSignature{
    // SQL Injection signatures
    .{
        .id = 1,
        .name = "SQL Injection - UNION",
        .pattern = "UNION SELECT",
        .category = "Web Attack",
        .severity = .High,
    },
    .{
        .id = 2,
        .name = "SQL Injection - Blind",
        .pattern = "1=1--",
        .category = "Web Attack",
        .severity = .High,
    },
    .{
        .id = 3,
        .name = "SQL Injection - Error Based",
        .pattern = "convert()",
        .category = "Web Attack",
        .severity = .High,
    },
    .{
        .id = 4,
        .name = "SQL Injection - Time Based",
        .pattern = "SLEEP(",
        .category = "Web Attack",
        .severity = .High,
    },
    .{
        .id = 5,
        .name = "SQL Injection - MySQL Comment",
        .pattern = "/*!",
        .category = "Web Attack",
        .severity = .High,
    },

    // XSS signatures
    .{
        .id = 6,
        .name = "XSS - Basic Script Tag",
        .pattern = "<script>",
        .category = "Web Attack",
        .severity = .Medium,
    },
    .{
        .id = 7,
        .name = "XSS - IMG Onerror",
        .pattern = "<img src=x onerror=",
        .category = "Web Attack",
        .severity = .Medium,
    },
    .{
        .id = 8,
        .name = "XSS - JavaScript Protocol",
        .pattern = "javascript:",
        .category = "Web Attack",
        .severity = .Medium,
    },
    .{
        .id = 9,
        .name = "XSS - Event Handler",
        .pattern = "onmouseover=",
        .category = "Web Attack",
        .severity = .Medium,
    },

    // Command injection
    .{
        .id = 10,
        .name = "Command Injection - Unix RCE",
        .pattern = "; rm -rf",
        .category = "Web Attack",
        .severity = .Critical,
    },
    .{
        .id = 11,
        .name = "Command Injection - Windows RCE",
        .pattern = "cmd.exe",
        .category = "Web Attack",
        .severity = .Critical,
    },
    .{
        .id = 12,
        .name = "Command Injection - Parameter",
        .pattern = "|wget",
        .category = "Web Attack",
        .severity = .Critical,
    },
    .{
        .id = 13,
        .name = "Command Injection - Reverse Shell",
        .pattern = "bash -i >& /dev/tcp/",
        .category = "Web Attack",
        .severity = .Critical,
    },
    
    // File inclusion
    .{
        .id = 14,
        .name = "File Inclusion - LFI",
        .pattern = "../../../etc/passwd",
        .category = "Web Attack",
        .severity = .High,
    },
    .{
        .id = 15,
        .name = "File Inclusion - RFI HTTP",
        .pattern = "=http://",
        .category = "Web Attack",
        .severity = .High,
    },
    .{
        .id = 16,
        .name = "File Inclusion - PHP Wrapper",
        .pattern = "php://filter/convert.base64-encode",
        .category = "Web Attack",
        .severity = .High,
    },

    // Binary/malware signatures
    .{
        .id = 17,
        .name = "Malware - PE Header",
        .pattern = "MZ\x90\x00\x03\x00\x00\x00", // PE file
        .category = "Malware",
        .severity = .High,
    },
    .{
        .id = 18,
        .name = "Malware - Script Obfuscation",
        .pattern = "eval(base64_decode(",
        .category = "Malware",
        .severity = .High,
    },
    .{
        .id = 19,
        .name = "Malware - Powershell Encoded Command",
        .pattern = "powershell -e",
        .category = "Malware",
        .severity = .High,
    },
    .{
        .id = 20,
        .name = "Malware - Linux ELF Magic",
        .pattern = "\x7fELF",
        .category = "Malware",
        .severity = .High,
    },

    // Protocol abuse
    .{
        .id = 21,
        .name = "DNS Tunneling",
        .pattern = "\x00\x00\x10\x00\x00", // Suspicious DNS
        .category = "Tunneling",
        .severity = .Medium,
    },
    .{
        .id = 22,
        .name = "ICMP Tunneling",
        .pattern = "TUNL",
        .category = "Tunneling",
        .severity = .Medium,
    },

    // Known exploits
    .{
        .id = 23,
        .name = "Log4j Exploitation Attempt",
        .pattern = "${jndi:ldap://",
        .category = "Exploit",
        .severity = .Critical,
    },
    .{
        .id = 24,
        .name = "Apache Struts Exploitation",
        .pattern = "%{#context",
        .category = "Exploit",
        .severity = .Critical,
    },
    .{
        .id = 25,
        .name = "Spring4Shell Attempt",
        .pattern = "class.module.classLoader",
        .category = "Exploit",
        .severity = .Critical,
    },

    // Web server attacks
    .{
        .id = 26,
        .name = "Server-Side Template Injection",
        .pattern = "{{7*7}}",
        .category = "Web Attack",
        .severity = .High,
    },
    .{
        .id = 27,
        .name = "XML External Entity Attack",
        .pattern = "<!ENTITY",
        .category = "Web Attack",
        .severity = .High,
    },

    // Scanning tools
    .{
        .id = 28,
        .name = "Nikto Scanner",
        .pattern = "Nikto/",
        .category = "Scanning",
        .severity = .Medium,
    },
    .{
        .id = 29,
        .name = "SQLmap Scanner",
        .pattern = "sqlmap/",
        .category = "Scanning",
        .severity = .Medium,
    },
    .{
        .id = 30,
        .name = "Nmap Scanner",
        .pattern = "Nmap Scripting Engine",
        .category = "Scanning",
        .severity = .Medium,
    },
};

pub const PortInfo = struct {
    port: u16,
    service: []const u8,
    category: []const u8,
    risk_level: u8, // 1-10 scale
};

// Structure to track port scanning state
const PortScanState = struct {
    last_seen: i64,
    first_seen: i64,
    target_ports: std.AutoHashMap(u16, void),
    target_ips: std.AutoHashMap([4]u8, void),
    scan_rate: f32,
};

/// Known suspicious ports with context
const SUSPICIOUS_PORTS = [_]PortInfo{
    // Trojan/backdoor ports
    .{ .port = 31, .service = "Agent 31", .category = "Backdoor", .risk_level = 8 },
    .{ .port = 1080, .service = "SOCKS Proxy", .category = "Proxy", .risk_level = 6 },
    .{ .port = 1337, .service = "WASTE", .category = "Backdoor", .risk_level = 7 },
    .{ .port = 1434, .service = "MS-SQL Slammer", .category = "Malware", .risk_level = 9 },
    .{ .port = 2222, .service = "DirectAdmin", .category = "Alternative SSH", .risk_level = 6 },
    .{ .port = 2745, .service = "Bagle Backdoor", .category = "Backdoor", .risk_level = 9 },
    .{ .port = 3128, .service = "Squid Proxy", .category = "Proxy", .risk_level = 5 },
    .{ .port = 3333, .service = "Dec RPC", .category = "Remote Access", .risk_level = 7 },
    .{ .port = 4444, .service = "Metasploit", .category = "Backdoor", .risk_level = 9 },
    .{ .port = 5000, .service = "UPnP", .category = "Service Discovery", .risk_level = 6 },
    .{ .port = 5554, .service = "Sasser Worm", .category = "Malware", .risk_level = 9 },
    .{ .port = 5800, .service = "VNC", .category = "Remote Access", .risk_level = 6 },
    .{ .port = 5900, .service = "VNC", .category = "Remote Access", .risk_level = 6 },
    .{ .port = 6346, .service = "Gnutella", .category = "P2P", .risk_level = 5 },
    .{ .port = 6666, .service = "IRC", .category = "C&C", .risk_level = 7 },
    .{ .port = 6667, .service = "IRC", .category = "C&C", .risk_level = 7 },
    .{ .port = 8080, .service = "HTTP Alternate", .category = "Web", .risk_level = 5 },
    .{ .port = 8443, .service = "HTTPS Alternate", .category = "Web", .risk_level = 5 },
    .{ .port = 9001, .service = "Tor ORPort", .category = "Proxy", .risk_level = 7 },
    .{ .port = 9996, .service = "Remote Trojans", .category = "Backdoor", .risk_level = 8 },
    .{ .port = 12345, .service = "NetBus", .category = "Backdoor", .risk_level = 9 },
    .{ .port = 16464, .service = "Bot Communication", .category = "C&C", .risk_level = 9 },
    .{ .port = 27374, .service = "SubSeven", .category = "Backdoor", .risk_level = 9 },
    .{ .port = 31337, .service = "Back Orifice", .category = "Backdoor", .risk_level = 9 },
    
    // Commonly abused legitimate services
    .{ .port = 21, .service = "FTP", .category = "FileTransfer", .risk_level = 6 },
    .{ .port = 22, .service = "SSH", .category = "RemoteAccess", .risk_level = 5 },
    .{ .port = 23, .service = "Telnet", .category = "ClearText", .risk_level = 7 },
    .{ .port = 25, .service = "SMTP", .category = "Email", .risk_level = 6 },
    .{ .port = 110, .service = "POP3", .category = "Email", .risk_level = 5 },
    .{ .port = 135, .service = "MSRPC", .category = "Windows", .risk_level = 7 },
    .{ .port = 137, .service = "NetBIOS", .category = "Windows", .risk_level = 7 },
    .{ .port = 138, .service = "NetBIOS", .category = "Windows", .risk_level = 7 },
    .{ .port = 139, .service = "NetBIOS", .category = "Windows", .risk_level = 7 },
    .{ .port = 389, .service = "LDAP", .category = "Directory", .risk_level = 6 },
    .{ .port = 443, .service = "HTTPS", .category = "Web", .risk_level = 4 },
    .{ .port = 445, .service = "SMB", .category = "FileSharing", .risk_level = 6 },
    .{ .port = 1433, .service = "MS SQL", .category = "Database", .risk_level = 6 },
    .{ .port = 1521, .service = "Oracle", .category = "Database", .risk_level = 6 },
    .{ .port = 3306, .service = "MySQL", .category = "Database", .risk_level = 6 },
    .{ .port = 3389, .service = "RDP", .category = "RemoteAccess", .risk_level = 6 },
    .{ .port = 5432, .service = "PostgreSQL", .category = "Database", .risk_level = 6 },
    .{ .port = 5938, .service = "TeamViewer", .category = "RemoteAccess", .risk_level = 7 },
    
    // Cryptocurrency
    .{ .port = 3333, .service = "Mining Pool", .category = "Cryptocurrency", .risk_level = 7 },
    .{ .port = 8333, .service = "Bitcoin", .category = "Cryptocurrency", .risk_level = 6 },
    .{ .port = 8545, .service = "Ethereum", .category = "Cryptocurrency", .risk_level = 6 },
    
    // VPN services
    .{ .port = 500, .service = "IKE (VPN)", .category = "VPN", .risk_level = 5 },
    .{ .port = 1194, .service = "OpenVPN", .category = "VPN", .risk_level = 5 },
    .{ .port = 1701, .service = "L2TP", .category = "VPN", .risk_level = 5 },
    .{ .port = 1723, .service = "PPTP", .category = "VPN", .risk_level = 6 },
    
    // Additional dangerous services
    .{ .port = 161, .service = "SNMP", .category = "Management", .risk_level = 6 },
    .{ .port = 512, .service = "rexec", .category = "ClearText", .risk_level = 8 },
    .{ .port = 513, .service = "rlogin", .category = "ClearText", .risk_level = 8 },
    .{ .port = 514, .service = "rsh", .category = "ClearText", .risk_level = 8 },
};

/// Detect access to suspicious ports with context awareness
fn detectSuspiciousPort(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    // Local helper function to get context description
    const getPortContext = struct {
        fn get(port: u16) ?PortInfo {
            for (SUSPICIOUS_PORTS) |port_info| {
                if (port_info.port == port) {
                    return port_info;
                }
            }
            return null;
        }
    }.get;
    
    // 1. Check if destination port is in our suspicious list
    var is_suspicious = false;
    var detected_risk_level: u8 = 0;
    var port_info: ?PortInfo = null;
    
    if (getPortContext(packet.dest_port)) |context| {
        port_info = context;
        detected_risk_level = context.risk_level;
        
        // High risk ports are always suspicious
        if (context.risk_level >= 8) {
            is_suspicious = true;
        }
        // For medium risk ports, use additional context
        else if (context.risk_level >= 5) {
            // 2. Consider port context and traffic direction
            
            // Clear text protocols crossing network boundaries are suspicious
            if (std.mem.eql(u8, context.category, "ClearText") and 
                !isPrivateIP(packet.dest_ip)) {
                is_suspicious = true;
            }
            
            // Database services exposed to the internet are suspicious
            else if (std.mem.eql(u8, context.category, "Database") and 
                    !isPrivateIP(packet.dest_ip)) {
                is_suspicious = true;
            }
            
            // SMB should only be used on private networks
            else if (std.mem.eql(u8, context.service, "SMB") and 
                    !isPrivateIP(packet.dest_ip)) {
                is_suspicious = true;
            }
            
            // RDP from outside is suspicious
            else if (std.mem.eql(u8, context.service, "RDP") and 
                    !isPrivateIP(packet.source_ip)) {
                is_suspicious = true;
            }
            
            // Management services from outside are suspicious
            else if (std.mem.eql(u8, context.category, "Management") and 
                    !isPrivateIP(packet.source_ip)) {
                is_suspicious = true;
            }
            
            // P2P traffic detection
            else if (std.mem.eql(u8, context.category, "P2P")) {
                is_suspicious = true;
            }
            
            // Outbound C&C channels are suspicious
            else if (std.mem.eql(u8, context.category, "C&C") and 
                    isPrivateIP(packet.source_ip) and 
                    !isPrivateIP(packet.dest_ip)) {
                is_suspicious = true;
            }
            
            // Mining pools are often suspicious
            else if (std.mem.eql(u8, context.category, "Cryptocurrency")) {
                is_suspicious = true;
            }
        }
    }
    
    // 3. Check source port too (could be a covert channel)
    if (!is_suspicious) {
        if (getPortContext(packet.source_port)) |context| {
            // Source ports matching high-risk services are unusual
            if (context.risk_level >= 7) {
                is_suspicious = true;
                port_info = context;
                detected_risk_level = context.risk_level;
            }
        }
    }
    
    // 4. Check for unusual port combinations
    if (!is_suspicious and conn_state != null) {
        // HTTP/HTTPS on non-standard ports
        const http_ports = [_]u16{ 80, 443, 8080, 8443 };
        var is_standard_http_port = false;
        
        for (http_ports) |http_port| {
            if (packet.dest_port == http_port) {
                is_standard_http_port = true;
                break;
            }
        }
        
        if (conn_state.?.payload_sample) |payload| {
            // Looks like HTTP but not on standard port
            if (!is_standard_http_port and isHttpTraffic(payload)) {
                is_suspicious = true;
                detected_risk_level = 7;
            }
        }
    }
    
    // 5. Port numbers to avoid in Zig code - ephemeral ports are fine
    if (packet.dest_port > 49151 and packet.dest_port < 65535) {
        const high_risk_dest_ports = [_]u16{ 
            51111, 51166, 53344, 54321, 60000, 61466, 65000 
        };
        
        for (high_risk_dest_ports) |risky_port| {
            if (packet.dest_port == risky_port) {
                is_suspicious = true;
                detected_risk_level = 7;
                break;
            }
        }
    }
    
    // 6. Suspicious port + non-standard flags is extra suspicious
    if (packet.protocol == .TCP and conn_state != null) {
        _ = @sizeOf(capture.EthernetHeader) + @sizeOf(capture.IpV4Header);
        if (conn_state.?.packet_count == 1) {
            // First packet with unusual flags - might be a port scan
            const is_suspicious_port = detected_risk_level >= 5;
            if (is_suspicious_port) {
                is_suspicious = true;
            }
        }
    }
    
    // Log the detection details for debugging
    if (is_suspicious and port_info != null) {
        log.debug("Suspicious port {d} ({s}) detected with risk level {d}", 
            .{ port_info.?.port, port_info.?.service, port_info.?.risk_level });
    }
    
    return is_suspicious;
}

/// Detect unusually large packets
fn detectLargePacket(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    _ = conn_state; // not used
    const LARGE_PACKET_THRESHOLD: u32 = 8000;
    return packet.captured_len > LARGE_PACKET_THRESHOLD;
}

/// Detect high packet rate (potential DoS)
fn detectHighPacketRate(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        // Alert if packet rate exceeds threshold and we've seen enough packets
        const PACKET_RATE_THRESHOLD: f32 = 100.0; // packets per second
        const MIN_PACKETS_NEEDED: u32 = 20; // minimum sample size

        return conn.packets_per_second > PACKET_RATE_THRESHOLD and
            conn.packet_count >= MIN_PACKETS_NEEDED;
    }

    return false;
}

/// Detect high bandwidth usage
fn detectHighBandwidth(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        // Alert if bandwidth exceeds threshold (10MB/s) and we've seen enough traffic
        const BANDWIDTH_THRESHOLD: f32 = 10.0 * 1024.0 * 1024.0; // 10 MB/s
        const MIN_BYTES_NEEDED: u64 = 100 * 1024; // 100KB minimum sample
        
        return conn.bytes_per_second > BANDWIDTH_THRESHOLD and 
               conn.byte_count >= MIN_BYTES_NEEDED;
    }
    return false;
}

/// Detect SYN flood attacks
pub fn detectSynFlood(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        // Alert on connections that stay in SYN_SENT state with multiple packets
        const SYN_FLOOD_PACKET_THRESHOLD: u32 = 20;

        const now = std.time.timestamp();
        const time_window = now - conn.first_seen;
        const MIN_TIME_WINDOW: i64 = 3; // at least 3 seconds to avoid false positives
        
        return conn.tcp_state == .SynSent and 
               conn.packet_count >= SYN_FLOOD_PACKET_THRESHOLD and
               time_window <= MIN_TIME_WINDOW;
    }
    return false;
}

/// Enhanced port scan detection using both connection-level and global heuristics
fn detectPortScan(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    // Perform connection-level checks first
    if (conn_state) |conn| {
        // 1. Connection-level characteristics of port scans
        
        // SYN scan detection - single packet, SYN only, no further communication
        const is_single_packet = conn.packet_count == 1;
        const is_syn_only = packet.protocol == .TCP and conn.tcp_state == .SynSent;
        
        // FIN/NULL scan detection
        const is_fin_scan = packet.protocol == .TCP and 
                          (conn.tcp_state == .Unknown or conn.tcp_state == .Closed);
                          
        // Short connection with very little data
        const is_short_conn = conn.packet_count <= 2;
        const low_data_volume = conn.byte_count < 100;
        
        // 2. Raw scan detection (connection level)
        if ((is_single_packet and is_syn_only) or
            (is_short_conn and low_data_volume and is_fin_scan)) {
            
            // 3. Consult global scan tracker for confirmation
            const now = std.time.timestamp();
            const is_part_of_scan = PortScanTracker.trackScan(
                packet.source_ip, packet.dest_ip, packet.dest_port, now
            ) catch false;
            
            // If this looks like a scan and fits into a larger pattern, alert
            if (is_part_of_scan) {
                return true;
            }
        }
    }
    
    return false;
}

/// Check if IP is in private ranges
fn isPrivateIP(ip: [4]u8) bool {
    // Localhost/loopback 127.0.0.0/8
    if (ip[0] == 127) {
        return true;
    }
    
    // 10.0.0.0/8
    if (ip[0] == 10) {
        return true;
    }
    
    // 172.16.0.0/12
    if (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) {
        return true;
    }
    
    // 192.168.0.0/16
    if (ip[0] == 192 and ip[1] == 168) {
        return true;
    }
    
    return false;
}

/// Detect payload patterns (signatures)
fn detectPayloadPattern(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (packet.payload) |direct_payload| {
        // only checking TCP and UDP packets with payload
        if (packet.protocol == .TCP or packet.protocol == .UDP) {
            // check against all signatures
            for (PAYLOAD_SIGNATURES) |sig|{
                if (std.mem.indexOf(u8, direct_payload, sig.pattern)) |_| {
                    // found a match
                    log.info("Payload signature match: {s} (ID: {d})", .{sig.name, sig.id});
                    return true;
                }
            }
        }
    }

    // check connection state payload sample as backup
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload_sample| {
            // check TCP and UDP packets
            if (packet.protocol == .TCP or packet.protocol == .UDP) {
                // check against all signatures
                for (PAYLOAD_SIGNATURES) |sig| {
                    if (std.mem.indexOf(u8, payload_sample, sig.pattern)) |_| {
                        // found a match
                        log.info("Connection payload signature match: {s} (ID: {d})", .{sig.name, sig.id});
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}

/// Detect HTTP protocol anomalies
fn detectHttpAnomaly(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload| {
            if (packet.protocol != .TCP) return false;
            
            // Only check if it looks like HTTP traffic
            if (!isHttpTraffic(payload)) return false;
            
            // Check for oversized HTTP headers (potential buffer overflow)
            if (std.mem.indexOf(u8, payload, "Content-Length: ")) |pos| {
                // Extract length value
                var end_pos: usize = pos + 16; // "Content-Length: " is 16 chars
                while (end_pos < payload.len and payload[end_pos] >= '0' and payload[end_pos] <= '9') {
                    end_pos += 1;
                }
                
                if (end_pos > pos + 16) {
                    const length_str = payload[pos+16..end_pos];
                    const content_length = std.fmt.parseInt(u32, length_str, 10) catch {
                        return false; // Invalid integer
                    };
                    
                    // Alert on suspiciously large content length
                    const MAX_REASONABLE_SIZE: u32 = 10 * 1024 * 1024; // 10MB
                    if (content_length > MAX_REASONABLE_SIZE) {
                        return true;
                    }
                }
            }
            
            // Check for very long URL (potential DoS/buffer overflow)
            if (std.mem.indexOf(u8, payload, "GET ")) |pos| {
                var end_pos: usize = pos + 4;
                while (end_pos < payload.len and payload[end_pos] != ' ') {
                    end_pos += 1;
                }
                
                const url_length = end_pos - (pos + 4);
                const MAX_URL_LENGTH: usize = 2000; // Reasonable URL length
                
                if (url_length > MAX_URL_LENGTH) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

fn isHttpTraffic(payload: []const u8) bool {
    const HTTP_METHODS = [_][]const u8{
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "TRACE ",
        "HTTP/1.", // For responses
    };
    
    for (HTTP_METHODS) |method| {
        if (std.mem.startsWith(u8, payload, method)) {
            return true;
        }
    }
    
    return false;
}

/// Detect DNS protocol anomalies
fn detectDnsAnomaly(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload| {
            if (packet.protocol != .UDP or (packet.dest_port != 53 and packet.source_port != 53)) 
                return false;
            
            // Basic check for DNS query packet format
            if (payload.len < 12) return false; // DNS header is 12 bytes

            // 1. Extract DNS header fields
            _ = @as(u16, payload[0]) << 8 | payload[1]; // transaction ID (not used)
            const flags = @as(u16, payload[2]) << 8 | payload[3];
            const qdcount = @as(u16, payload[4]) << 8 | payload[5]; // Question count
            const ancount = @as(u16, payload[6]) << 8 | payload[7]; // Answer count
            _ = @as(u16, payload[8]) << 8 | payload[9]; // Authority count (not used)
            _ = @as(u16, payload[10]) << 8 | payload[11]; // Additional count (not used)

            // query or response?
            const is_response = (flags & 0x8000) != 0;
            const opcode = (flags >> 11) & 0xF;

            // 2. Check for unusual query types
            if (opcode != 0) { // Not a standard query
                const rare_opcodes = [_]u4{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
                for (rare_opcodes) |code| {
                    if (opcode == code) return true;
                }
            }
            
            // 3. Check for oversized packets (data exfiltration)
            const MAX_REASONABLE_DNS_LEN: usize = 512; // RFC standard for UDP
            if (payload.len > MAX_REASONABLE_DNS_LEN) {
                return true;
            }
            
            // 4. Parse QNAME for domain analysis
            if (qdcount > 0) {
                var domain_parts_buffer: [32][]const u8 = undefined;
                var domain_parts_count: usize = 0;

                var i: usize = 12; // start after header
                var total_domain_len: usize = 0;
                var domain_entropy: f64 = 0;
                var char_counts = [_]usize{0} ** 256;

                // extracting domain parts
                while (i < payload.len) {
                    const label_len = payload[i];
                    if (label_len == 0) break; // End of QNA

                    // checking for label length conformance
                    if (label_len > 63) return true; // RFC violation
                    if (i + 1 + label_len >= payload.len) return true;

                    // track and analyze the label
                    const label = payload[i+1..i+1+label_len];
                    if (domain_parts_count < domain_parts_buffer.len) {
                        domain_parts_buffer[domain_parts_count] = label;
                        domain_parts_count += 1;
                    }
                    total_domain_len += label_len;

                    // character distribution for entropy analysis
                    for (label) |char| {
                        char_counts[char] += 1;
                    }

                    i += @as(usize, label_len) + 1;
                }

                // 5. Check for excessive length
                if (total_domain_len > 255) return true; // Max allowed by DNS

                // 6. Calculate entropy (Shannon entropy for detecting encoded/encrypted data)
                if (total_domain_len > 0) {
                    for (char_counts) |count| {
                        if (count > 0) {
                            const p = @as(f64, @floatFromInt(count)) / @as(f64, @floatFromInt(total_domain_len));
                            domain_entropy -= p * std.math.log2(p);
                        }
                    }

                    // high entropy indicates potential encoded data
                    const HIGH_ENTROPY_THRESHOLD: f64 = 4.0; // tuned for base64/hex data
                    if (domain_entropy > HIGH_ENTROPY_THRESHOLD and total_domain_len > 30) {
                        return true;
                    }
                }

                // 7. Check for numeric-heavy subdomains (often used in tunneling)
                var numeric_count: usize = 0;
                for (domain_parts_buffer[0..domain_parts_count]) |part| {
                    var digit_count: usize = 0;
                    for (part) |char| {
                        if (char >= '0' and char <= '9') {
                            digit_count += 1;
                        }
                    }

                    // if this part is >50% digits, flag it
                    if (part.len > 0 and digit_count * 2 > part.len) {
                        numeric_count += 1;
                    }
                }

                // suspicious if many parts are heavily numeric
                if (numeric_count >= 3 and domain_parts_count >= 5) {
                    return true;
                }

                // 8. Check for excessive subdomain count
                if (domain_parts_count > 10) { // unusually many subdomains
                    return true;
                }

                // 9. Check for repeated query patterns if we have connection state
                if (conn.packet_count > 5) {
                    // suspicious if sending many DNS queries in a short time
                    const HIGH_DNS_QUERY_RATE = 10.0; // queries per second
                    if (conn.packets_per_second > HIGH_DNS_QUERY_RATE) {
                        return true;
                    }
                }
                
                // 10. If this is a response, check for unusual record types
                if (is_response and ancount > 0) {
                    // look for .txt records, often abused for data exfiltration
                    const qtype_offset = i + 1; // +1 for the terminating zero
                    if (qtype_offset + 2 < payload.len) {
                        const qtype = @as(u16, payload[qtype_offset]) << 8 | payload[qtype_offset + 1];

                        // checking for unusual record types
                        const unusual_record_types = [_]u16{
                            16, // TXT
                            251, // IXFR - rare in normal traffic
                            252, // AXFR - zone transfers should be restricted
                            255, // ANY - often used in amplification attacks
                        };

                        for (unusual_record_types) |utype| {
                            if (qtype == utype) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return false;
}

/// Track port scan attempts using global state
const PortScanTracker = struct {
    // Track unique source IPs scanning multiple ports
    var ip_scan_attempts = std.AutoHashMap([4]u8, PortScanState).init(std.heap.page_allocator);
    
    // Last cleanup time for IP scan tracker
    var last_cleanup: i64 = 0;
    
    // Track scans by IP
    pub fn trackScan(source_ip: [4]u8, dest_ip: [4]u8, dest_port: u16, now: i64) !bool {
        // Cleanup old entries every 5 minutes
        if (now - last_cleanup > 300) {
            try cleanupOldEntries(now);
            last_cleanup = now;
        }
        
        var is_scan = false;
        var scan_state: *PortScanState = undefined;
        
        // Get or create scan state for this source IP
        if (ip_scan_attempts.getPtr(source_ip)) |state| {
            scan_state = state;
        } else {
            // Initialize new scan state
            try ip_scan_attempts.put(source_ip, PortScanState{
                .last_seen = now,
                .target_ports = std.AutoHashMap(u16, void).init(std.heap.page_allocator),
                .target_ips = std.AutoHashMap([4]u8, void).init(std.heap.page_allocator),
                .first_seen = now,
                .scan_rate = 0,
            });
            scan_state = ip_scan_attempts.getPtr(source_ip).?;
        }
        
        // Update scan state
        scan_state.last_seen = now;
        try scan_state.target_ports.put(dest_port, {});
        try scan_state.target_ips.put(dest_ip, {});
        
        // Calculate scan rate
        const time_window = now - scan_state.first_seen;
        if (time_window > 0) {
            scan_state.scan_rate = @as(f32, @floatFromInt(scan_state.target_ports.count())) / 
                             @as(f32, @floatFromInt(time_window));
        }
        
        // Different scan detection criteria:
        
        // 1. Horizontal scan (many ports on same IP)
        if (scan_state.target_ips.count() <= 3 and scan_state.target_ports.count() >= 10) {
            is_scan = true;
        }
        
        // 2. Vertical scan (same port on many IPs)
        if (scan_state.target_ips.count() >= 5 and scan_state.target_ports.count() <= 3) {
            is_scan = true;
        }
        
        // 3. Block scan (many ports on many IPs)
        if (scan_state.target_ips.count() >= 5 and scan_state.target_ports.count() >= 5) {
            is_scan = true;
        }
        
        // 4. Fast scan rate
        const FAST_SCAN_THRESHOLD: f32 = 1.0; // more than 1 port per second
        if (scan_state.scan_rate > FAST_SCAN_THRESHOLD and 
            scan_state.target_ports.count() > 5) {
            is_scan = true;
        }
        
        return is_scan;
    }
    
    // Clean up old entries to prevent memory leaks
    fn cleanupOldEntries(now: i64) !void {
        var to_remove = std.ArrayList([4]u8).init(std.heap.page_allocator);
        defer to_remove.deinit();
        
        // Find old entries (older than 30 minutes)
        var it = ip_scan_attempts.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr;
            if (now - state.last_seen > 1800) { // 30 minutes
                try to_remove.append(entry.key_ptr.*);
            }
        }
        
        // Remove old entries
        for (to_remove.items) |ip| {
            // Free resources
            if (ip_scan_attempts.getPtr(ip)) |state| {
                state.target_ports.deinit();
                state.target_ips.deinit();
            }
            _ = ip_scan_attempts.remove(ip);
        }
    }
    
    pub fn deinit() void {
        var it = ip_scan_attempts.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.target_ports.deinit();
            entry.value_ptr.target_ips.deinit();
        }
        ip_scan_attempts.deinit();
    }
};