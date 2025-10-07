///////////////////////////////////////////////////////////////////////////////
// Network Security Detection Module
//
// This module implements an intrusion detection system (IDS) with support for:
//   - Rule-based detection of suspicious network activities
//   - Connection state tracking for stateful analysis
//   - Signature-based and anomaly-based detection techniques
//   - TCP state machine modeling for protocol analysis
//   - Alert generation and management
//
// The design emphasizes extensibility (custom rule functions), efficiency
// (hash-based lookups), and quality detection with minimal false positives.
///////////////////////////////////////////////////////////////////////////////

const std = @import("std");
const Allocator = std.mem.Allocator;
const capture = @import("backend");
const common = @import("common");
const shrykull = @import("shrykull_manager");
const log = std.log.scoped(.detection);

/// Error types specific to detection operations
pub const Error = error{
    InitializationFailed, // failed to initialize detection engine
    RuleParsingFailed, // failed to parse detection rule
    DetectionFailed, // error during packet analysis
    MemoryError, // memory allocation/management error
};

/// Severity level for detection events
pub const AlertSeverity = enum {
    Low, // informational or low-impact events
    Medium, // potentially suspicious activities
    High, // likely malicious activities
    Critical, // severe security incidents requiring immediate attention
};

/// Represents a detection event/alert
pub const Alert = struct {
    /// Unique identifier for this alert
    id: u32,
    /// When the alert was generated (Unix timestamp)
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
    /// Associated flow ID (optional)
    flow_id: ?u64 = null,
    
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
    /// Whether this rule requires connection state tracking
    requires_conn_state: bool,
    
    /// Free memory allocated for rule fields
    pub fn deinit(self: *DetectionRule, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.message_template);
    }
};

/// Connection tracking key for bidirectional flow identification
pub const ConnectionKey = struct {
    /// Source IPv4 address
    source_ip: [4]u8,
    /// Destination IPv4 address
    dest_ip: [4]u8,
    /// Source port number
    source_port: u16,
    /// Destination port number
    dest_port: u16,
    /// Protocol (TCP, UDP, ICMP)
    protocol: common.Protocol,

    /// Create a connection key from packet info
    pub fn init(packet: capture.PacketInfo) ConnectionKey {
        return ConnectionKey{
            .source_ip = packet.source_ip,
            .dest_ip = packet.dest_ip,
            .source_port = packet.source_port,
            .dest_port = packet.dest_port,
            .protocol = packet.protocol,
        };
    }

    /// Generate a hash value for connection lookup
    pub fn hash(self: ConnectionKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, self.source_ip);
        std.hash.autoHash(&hasher, self.dest_ip);
        std.hash.autoHash(&hasher, self.source_port);
        std.hash.autoHash(&hasher, self.dest_port);
        std.hash.autoHash(&hasher, self.protocol);
        return hasher.final();
    }

    /// Compare two connection keys for equality
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
    syn: bool = false, // SYN flag (Synchronize sequence numbers)
    ack: bool = false, // ACK flag (Acknowledgment field significant)
    fin: bool = false, // FIN flag (No more data from sender)
    rst: bool = false, // RST flag (Reset the connection)
    psh: bool = false, // PSH flag (Push function)
    urg: bool = false, // URG flag (Urgent pointer field significant)

    /// Extract TCP flags from a packet
    pub fn fromPacket(packet_data: []const u8, tcp_header_offset: usize) TcpFlags {
        // ensure packet has enough data for TCP header
        if (packet_data.len < tcp_header_offset + 14) return TcpFlags{};

        // extract the flags byte (offset 13 in TCP header)
        const flags_byte = packet_data[tcp_header_offset + 13];

        // parse individual flags
        return TcpFlags{
            .fin = (flags_byte & 0x01) != 0, // FIN - bit 0
            .syn = (flags_byte & 0x02) != 0, // SYN - bit 1
            .rst = (flags_byte & 0x04) != 0, // RST - bit 2
            .psh = (flags_byte & 0x08) != 0, // PSH - bit 3
            .ack = (flags_byte & 0x10) != 0, // ACK - bit 4
            .urg = (flags_byte & 0x20) != 0, // URG - bit 5
        };
    }
};

/// Connection state for stateful analysis
pub const ConnectionState = struct {
    /// Connection identifier
    key: ConnectionKey,
    /// When the connection was first observed (Unix timestamp)
    first_seen: i64,
    /// When the connection was last observed (Unix timestamp)
    last_seen: i64,
    /// Total packets in this connection
    packet_count: u32,
    /// Total bytes in this connection
    byte_count: u64,
    /// Packet rate (packets/second) - exponentially weighted moving average
    packets_per_second: f32,
    /// Bandwidth usage (bytes/second) - exponentially weighted moving average
    bytes_per_second: f32,
    /// Current state in TCP state machine
    tcp_state: TcpConnectionState,
    /// Sample of payload data for pattern matching (optional)
    payload_sample: ?[]u8 = null,
    
    /// Free memory allocated for connection state
    pub fn deinit(self: *ConnectionState, allocator: Allocator) void {
        if (self.payload_sample) |sample| {
            allocator.free(sample);
            self.payload_sample = null;
        }
    }
};

/// TCP connection states for protocol state machine
/// Based on standard TCP state diagram (RFC 793)
pub const TcpConnectionState = enum {
    Unknown,        // initial or indeterminate state
    SynSent,        // client sent SYN, awaiting SYN-ACK
    SynReceived,    // server sent SYN-ACK, awaiting ACK
    Established,    // connection established, data transfer
    FinWait1,       // FIN sent, awaiting ACK or FIN-ACK
    FinWait2,       // FIN ACK'd, awaiting FIN
    CloseWait,      // received FIN, awaiting close from app
    Closing,        // both sides sent FIN, awaiting ACK
    LastAck,        // sent FIN after close from app, awaiting ACK
    TimeWait,       // waiting for delayed segments to expire
    Closed,         // connection fully terminated
};

/// Tracks connection states for stateful analysis
pub const ConnectionTracker = struct {
    /// Memory allocator for dynamic allocations
    allocator: Allocator,
    /// Map of active connections (hash -> state)
    connections: std.AutoHashMap(u64, ConnectionState),
    /// Last time stale connections were cleaned up
    last_cleanup: i64,
    /// How often to run cleanup (seconds)
    cleanup_interval: i64,
    /// Maximum idle time before a connection is considered stale (seconds)
    connection_timeout: i64,
    /// Maximum number of connections to track
    max_connections: usize,
    
    /// Initialize a new connection tracker
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
    
    /// Clean up resources used by the connection tracker
    pub fn deinit(self: *ConnectionTracker) void {
        var it = self.connections.valueIterator();
        while (it.next()) |conn_state| {
            conn_state.deinit(self.allocator);
        }
        self.connections.deinit();
    }
    
    /// Update connection state with new packet information
    /// Returns a pointer to the updated or new connection state
    pub fn trackPacket(self: *ConnectionTracker, packet: capture.PacketInfo, packet_data: []const u8) !*ConnectionState {
        // create connection key and hash from packet info
        const key = ConnectionKey.init(packet);
        const hash_key = key.hash();
        
        const now = std.time.timestamp();
        
        // run periodic cleanup if needed
        if (now - self.last_cleanup > self.cleanup_interval) {
            try self.cleanupStaleConnections();
            self.last_cleanup = now;
        }

        // update existing connection or create new one
        if (self.connections.getPtr(hash_key)) |conn| {
            // update existing connection
            const time_diff = now - conn.last_seen;
            
            // update packet and byte counters
            conn.packet_count += 1;
            conn.byte_count += packet.captured_len;
            conn.last_seen = now;
            
            // update rate calculations with exponential moving average
            if (time_diff > 0) {
                const alpha: f32 = 0.3; // smoothing factor
                const packets_per_second = @as(f32, 1) / @as(f32, @floatFromInt(time_diff));
                const bytes_per_second = @as(f32, @floatFromInt(packet.captured_len)) / @as(f32, @floatFromInt(time_diff));
                
                // smoothing formula: new_value = (1 - alpha) * old_value + alpha * sample
                conn.packets_per_second = (1 - alpha) * conn.packets_per_second + alpha * packets_per_second;
                conn.bytes_per_second = (1 - alpha) * conn.bytes_per_second + alpha * bytes_per_second;
            }
            
            // update TCP state machine if applicable
            if (packet.protocol == .TCP) {
                const tcp_header_offset = @sizeOf(capture.EthernetHeader) + @sizeOf(capture.IpV4Header);
                if (packet_data.len >= tcp_header_offset) {
                    const tcp_flags = TcpFlags.fromPacket(packet_data, tcp_header_offset);
                    conn.tcp_state = self.updateTcpState(conn.tcp_state, tcp_flags);
                }
            }
            
            // sample payload for pattern matching (just store the first N bytes)
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
            // implement connection table limits
            if (self.connections.count() >= self.max_connections) {
                // try cleanup first to free space
                try self.cleanupStaleConnections();
                
                // if still at capacity, remove oldest connection
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
            
            // create new connection state
            var initial_tcp_state = TcpConnectionState.Unknown;
            if (packet.protocol == .TCP) {
                const tcp_header_offset = @sizeOf(capture.EthernetHeader) + @sizeOf(capture.IpV4Header);
                if (packet_data.len >= tcp_header_offset) {
                    const tcp_flags = TcpFlags.fromPacket(packet_data, tcp_header_offset);
                    // if first packet is a SYN, mark as SynSent state
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
            
            // sample payload for new connection
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
    
    /// Update TCP state machine based on observed flags
    /// Follows standard TCP state transitions as defined in RFC 793
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
    
    /// Remove inactive connections to prevent memory exhaustion
    fn cleanupStaleConnections(self: *ConnectionTracker) !void {
        const now = std.time.timestamp();
        
        // create temporary list of keys to remove
        var keys_to_remove = std.ArrayList(u64).init(self.allocator);
        defer keys_to_remove.deinit();
        
        // identify stale connections
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            const conn = entry.value_ptr;
            
            // check if connection is stale (inactive for too long)
            if (now - conn.last_seen > self.connection_timeout) {
                try keys_to_remove.append(entry.key_ptr.*);
            }
        }
        
        // remove stale connections and free their resources
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
    /// Memory allocator for dynamic allocations
    allocator: Allocator,
    /// List of detection rules
    rules: std.ArrayList(DetectionRule),
    /// Counter for generating unique alert IDs
    alert_counter: std.atomic.Value(u32),
    /// Connection tracker for stateful analysis
    connection_tracker: ConnectionTracker,
    /// Shrykull vulnerability scanner manager (optional)
    shrykull_manager: ?*shrykull.ShrykullManager = null,
    
    /// Initialize a new detection engine
    pub fn init(allocator: Allocator, shrykull_manager: ?*shrykull.ShrykullManager) !DetectionEngine {
        return DetectionEngine{
            .allocator = allocator,
            .rules = std.ArrayList(DetectionRule).init(allocator),
            .alert_counter = std.atomic.Value(u32).init(1), // Start from 1
            .connection_tracker = try ConnectionTracker.init(allocator),
            .shrykull_manager = shrykull_manager,        
        };
    }
    
    /// Clean up all resources used by the detection engine
    pub fn deinit(self: *DetectionEngine) void {
        for (self.rules.items) |*rule| {
            rule.deinit(self.allocator);
        }
        self.rules.deinit();
        self.connection_tracker.deinit();
    }
    
    /// Add a detection rule to the engine
    pub fn addRule(self: *DetectionEngine, rule: DetectionRule) !void {
        try self.rules.append(rule);
    }
    
    /// Analyze a packet and return any alerts generated
    /// This is the main entry point for packet analysis
    pub fn analyzePacket(
        self: *DetectionEngine, 
        packet_info: capture.PacketInfo,
        packet_data: []const u8,
    ) !?Alert {
        // update connection state tracking
        const conn_state = try self.connection_tracker.trackPacket(packet_info, packet_data);

        // first check stateless rules (don't need connection context)
        if (try self.checkStatelessRules(packet_info)) |alert| {
            if (alert.severity == .Critical or alert.severity == .High) {
                try triggerVulnerabilityScan(self, alert, packet_info);
            }
            return alert;
        }

        // then check stateful rules that use connection context
        if (try self.checkStatefulRules(packet_info, conn_state)) |alert| {
            // Trigger vulnerability scan for Critical/High alerts
            if (alert.severity == .Critical or alert.severity == .High) {
                try triggerVulnerabilityScan(self, alert, packet_info);
            }
            return alert;
        }
        
        return null;
    }

    /// Check rules that don't require connection state
    fn checkStatelessRules(
        self: *DetectionEngine,
        packet_info: capture.PacketInfo
    ) !?Alert {
        // check each enabled rule
        for (self.rules.items) |rule| {
            if (!rule.enabled or rule.requires_conn_state) continue;
            
            // if the rule condition matches, generate an alert
            if (rule.condition(packet_info, null)) {
                return try self.createAlert(rule, packet_info);
            }
        }
        return null;
    }

    /// Check rules that require connection state
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

    /// Create an alert from a triggered rule
    fn createAlert(
        self: *DetectionEngine,
        rule: DetectionRule,
        packet_info: capture.PacketInfo
    ) !Alert {
        // get next alert ID (thread-safe)
        const alert_id = self.alert_counter.fetchAdd(1, .monotonic);
        
        // format source IP as string (e.g. "192.168.1.1")
        const source_ip_str = try std.fmt.allocPrint(
            self.allocator,
            "{d}.{d}.{d}.{d}",
            .{
                packet_info.source_ip[0], packet_info.source_ip[1],
                packet_info.source_ip[2], packet_info.source_ip[3]
            }
        );
        defer self.allocator.free(source_ip_str);

        // format destination IP as string
        const dest_ip_str = try std.fmt.allocPrint(
            self.allocator, 
            "{d}.{d}.{d}.{d}",
            .{
                packet_info.dest_ip[0], packet_info.dest_ip[1],
                packet_info.dest_ip[2], packet_info.dest_ip[3]
            }
        );
        defer self.allocator.free(dest_ip_str);
        
        // format ports as strings
        const source_port_str = try std.fmt.allocPrint(
        self.allocator, "{d}", .{packet_info.source_port}
        );
        defer self.allocator.free(source_port_str);
        
        const dest_port_str = try std.fmt.allocPrint(
            self.allocator, "{d}", .{packet_info.dest_port}
        );
        defer self.allocator.free(dest_port_str);
        
        // get protocol name
        const protocol_str = @tagName(packet_info.protocol);
                
        // format alert message with connection details
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

        // use rule name as alert category
        const category = try self.allocator.dupe(u8, rule.name);
                
        // create and return the alert
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
    
    /// Load a set of predefined detection rules
    pub fn loadDefaultRules(self: *DetectionEngine) !void {
        // suspicious port detection
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

        // Bandwidth usage detection
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

        // DNS protocol anomaly detection
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

        // HTTP traffic detection
        try self.addRule(DetectionRule{
            .id = 2001,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "HTTP Traffic Detected"),
            .severity = .Low,
            .condition = detectBasicHttpTraffic,
            .message_template = try self.allocator.dupe(
                u8,
                "HTTP traffic from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });

        // Multiple small connections
        try self.addRule(DetectionRule{
            .id = 2002,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Multiple Small Connections"),
            .severity = .Low,
            .condition = detectMultipleSmallConnections,
            .message_template = try self.allocator.dupe(
                u8, 
                "Multiple small connections from {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });

        // Non-standard HTTP method
        try self.addRule(DetectionRule{
            .id = 2003,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Non-Standard HTTP Method"),
            .severity = .Low,
            .condition = detectNonStandardHttpMethod,
            .message_template = try self.allocator.dupe(
                u8, 
                "Non-standard HTTP method from {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });

        // Backdoor communication
        try self.addRule(DetectionRule{
            .id = 3003,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Backdoor Communication"),
            .severity = .Critical,
            .condition = detectBackdoorCommunication,
            .message_template = try self.allocator.dupe(
                u8, 
                "Backdoor communication detected from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = false,
        });

        // Known exploit attempt
        try self.addRule(DetectionRule{
            .id = 3005,
            .enabled = true,
            .name = try self.allocator.dupe(u8, "Known Exploit Attempt"),
            .severity = .Critical,
            .condition = detectKnownExploit,
            .message_template = try self.allocator.dupe(
                u8, 
                "Known exploit attempt from {d}.{d}.{d}.{d}:{d} to {d}.{d}.{d}.{d}:{d}"
            ),
            .requires_conn_state = true,
        });
    }
};

/// Payload signature for pattern matching
pub const PayloadSignature = struct {
    /// Unique identifier for this signature
    id: u32,
    /// Human-readable name
    name: []const u8,
    /// Binary pattern to match in packet payload
    pattern: []const u8,
    /// Category of attack (e.g., "Web AttacK", "Malware")
    category: []const u8,
    /// Severity if detected
    severity: AlertSeverity,
};

/// Database of known malicious payload patterns
/// These signatures detect common attack patterns in network traffic
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

/// Information about network ports and their security implications
pub const PortInfo = struct {
    /// Port number
    port: u16,
    /// Service name typically associated with this port
    service: []const u8,
    /// Category of service (e.g., "Backdoor", "Database")
    category: []const u8,
    /// Risk level on a scale of 1-10 (higher is more suspicious)
    risk_level: u8,
};

/// Structure to track port scanning state
const PortScanState = struct {
    /// When this source was last seen scanning
    last_seen: i64,
    /// When this source was first seen scanning
    first_seen: i64,
    /// Set of unique destination ports targeted
    target_ports: std.AutoHashMap(u16, void),
    /// Set of unique destination IPs targeted
    target_ips: std.AutoHashMap([4]u8, void),
    /// Rate of port scanning (ports/second)
    scan_rate: f32,
};

/// Database of suspicious ports with context
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
/// Uses port knowledge base and traffic characteristics to identify suspicious activity
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
        
        // high risk ports are always suspicious
        if (context.risk_level >= 8) {
            is_suspicious = true;
        }
        // for medium risk ports, use additional context
        else if (context.risk_level >= 5) {
            // 2. Consider port context and traffic direction
            
            // clear text protocols crossing network boundaries are suspicious
            if (std.mem.eql(u8, context.category, "ClearText") and 
                !isPrivateIP(packet.dest_ip)) {
                is_suspicious = true;
            }
            
            // database services exposed to the internet are suspicious
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
            // source ports matching high-risk services are unusual
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
            // looks like HTTP but not on standard port
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

    if (is_suspicious and port_info != null) {
        log.debug("Suspicious port {d} ({s}) detected with risk level {d}", 
            .{ port_info.?.port, port_info.?.service, port_info.?.risk_level });
    }
    
    return is_suspicious;
}

/// Detect unusually large packets (potential data exfiltration or buffer overflow)
fn detectLargePacket(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    _ = conn_state; // not used
    const LARGE_PACKET_THRESHOLD: u32 = 8000; // bytes
    return packet.captured_len > LARGE_PACKET_THRESHOLD;
}

/// Detect high packet rate (potential DoS attack)
fn detectHighPacketRate(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        // alert if packet rate exceeds threshold and we've seen enough packets
        const PACKET_RATE_THRESHOLD: f32 = 100.0; // packets per second
        const MIN_PACKETS_NEEDED: u32 = 20; // minimum sample size

        return conn.packets_per_second > PACKET_RATE_THRESHOLD and
            conn.packet_count >= MIN_PACKETS_NEEDED;
    }

    return false;
}

/// Detect high bandwidth usage (potential DoS or data exfiltration)
fn detectHighBandwidth(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        // alert if bandwidth exceeds threshold (10MB/s) and we've seen enough traffic
        const BANDWIDTH_THRESHOLD: f32 = 10.0 * 1024.0 * 1024.0; // 10 MB/s
        const MIN_BYTES_NEEDED: u64 = 100 * 1024; // 100KB minimum sample
        
        return conn.bytes_per_second > BANDWIDTH_THRESHOLD and 
               conn.byte_count >= MIN_BYTES_NEEDED;
    }
    return false;
}

/// Detect SYN flood attacks (TCP DoS technique)
pub fn detectSynFlood(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        // alert on connections that stay in SYN_SENT state with multiple packets
        const SYN_FLOOD_PACKET_THRESHOLD: u32 = 25;

        const now = std.time.timestamp();
        const time_window = now - conn.first_seen;
        //const MIN_TIME_WINDOW: i64 = 10; // at least 10 seconds to avoid false positives
        const MAX_TIME_WINDOW: i64 = 20;

        if (packet.protocol != .TCP or conn.tcp_state != .SynSent) {
            return false;
        }

        const has_enough_packets = conn.packet_count >= SYN_FLOOD_PACKET_THRESHOLD;
        const is_rapid = time_window <= MAX_TIME_WINDOW;

        const high_rate = conn.packets_per_second > 5.0;

        return has_enough_packets and is_rapid and high_rate;
    }
    return false;
}

/// Enhanced port scan detection using both connection-level and global heuristics
fn detectPortScan(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    // perform connection-level checks first
    if (conn_state) |conn| {
        if (packet.protocol == .TCP and conn.tcp_state == .SynSent) {
            if (conn.packet_count > 10) {
                return false; // potential SYN flood, not a scan
            }

            if (conn.packets_per_second > 3.0 and conn.packet_count > 5) {
                return false; // too high rate, likely not a scan
            }
        }
        
        // 1. Connection-level characteristics of port scans
        
        // SYN scan detection - single packet, SYN only, no further communication
        const is_single_packet = conn.packet_count == 1;
        const is_syn_only = packet.protocol == .TCP and conn.tcp_state == .SynSent;
        
        // FIN/NULL scan detection
        const is_fin_scan = packet.protocol == .TCP and 
                          (conn.tcp_state == .Unknown or conn.tcp_state == .Closed);
                          
        // short connection with very little data (typical of scans)
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
            
            // if this looks like a scan and fits into a larger pattern, alert
            if (is_part_of_scan) {
                return true;
            }
        }
    }
    
    return false;
}

/// Check if IP is in private ranges (RFC 1918)
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

/// Detect malicious payload patterns (signature-based detection)
fn detectPayloadPattern(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    // first check direct payload if available
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

    // then check connection state payload sample as backup
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

/// Detect HTTP protocol anomalies and attacks
fn detectHttpAnomaly(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload| {
            if (packet.protocol != .TCP) return false;
            
            // only check if it looks like HTTP traffic
            if (!isHttpTraffic(payload)) return false;
            
            // check for oversized HTTP headers (potential buffer overflow)
            if (std.mem.indexOf(u8, payload, "Content-Length: ")) |pos| {
                // extract length value
                var end_pos: usize = pos + 16; // "Content-Length: " is 16 chars
                while (end_pos < payload.len and payload[end_pos] >= '0' and payload[end_pos] <= '9') {
                    end_pos += 1;
                }
                
                if (end_pos > pos + 16) {
                    const length_str = payload[pos+16..end_pos];
                    const content_length = std.fmt.parseInt(u32, length_str, 10) catch {
                        return false; // invalid integer
                    };
                    
                    // alert on suspiciously large content length
                    const MAX_REASONABLE_SIZE: u32 = 10 * 1024 * 1024; // 10MB
                    if (content_length > MAX_REASONABLE_SIZE) {
                        return true;
                    }
                }
            }
            
            // check for very long URL (potential DoS/buffer overflow)
            if (std.mem.indexOf(u8, payload, "GET ")) |pos| {
                var end_pos: usize = pos + 4;
                while (end_pos < payload.len and payload[end_pos] != ' ') {
                    end_pos += 1;
                }
                
                const url_length = end_pos - (pos + 4);
                const MAX_URL_LENGTH: usize = 2000; // reasonable URL length
                
                if (url_length > MAX_URL_LENGTH) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

/// Check if payload appears to be HTTP traffic
fn isHttpTraffic(payload: []const u8) bool {
    // Common HTTP methods and response patterns
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

/// Detect DNS protocol anomalies and potential DNS tunneling
/// Analyzes DNS packets for unusual patterns that may indicate abuse
/// Including: oversized packets, high entropy domain names, excessive subdomains
fn detectDnsAnomaly(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload| {
            if (packet.protocol != .UDP or (packet.dest_port != 53 and packet.source_port != 53)) 
                return false;
            
            // basic check for DNS query packet format
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
            if (opcode != 0) { // not a standard query
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
                    if (label_len == 0) break; // end of QNA

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
                if (total_domain_len > 255) return true; // max allowed by DNS

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

/// Detect basic HTTP traffic
fn detectBasicHttpTraffic(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload| {
            // simple HTTP detection
            return std.mem.indexOf(u8, payload, "GET ") != null or
                   std.mem.indexOf(u8, payload, "POST ") != null or
                   std.mem.indexOf(u8, payload, "HTTP/") != null;
        }
    }
    return false;
}

/// Detect multiple small connections
fn detectMultipleSmallConnections(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        // alert on connections with moderate packet count but low data
        return conn.packet_count >= 3 and 
               conn.packet_count <= 10 and 
               conn.byte_count < 1000;
    }
    return false;
}

/// Detect non-standard HTTP methods
fn detectNonStandardHttpMethod(_: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload| {
            const unusual_methods = [_][]const u8{
                "TRACE ", "OPTIONS ", "CONNECT ", "PATCH ", "DELETE "
            };
            
            for (unusual_methods) |method| {
                if (std.mem.indexOf(u8, payload, method) != null) {
                    return true;
                }
            }
        }
    }
    return false;
}

/// Detect backdoor communication
fn detectBackdoorCommunication(packet: capture.PacketInfo, _: ?*const ConnectionState) bool {
    // checking for connections to known backdoor ports
    const backdoor_ports = [_]u16{
        1337, 4444, 5554, 6666, 12345, 31337, 9999, 6969, 1234, 54321
    };
    
    for (backdoor_ports) |port| {
        if (packet.dest_port == port or packet.source_port == port) {
            return true;
        }
    }
    
    return false;
}

/// Enhanced detection that checks the full packet data
fn detectKnownExploit(packet: capture.PacketInfo, conn_state: ?*const ConnectionState) bool {
    if (packet.payload) |direct_payload| {
        const exploit_patterns = [_][]const u8{
            "cmd=", "exec=", "file=", "info=", 
            "bash%20-i", "cmd.exe%20", "uname%20-a", "../../../etc/"
        };
        
        for (exploit_patterns) |pattern| {
            if (std.mem.indexOf(u8, direct_payload, pattern) != null) {
                return true;
            }
        }
    }
    
    if (conn_state) |conn| {
        if (conn.payload_sample) |payload| {
            const exploit_patterns = [_][]const u8{
                "cmd=", "exec=", "file=", "info=", 
                "bash%20-i", "cmd.exe%20", "uname%20-a", "../../../etc/"
            };
            
            for (exploit_patterns) |pattern| {
                if (std.mem.indexOf(u8, payload, pattern) != null) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

/// Trigger external vulnerability scan when critical threats detected
fn triggerVulnerabilityScan(self: *DetectionEngine, alert: Alert, packet: capture.PacketInfo) !void {
    // Scanning only on Critical or High severity alerts
    if (alert.severity != .Critical and alert.severity != .High) {
        return;
    }

    // Only scan if Shrykull manager is available
    if (self.shrykull_manager == null) {
        std.log.debug("Shrykull scanner not enabled, skipping vulnerability scan", .{});
        return;
    }

    // Build scan request
    const scan_request = shrykull.ScanRequest{
        .request_id = "",
        .target_ip = packet.source_ip,
        .ports = inferSuspiciousPorts(alert, packet),
        .reason = alert.message,
        .severity = @tagName(alert.severity),
        .attack_type = inferAttackType(alert),
        .payload_sample = if (packet.payload) |p| 
            p[0..@min(256, p.len)] 
        else 
            null,
        .scan_options = .{
            .depth = if (alert.severity == .Critical) "full" else "standard",
            .priority = if (alert.severity == .Critical) "critical" else "high",
        },
    };

    try self.shrykull_manager.?.requestScan(scan_request);

    std.log.info("Vulnerability scan triggered for {s} alert from {d}.{d}.{d}.{d}", 
        .{@tagName(alert.severity), packet.source_ip[0], packet.source_ip[1], 
          packet.source_ip[2], packet.source_ip[3]});
}

/// Infer which ports should be scanned based on the alert
fn inferSuspiciousPorts(alert: Alert, packet: capture.PacketInfo) []const u16 {
    _ = alert; // unused for now

    // return the port involved in the alert
    const ports = [_]u16{packet.dest_port};
    return &ports;
}

/// Infer the type of attack from the alert
fn inferAttackType(alert: Alert) []const u8 {
    return alert.category;
}

/// Global tracker for port scanning activities across all connections
/// Maintains state about scanning patterns to detect horizontal, vertical and block scans
const PortScanTracker = struct {
    /// Maps source IPs to their scanning activity state
    var ip_scan_attempts = std.AutoHashMap([4]u8, PortScanState).init(std.heap.page_allocator);
    
    /// Timestamp of last cleanup operation
    var last_cleanup: i64 = 0;
    
    /// Process a potential scanning packet and determine if it's part of a port scan
    /// 
    /// Parameters:
    ///   source_ip: IP address initiating the connection
    ///   dest_ip: Target IP address
    ///   dest_port: Target port number
    ///   now: Current timestamp
    /// 
    /// Returns:
    ///   true if this packet appears to be part of a port scan pattern
    pub fn trackScan(source_ip: [4]u8, dest_ip: [4]u8, dest_port: u16, now: i64) !bool {
        // cleanup old entries every 5 minutes
        if (now - last_cleanup > 300) {
            try cleanupOldEntries(now);
            last_cleanup = now;
        }
        
        var is_scan = false;
        var scan_state: *PortScanState = undefined;
        
        // get or create scan state for this source IP
        if (ip_scan_attempts.getPtr(source_ip)) |state| {
            scan_state = state;
        } else {
            // initialize new scan state
            try ip_scan_attempts.put(source_ip, PortScanState{
                .last_seen = now,
                .target_ports = std.AutoHashMap(u16, void).init(std.heap.page_allocator),
                .target_ips = std.AutoHashMap([4]u8, void).init(std.heap.page_allocator),
                .first_seen = now,
                .scan_rate = 0,
            });
            scan_state = ip_scan_attempts.getPtr(source_ip).?;
        }
        
        // update scan state with new target information
        scan_state.last_seen = now;
        try scan_state.target_ports.put(dest_port, {});
        try scan_state.target_ips.put(dest_ip, {});
        
        // calculate scan rate (ports per second)
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
    
    /// Remove old scan tracking entries to prevent memory exhaustion
    /// Frees resources for sources that haven't been active recently
    fn cleanupOldEntries(now: i64) !void {
        var to_remove = std.ArrayList([4]u8).init(std.heap.page_allocator);
        defer to_remove.deinit();
        
        // find old entries (older than 30 minutes)
        var it = ip_scan_attempts.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr;
            if (now - state.last_seen > 1800) { // 30 minutes
                try to_remove.append(entry.key_ptr.*);
            }
        }
        
        // remove old entries and free their resources
        for (to_remove.items) |ip| {
            if (ip_scan_attempts.getPtr(ip)) |state| {
                state.target_ports.deinit();
                state.target_ips.deinit();
            }
            _ = ip_scan_attempts.remove(ip);
        }
    }
    
    /// Free all resources used by the port scan tracker
    pub fn deinit() void {
        var it = ip_scan_attempts.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.target_ports.deinit();
            entry.value_ptr.target_ips.deinit();
        }
        ip_scan_attempts.deinit();
    }
};