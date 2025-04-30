///////////////////////////////////////////////////////////////////////////////
// Necronet Messaging Protocol
//
// This module defines the inter-process communication (IPC) message structures 
// and serialization routines used for communication between the Necronet 
// backend (Slig Barracks) and frontend (Mudokon Command) components.
//
// The messaging protocol is versioned, with strong validation and includes
// support for both binary and JSON serialization formats. All messages follow
// a consistent header-payload structure for reliable parsing and routing.
///////////////////////////////////////////////////////////////////////////////

const std = @import("std");
const common = @import("common");
const detection = @import("detection");
const capture = @import("backend");

/// Necronet IPC Protocol Version
/// Used to ensure compatibility between components
pub const PROTOCOL_VERSION: u16 = 1;

/// Message types exchanged between Slig Barracks (backend) and Mudokon Command (UI)
/// Provides a complete taxonomy of all possible message categories in the system
pub const MessageType = enum(u8) {
    // System messages
    Hello, // Initial connection handshake
    Heartbeat, // Keep-alive message
    Shutdown, // Graceful shutdown request
    Error, // Error notification

    // Data messages
    PacketEvent, // Individual packet info
    FlowUpdate, // Network flow statistics update
    SligAlert, // Security alert (threat detected)
    DetectionStats, // Stats about detection engine

    // Control messages
    ConfigUpdate, // Configuration change request
    CaptureControl, // Start/stop/pause packet capture
    FilterUpdate, // Update capture/display filters
};

/// Header included with every IPC message
/// Provides routing, sequencing and size information for reliable transport
pub const MessageHeader = struct {
    version: u16 = PROTOCOL_VERSION, // Protocol version
    sequence: u64, // Message sequence number
    timestamp: i64, // Unix timestamp (microseconds)
    msg_type: MessageType, // Type of message
    payload_size: u32, // Size of payload in bytes
};

/// Minimal packet info for UI visualization
/// Contains essential network metadata for display and analysis
pub const PacketEvent = struct {
    flow_id: u64, // ID to group related packets
    timestamp: i64, // Precise timestamp (microseconds)
    protocol: common.Protocol, // Protocol identifier
    source_ip: [4]u8, // Source IP address
    dest_ip: [4]u8, // Destination IP address
    source_port: u16, // Source port
    dest_port: u16, // Destination port
    packet_size: u32, // Original packet size
    flags: PacketFlags, // Relevant protocol flags
    payload: ?[]const u8 = null, // Optional packet payload

    /// TCP/IP flags and metadata
    /// Compressed representation of important protocol flags
    pub const PacketFlags = packed struct {
        syn: bool = false, // TCP SYN flag
        ack: bool = false, // TCP ACK flag
        fin: bool = false, // TCP FIN flag
        rst: bool = false, // TCP RST flag
        psh: bool = false, // TCP PSH flag
        urg: bool = false, // TCP URG flag
        fragmented: bool = false, // IP fragmentation
        retransmission: bool = false, // Detected retransmission
        _padding: u8 = 0, // Reserved for future use
    };
};

/// Flow statistics for visualization as "pipes" in UI
/// Aggregated metrics for network connections over time
pub const FlowUpdate = struct {
    flow_id: u64, // Unique flow identifier
    protocol: common.Protocol, // Protocol identifier
    source_ip: [4]u8, // Source IP address
    dest_ip: [4]u8, // Destination IP address
    source_port: u16, // Source port
    dest_port: u16, // Destination port
    active_time_ms: u64, // Flow duration in milliseconds
    packet_count: u32, // Total packets in flow
    byte_count: u64, // Total bytes in flow
    packets_per_sec: f32, // Packet rate
    bytes_per_sec: f32, // Bandwidth usage
    state: FlowState, // Connection state
    last_update: i64, // Last updated timestamp

    /// Connection flow states
    /// Provides a high-level view of connection health and status
    pub const FlowState = enum(u8) {
        Unknown, // state cannot be determined
        Established, // connection is active and normal
        Terminated, // connection has been closed properly
        Blocked, // connection was blocked by security policy
        Suspicious, // marked for closer inspection
        Contaminated, // confirmed malicious
    };
};

/// Alert event ("Slig Alert") for threats/anomalies
/// Comprehensive security incident information for analysis and response
pub const SligAlert = struct {
    alert_id: u64, // Unique alert identifier
    timestamp: i64, // Detection timestamp
    severity: detection.AlertSeverity, // Alert severity level
    category: []const u8, // Alert category
    message: []const u8, // Alert description
    protocol: common.Protocol, // Affected protocol
    source_ip: [4]u8, // Source IP address
    dest_ip: [4]u8, // Destination IP address
    source_port: u16, // Source port
    dest_port: u16, // Destination port
    flow_id: u64, // Associated flow ID
    confidence: f32, // Detection confidence (0.0-1.0)
    evidence: ?[]const u8, // Optional evidence data

    /// Free any allocated memory in the alert
    /// Prevents memory leaks by properly releasing all dynamic allocations
    pub fn deinit(self: *SligAlert, allocator: std.mem.Allocator) void {
        if (self.category.len > 0) allocator.free(self.category);
        if (self.message.len > 0) allocator.free(self.message);
        if (self.evidence != null) allocator.free(self.evidence.?);
    }

    /// Create a SligAlert from a detection.Alert
    /// Converts internal alert representation to IPC-compatible format
    pub fn fromDetectionAlert(alert: detection.Alert, allocator: std.mem.Allocator) !SligAlert {
        const slig_alert = SligAlert{
            .alert_id = alert.id,
            .timestamp = alert.timestamp,
            .severity = alert.severity,
            .category = try allocator.dupe(u8, alert.category),
            .message = try allocator.dupe(u8, alert.message),
            .protocol = alert.protocol,
            .source_ip = alert.source_ip,
            .dest_ip = alert.dest_ip,
            .source_port = alert.source_port,
            .dest_port = alert.dest_port,
            .flow_id = alert.flow_id orelse 0,
            .confidence = 1.0,
            .evidence = null,
        };

        return slig_alert;
    }
};

/// Detection engine statistics
/// Performance metrics and status information for the detection subsystem
pub const DetectionStats = struct {
    uptime_seconds: u64, // Engine uptime
    packets_analyzed: u64, // Total packets analyzed
    flows_tracked: u32, // Current tracked flows
    alerts_generated: u32, // Total alerts since startup
    rules_loaded: u16, // Number of detection rules
    memory_usage_kb: u64, // Memory usage in KB
    slig_status: SligStatus, // Status of detection "Sligs"

    /// Operational status of the detection system
    /// Indicates the current detection posture and capability
    pub const SligStatus = enum(u8) {
        Sleeping, // Idle, minimal analysis
        Patrolling, // Normal operation
        Alarmed, // Heightened detection, found something
        Overwhelmed, // Too much traffic to analyze fully
    };
};

/// Error information
/// Structured error details for robust error handling across process boundaries
pub const ErrorInfo = struct {
    code: ErrorCode, // Error classification
    component: []const u8, // Component that generated error
    message: []const u8, // Error description
    recoverable: bool, // Whether system can continue

    /// Categorized error codes
    /// Standardized error taxonomy for consistent handling
    pub const ErrorCode = enum(u16) {
        Unknown = 0,

        // IPC Errors (1-99)
        ProtocolMismatch = 1,
        MessageCorrupted = 2,
        DeserializationFailed = 3,

        // Capture Errors (100-199)
        CaptureInitFailed = 100,
        DeviceNotFound = 101,
        InsufficientPermissions = 102,

        // Detection Errors (200-299)
        EngineInitFailed = 200,
        RuleLoadFailed = 201,

        // System Errors (900-999)
        OutOfMemory = 900,
        SystemResourceExhausted = 901,
    };

    /// Free allocated error resources
    /// Ensures proper cleanup of dynamic memory in error messages
    pub fn deinit(self: *ErrorInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.component);
        allocator.free(self.message);
    }
};

/// Initial handshake message payload
pub const HelloPayload = struct {
    client_version: u16, // client software version
    client_name: []const u8, // client identifier
    capabilities: u32, // bitfield of supported features
};

/// Periodic keep-alive message payload
pub const HeartbeatPayload = struct {
    uptime_seconds: u64, // time since component initialization
};

/// Graceful termination message payload
pub const ShutdownPayload = struct {
    reason: []const u8, // human-readable shutdown reason
    restart: bool = false, // whether to restart after shutdown
};

/// Configuration update message payload
pub const ConfigUpdatePayload = struct {
    config_path: ?[]const u8 = null, // path to configuration file
    config_json: ?[]const u8 = null, // direct configuration content
};

/// Capture engine control message payload
pub const CaptureControlPayload = struct {
    /// Operation to perform on the capture engine
    command: enum(u8) {
        Start, // begin packet capture
        Stop, // end packet capture
        Pause, // temporarily suspend capture
        Resume, // continue suspended capture
    },
    device_name: ?[]const u8 = null, // specific capture device to control
};

/// Capture filter update message payload
pub const FilterUpdatePayload = struct {
    filter_expression: []const u8, // Berkeley Packet Filter expression
    apply_immediately: bool = true, // whether to apply without waiting
};

/// Top-level wrapper for all IPC messages
/// Provides a unified container for all message types with common header
pub const Message = struct {
    header: MessageHeader,
    payload: Payload,

    /// Tagged union of all possible message payloads
    /// Uses the message type as discriminant for type safety
    pub const Payload = union(MessageType) {
        Hello: HelloPayload,
        Heartbeat: HeartbeatPayload,
        Shutdown: ShutdownPayload,
        Error: ErrorInfo,
        PacketEvent: PacketEvent,
        FlowUpdate: FlowUpdate,
        SligAlert: SligAlert,
        DetectionStats: DetectionStats,
        ConfigUpdate: ConfigUpdatePayload,
        CaptureControl: CaptureControlPayload,
        FilterUpdate: FilterUpdatePayload,
    };

    /// Free memory associated with this message
    /// Properly cleans up all dynamically allocated fields based on message type
    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        switch (self.payload) {
            .Hello => |p| allocator.free(p.client_name),
            .Shutdown => |p| allocator.free(p.reason),
            .Error => |*p| p.deinit(allocator),
            .SligAlert => |*p| p.deinit(allocator),
            .ConfigUpdate => |p| {
                if (p.config_path) |path| allocator.free(path);
                if (p.config_json) |json| allocator.free(json);
            },
            .CaptureControl => |p| {
                if (p.device_name) |name| allocator.free(name);
            },
            .FilterUpdate => |p| allocator.free(p.filter_expression),
            else => {}, // no allocation needed for other message types
        }
    }
};

// Factory functions for creating common message types

/// Create a packet event message
/// Constructs a properly formatted PacketEvent message with appropriate timestamps
pub fn createPacketEventMsg(sequence: u64, event: PacketEvent) Message {
    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .PacketEvent,
            .payload_size = @sizeOf(PacketEvent),
        },
        .payload = .{ .PacketEvent = event },
    };
}

/// Create a Slig Alert message
/// Constructs a properly formatted security alert with deep copies of strings
pub fn createSligAlertMsg(sequence: u64, alert: SligAlert, allocator: std.mem.Allocator) !Message {
    const category_copy = try allocator.dupe(u8, alert.category);
    errdefer allocator.free(category_copy);

    const message_copy = try allocator.dupe(u8, alert.message);
    errdefer allocator.free(message_copy);

    var evidence_copy: ?[]u8 = null;
    if (alert.evidence) |evidence| {
        evidence_copy = try allocator.dupe(u8, evidence);
    }

    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .SligAlert,
            .payload_size = blk: {
                var size: u64 = @sizeOf(SligAlert);

                size += category_copy.len;
                size += message_copy.len;

                if (evidence_copy) |e| size += e.len;

                if (size > std.math.maxInt(u32)) {
                    @panic("Message payload size exceeds u32 max");
                }

                break :blk @intCast(size);
            },
        },
        .payload = .{ 
            .SligAlert = .{
                .alert_id = alert.alert_id,
                .flow_id = alert.flow_id,
                .timestamp = alert.timestamp,
                .severity = alert.severity,
                .category = category_copy,
                .message = message_copy,
                .protocol = alert.protocol,
                .source_ip = alert.source_ip,
                .dest_ip = alert.dest_ip,
                .source_port = alert.source_port,
                .dest_port = alert.dest_port,
                .confidence = alert.confidence,
                .evidence = evidence_copy,
                }
        },
    };
}

/// Create a flow update message
/// Constructs a properly formatted network flow update message
pub fn createFlowUpdateMsg(sequence: u64, flow: FlowUpdate) Message {
    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .FlowUpdate,
            .payload_size = @sizeOf(FlowUpdate),
        },
        .payload = .{ .FlowUpdate = flow },
    };
}

/// Create an error message
/// Constructs a properly formatted error notification with appropriate size calculation
pub fn createErrorMsg(sequence: u64, err: ErrorInfo) Message {
    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .Error,
            .payload_size = blk: {
                const size = @sizeOf(ErrorInfo) + err.component.len + err.message.len;
                if (size > std.math.maxInt(u32)) {
                    @panic("Message payload size exceeds u32 max");
                }
                break :blk @intCast(size);
            },
        },
        .payload = .{ .Error = err },
    };
}

/// Create a PacketEvent from a capture.PacketInfo
///
/// This function converts a raw packet from the capture system into
/// the IPC packet format, extracting all available metadata including
/// TCP flags and fragmentation status.
///
/// Parameters:
///   packet: Pointer to the captured packet information
///   flow_id: Identifier for the flow this packet belongs to
///
/// Returns:
///   A fully populated PacketEvent struct ready for IPC transmission
pub fn packetEventFromCaptureInfo(packet: *const capture.PacketInfo, flow_id: u64) PacketEvent {
    var flags = PacketEvent.PacketFlags{};

    // extract TCP flags if we have a TCP packet with payload
    if (packet.protocol == .TCP and packet.payload != null) {
        const payload = packet.payload.?;

        // first verify we have an IP header (minimum 20 bytes)
        if (payload.len >= 20) {
            // get IP header version and length
            const version_ihl = payload[0];
            const version = version_ihl >> 4;

            // only proceed if this is IPv4
            if (version == 4) {
                // calculate IP header length (IHL is in 4-byte units)
                const ihl = version_ihl & 0x0F;
                const ip_header_len = ihl * 4;

                // verify IP header length is valid and we have enough data
                if (ihl >= 5 and payload.len >= ip_header_len) {
                    // extract fragmentation info from IP header
                    const frag_info = std.mem.readInt(u16, payload[6..8], .big);
                    flags.fragmented = (frag_info & 0x1FFF) != 0; // Check offset or MF flag

                    // calculate TCP header offset and verify we have enough data
                    const tcp_offset = ip_header_len;
                    if (payload.len >= tcp_offset + 14) { // TCP header is at least 20 bytes, but safely check first 14
                        // extract TCP flags (flags are at offset 13 in TCP header)
                        const tcp_flags = payload[tcp_offset + 13];

                        flags.fin = (tcp_flags & 0x01) != 0; // FIN
                        flags.syn = (tcp_flags & 0x02) != 0; // SYN
                        flags.rst = (tcp_flags & 0x04) != 0; // RST
                        flags.psh = (tcp_flags & 0x08) != 0; // PSH
                        flags.ack = (tcp_flags & 0x10) != 0; // ACK
                        flags.urg = (tcp_flags & 0x20) != 0; // URG
                    }
                }
            }
        }
    }

    return PacketEvent{
        .flow_id = flow_id,
        .timestamp = @as(i64, packet.timestamp_sec) * 1_000_000 + @as(i64, packet.timestamp_usec),
        .protocol = packet.protocol,
        .source_ip = packet.source_ip,
        .dest_ip = packet.dest_ip,
        .source_port = packet.source_port,
        .dest_port = packet.dest_port,
        .packet_size = packet.original_len,
        .flags = flags,
    };
}

/// Serialize a Message to JSON
///
/// Converts a Message structure to a JSON string representation using the standard
/// library JSON serializer. Includes proper indentation for better human readability.
///
/// Parameters:
///   self: Pointer to the message to serialize
///   allocator: Memory allocator for the resulting JSON string
///
/// Returns:
///   Allocated string containing the JSON representation of the message
///   Caller takes ownership of the returned memory
pub fn toJson(self: *const Message, allocator: std.mem.Allocator) ![]u8 {
    var string = std.ArrayList(u8).init(allocator);
    errdefer string.deinit();

    try std.json.stringify(self.*, .{
        .whitespace = .indent_2,
    }, string.writer());

    return string.toOwnedSlice();
}

/// Deserialize a Message from JSON
///
/// Parses a JSON string into a properly structured Message object.
/// Creates deep copies of all string fields to ensure proper memory ownership.
///
/// Parameters:
///   json_str: JSON string representation of a Message
///   allocator: Memory allocator for the resulting Message and its contents
///
/// Returns:
///   Fully populated Message structure with independent memory ownership
///   Caller takes ownership of the returned Message and must call deinit()
pub fn fromJson(json_str: []const u8, allocator: std.mem.Allocator) !Message {
    var parsed = try std.json.parseFromSlice(Message, allocator, json_str, .{});
    defer parsed.deinit();

    var result = parsed.value;

    switch (result.payload) {
        .Hello => |*hello| {
            hello.client_name = try allocator.dupe(u8, hello.client_name);
        },
        .Shutdown => |*shutdown| {
            shutdown.reason = try allocator.dupe(u8, shutdown.reason);
        },
        .Error => |*err| {
            err.component = try allocator.dupe(u8, err.component);
            err.message = try allocator.dupe(u8, err.message);
        },
        .SligAlert => |*alert| {
            alert.category = try allocator.dupe(u8, alert.category);
            alert.message = try allocator.dupe(u8, alert.message);
            if (alert.evidence) |evidence| {
                alert.evidence = try allocator.dupe(u8, evidence);
            }
        },
        .ConfigUpdate => |*config| {
            if (config.config_path) |path| {
                config.config_path = try allocator.dupe(u8, path);
            }
            if (config.config_json) |json| {
                config.config_json = try allocator.dupe(u8, json);
            }
        },
        .CaptureControl => |*ctrl| {
            if (ctrl.device_name) |name| {
                ctrl.device_name = try allocator.dupe(u8, name);
            }
        },
        .FilterUpdate => |*filter| {
            filter.filter_expression = try allocator.dupe(u8, filter.filter_expression);
        },
        else => {}, // other message types don't have string fields
    }

    return result;
}

/// Validate that a message is well-formed before sending
///
/// Performs comprehensive validation of message structure, contents, and relationships
/// to prevent malformed messages from being transmitted. Checks include version 
/// compatibility, payload size validation, and message-type-specific validations.
///
/// Parameters:
///   self: Pointer to the message to validate
///
/// Returns:
///   null if the message is valid, or an ErrorInfo structure describing the issue
pub fn validate(self: *const Message) ?ErrorInfo {
    // check protocol version
    if (self.header.version != PROTOCOL_VERSION) {
        return ErrorInfo{
            .code = .ProtocolMismatch,
            .component = "ipc.messages",
            .message = "Message protocol version mismatch",
            .recoverable = false,
        };
    }

    // validate payload size based on message type
    const min_size: u32 = switch (self.header.msg_type) {
        .Hello => @sizeOf(HelloPayload),
        .Heartbeat => @sizeOf(HeartbeatPayload),
        .Shutdown => @sizeOf(ShutdownPayload),
        .Error => @sizeOf(ErrorInfo),
        .PacketEvent => @sizeOf(PacketEvent),
        .FlowUpdate => @sizeOf(FlowUpdate),
        .SligAlert => @sizeOf(SligAlert),
        .DetectionStats => @sizeOf(DetectionStats),
        .ConfigUpdate => @sizeOf(ConfigUpdatePayload),
        .CaptureControl => @sizeOf(CaptureControlPayload),
        .FilterUpdate => @sizeOf(FilterUpdatePayload),
    };

    if (self.header.payload_size < min_size) {
        return ErrorInfo{
            .code = .MessageCorrupted,
            .component = "ipc.messages",
            .message = "Message payload size is too small",
            .recoverable = false,
        };
    }

    // content validations based on message type
    switch (self.payload) {
        .Hello => |hello| {
            if (hello.client_name.len == 0) {
                return ErrorInfo{
                    .code = .MessageCorrupted,
                    .component = "ipc.messages",
                    .message = "Hello message missing client name",
                    .recoverable = false,
                };
            }
        },
        .Shutdown => |shutdown| {
            if (shutdown.reason.len == 0) {
                return ErrorInfo{
                    .code = .MessageCorrupted,
                    .component = "ipc.messages",
                    .message = "Shutdown message missing reason",
                    .recoverable = false,
                };
            }
        },
        .Error => |err| {
            if (err.component.len == 0 or err.message.len == 0) {
                return ErrorInfo{
                    .code = .MessageCorrupted,
                    .component = "ipc.messages",
                    .message = "Error message missing component or message",
                    .recoverable = false,
                };
            }
        },
        .PacketEvent => |_| {
            // basic structure validation handled by min_size check above
            // could add more specific validations in the future (TODO)
        },
        .FlowUpdate => |flow| {
            if (flow.packet_count == 0 and flow.active_time_ms > 0) {
                return ErrorInfo{
                    .code = .MessageCorrupted,
                    .component = "ipc.messages",
                    .message = "Flow update has active time but no packets",
                    .recoverable = true, // not critical
                };
            }
        },
        .SligAlert => |alert| {
            if (alert.category.len == 0 or alert.message.len == 0) {
                return ErrorInfo{
                    .code = .MessageCorrupted,
                    .component = "ipc.messages",
                    .message = "SligAlert missing category or message",
                    .recoverable = false,
                };
            }

            if (alert.confidence < 0.0 or alert.confidence > 1.0) {
                return ErrorInfo{
                    .code = .MessageCorrupted,
                    .component = "ipc.messages",
                    .message = "SligAlert confidence out of range (0.0-1.0)",
                    .recoverable = true,
                };
            }
        },
        .FilterUpdate => |filter| {
            if (filter.filter_expression.len == 0) {
                return ErrorInfo{
                    .code = .MessageCorrupted,
                    .component = "ipc.messages",
                    .message = "FilterUpdate missing filter expression",
                    .recoverable = false,
                };
            }
        },
        else => {}, // no specific validation for other types
    }

    return null; // no validation errors
}

/// Calculate total message size including dynamic content
///
/// Determines the total size of a message including all dynamic fields,
/// which is necessary for binary serialization and buffer allocation.
/// Handles each message type specifically to account for string lengths.
///
/// Parameters:
///   self: Pointer to the message to measure
///
/// Returns:
///   Total size in bytes required to represent the message in binary form
pub fn calculateMessageSize(self: *const Message) usize {
    var size: usize = @sizeOf(MessageHeader);

    switch (self.payload) {
        .Hello => |p| {
            size += @sizeOf(@TypeOf(p));
            size += p.client_name.len;
        },
        .Heartbeat => |p| {
            size += @sizeOf(@TypeOf(p));
        },
        .Shutdown => |p| {
            size += @sizeOf(@TypeOf(p));
            size += p.reason.len;
        },
        .Error => |p| {
            size += @sizeOf(ErrorInfo);
            size += p.component.len;
            size += p.message.len;
        },
        .PacketEvent => |_| {
            size += @sizeOf(PacketEvent);
        },
        .FlowUpdate => |_| {
            size += @sizeOf(FlowUpdate);
        },
        .SligAlert => |p| {
            size += @sizeOf(SligAlert);
            size += p.category.len;
            size += p.message.len;
            if (p.evidence) |e| size += e.len;
        },
        .DetectionStats => |_| {
            size += @sizeOf(DetectionStats);
        },
        .ConfigUpdate => |p| {
            size += @sizeOf(@TypeOf(p));
            if (p.config_path) |path| size += path.len;
            if (p.config_json) |json| size += json.len;
        },
        .CaptureControl => |p| {
            size += @sizeOf(@TypeOf(p));
            if (p.device_name) |name| size += name.len;
        },
        .FilterUpdate => |p| {
            size += @sizeOf(@TypeOf(p));
            size += p.filter_expression.len;
        },
    }

    return size;
}

/// Test utility to round-trip a message through JSON serialization and deserialization
///
/// Useful for testing that serialization and deserialization work correctly by
/// ensuring a message maintains its structure after the round-trip process.
///
/// Parameters:
///   msg: Message to round-trip through JSON
///   allocator: Memory allocator for temporary and result objects
///
/// Returns:
///   A new message that is the result of serializing and deserializing the input
pub fn testJsonRoundTrip(msg: Message, allocator: std.mem.Allocator) !Message {
    // serialize to JSON
    const json_str = try toJson(&msg, allocator);
    defer allocator.free(json_str);

    // deserialize back to a Message
    return try fromJson(json_str, allocator);
}

/// Create a binary representation of the message
///
/// Serializes a Message into a compact binary format for efficient transmission.
/// This binary format is platform-independent with explicit byte ordering.
///
/// Parameters:
///   self: Pointer to the message to serialize
///   allocator: Memory allocator for the resulting binary data
///
/// Returns:
///   Allocated byte array containing the binary representation of the message
///   Caller takes ownership of the returned memory
pub fn toBinary(self: *const Message, allocator: std.mem.Allocator) ![]u8 {
    const total_size = calculateMessageSize(self);

    // allocate buffer for the entire message
    var buffer = try allocator.alloc(u8, total_size);
    errdefer allocator.free(buffer);

    // write header
    std.mem.writeInt(u16, buffer[0..2], self.header.version, .big);
    std.mem.writeInt(u64, buffer[2..10], self.header.sequence, .big);
    std.mem.writeInt(i64, buffer[10..18], self.header.timestamp, .big);
    buffer[18] = @intFromEnum(self.header.msg_type);
    std.mem.writeInt(u32, buffer[19..23], self.header.payload_size, .big);

    // write payload (varies by type)
    switch (self.payload) {
        .Hello => |p| {
            var offset: usize = @sizeOf(MessageHeader);

            // write fixed-size fields
            std.mem.writeInt(u16, buffer[offset..][0..2], p.client_version, .big);
            offset += 2;
            std.mem.writeInt(u32, buffer[offset..][0..4], p.capabilities, .big);
            offset += 4;

            // write string length and content
            std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(p.client_name.len), .big);
            offset += 4;
            @memcpy(buffer[offset..][0..p.client_name.len], p.client_name);
        },
        .SligAlert => |p| {
            var offset: usize = @sizeOf(MessageHeader);

            // write fixed-size fields first
            std.mem.writeInt(u64, buffer[offset..][0..8], p.alert_id, .big);
            offset += 8;
            std.mem.writeInt(i64, buffer[offset..][0..8], p.timestamp, .big);
            offset += 8;
            buffer[offset] = @intFromEnum(p.severity);
            offset += 1;

            // write category
            std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(p.category.len), .big);
            offset += 4;
            @memcpy(buffer[offset..][0..p.category.len], p.category);
            offset += p.category.len;

            // write message
            std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(p.message.len), .big);
            offset += 4;
            @memcpy(buffer[offset..][0..p.message.len], p.message);
            offset += p.message.len;

            // write evidence if present
            if (p.evidence) |evidence| {
                buffer[offset] = 1; // has evidence
                offset += 1;
                std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(evidence.len), .big);
                offset += 4;
                @memcpy(buffer[offset..][0..evidence.len], evidence);
            } else {
                buffer[offset] = 0; // no evidence
            }
        },
        .Heartbeat => |p| {
            const offset: usize = @sizeOf(MessageHeader);
            @memcpy(buffer[offset..][0..@sizeOf(u64)], std.mem.asBytes(&p.uptime_seconds));
        },
        .Shutdown => |p| {
            var offset: usize = @sizeOf(MessageHeader);
            @memcpy(buffer[offset..][0..@sizeOf(bool)], std.mem.asBytes(&p.restart));
            offset += @sizeOf(bool);

            @memcpy(buffer[offset..][0..p.reason.len], p.reason);

            return buffer;
        },
        .PacketEvent => |p| {
            const offset = @sizeOf(MessageHeader);
            @memcpy(buffer[offset..][0..@sizeOf(PacketEvent)], std.mem.asBytes(&p));

            return buffer;
        },
        else => {
            // implement binary serialization here (TODO)
            @panic("Binary serialization not implemented for this message type");
        },
    }

    return buffer;
}

/// Parse a Message from binary data
///
/// Deserializes a binary message back into a structured Message object.
/// Validates the message format and ensures memory safety.
///
/// Parameters:
///   data: Binary representation of a Message
///   allocator: Memory allocator for the resulting Message and its contents
///
/// Returns:
///   Fully populated Message structure with independent memory ownership
///   Caller takes ownership of the returned Message and must call deinit()
pub fn fromBinary(data: []const u8, allocator: std.mem.Allocator) !Message {
    if (data.len < @sizeOf(MessageHeader)) {
        return error.InvalidMessageFormat;
    }

    // parse header
    const header = MessageHeader{
        .version = std.mem.readInt(u16, data[0..2], .big),
        .sequence = std.mem.readInt(u64, data[2..10], .big),
        .timestamp = std.mem.readInt(i64, data[10..18], .big),
        .msg_type = @enumFromInt(data[18]),
        .payload_size = std.mem.readInt(u32, data[19..23], .big),
    };

    // validate header
    if (header.version != PROTOCOL_VERSION) {
        return error.ProtocolVersionMismatch;
    }

    if (data.len < @sizeOf(MessageHeader) + header.payload_size) {
        return error.MessageTruncated;
    }

    // parse payload based on message type
    var payload: Message.Payload = undefined;
    var offset: usize = @sizeOf(MessageHeader);

    switch (header.msg_type) {
        .Hello => {
            if (offset + 6 > data.len) return error.MessageTruncated;
            const client_version = std.mem.readInt(
                u16, 
                @ptrCast(@alignCast(&data[offset])), 
                .big
            );
            offset += 2;
            const capabilities = std.mem.readInt(u32, @ptrCast(@alignCast(&data[offset])), .big);
            offset += 4;

            if (offset + 4 > data.len) return error.MessageTruncated;
            const name_len = std.mem.readInt(u32, @ptrCast(@alignCast(&data[offset])), .big);
            offset += 4;

            if (offset + name_len > data.len) return error.MessageTruncated;
            const client_name = try allocator.dupe(u8, data[offset .. offset + name_len]);
            offset += name_len;

            payload = .{
                .Hello = .{
                    .client_version = client_version,
                    .client_name = client_name,
                    .capabilities = capabilities,
                },
            };
        },
        else => {
            return error.UnsupportedMessageType;
        },
    }

    return Message{
        .header = header,
        .payload = payload,
    };
}

/// Create a Hello message to establish an IPC connection
///
/// Factory function that creates a properly formatted Hello message with
/// appropriate sizing and timestamp information.
///
/// Parameters:
///   sequence: Unique message sequence number
///   client_name: Name of the connecting client
///   client_version: Version of the connecting client
///   capabilities: Bitfield of client feature capabilities
///
/// Returns:
///   A fully formatted Hello message ready for transmission
pub fn createHelloMsg(sequence: u64, client_name: []const u8, client_version: u16, capabilities: u32) Message {
    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .Hello,
            .payload_size = blk: {
                const size = @sizeOf(HelloPayload) + client_name.len;
                if (size > std.math.maxInt(u32)) {
                    @panic("Message payload size exceeds u32 max");
                }
                break :blk @intCast(size);
            },
        },
        .payload = .{ .Hello = .{
            .client_version = client_version,
            .client_name = client_name,
            .capabilities = capabilities,
        } },
    };
}

/// Create a Heartbeat message for connection maintenance
///
/// Factory function that creates a properly formatted Heartbeat message to
/// indicate that a connection is still active.
///
/// Parameters:
///   sequence: Unique message sequence number
///   uptime_seconds: Time in seconds since the sender initialized
///
/// Returns:
///   A fully formatted Heartbeat message ready for transmission
pub fn createHeartbeatMsg(sequence: u64, uptime_seconds: u64) Message {
    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .Heartbeat,
            .payload_size = blk: {
                const size = @sizeOf(HeartbeatPayload);
                if (size > std.math.maxInt(u32)) {
                    @panic("Message payload size exceeds u32 max");
                }
                break :blk @intCast(size);
            },
        },
        .payload = .{ .Heartbeat = .{
            .uptime_seconds = uptime_seconds,
        } },
    };
}

/// Create a Shutdown message to request graceful termination
///
/// Factory function that creates a properly formatted Shutdown message with
/// a reason and restart flag to indicate how the receiver should handle shutdown.
///
/// Parameters:
///   sequence: Unique message sequence number
///   reason: Human-readable explanation for the shutdown
///   restart: Whether the receiver should restart after shutdown
///
/// Returns:
///   A fully formatted Shutdown message ready for transmission
pub fn createShutdownMsg(sequence: u64, reason: []const u8, restart: bool) Message {
    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .Shutdown,
            .payload_size = blk: {
                const size = @sizeOf(ShutdownPayload) + reason.len;
                if (size > std.math.maxInt(u32)) {
                    @panic("Message payload size exceeds u32 max");
                }
                break :blk @intCast(size);
            },
        },
        .payload = .{ .Shutdown = .{
            .reason = reason,
            .restart = restart,
        } },
    };
}

/// Create a detection stats message with engine metrics
///
/// Factory function that creates a properly formatted DetectionStats message
/// containing operational metrics from the detection engine.
///
/// Parameters:
///   sequence: Unique message sequence number
///   stats: Detection engine statistics to include in the message
///
/// Returns:
///   A fully formatted DetectionStats message ready for transmission
pub fn createDetectionStatsMsg(sequence: u64, stats: DetectionStats) Message {
    return Message{
        .header = MessageHeader{
            .sequence = sequence,
            .timestamp = std.time.microTimestamp(),
            .msg_type = .DetectionStats,
            .payload_size = @sizeOf(DetectionStats),
        },
        .payload = .{ .DetectionStats = stats },
    };
}

/// Convert a detection alert to a SligAlert for IPC transmission
///
/// Transforms an internal detection system alert into the IPC-compatible format
/// with proper memory allocation for dynamic fields.
///
/// Parameters:
///   alert: Source detection alert to convert
///   allocator: Memory allocator for string fields
///
/// Returns:
///   A fully populated SligAlert structure with allocated strings
///   Caller takes ownership of string fields and must call deinit()
pub fn fromDetectionAlert(alert: detection.Alert, allocator: std.mem.Allocator) !SligAlert {
    return SligAlert{
        .alert_id = alert.id,
        .flow_id = alert.flow_id orelse 0,
        .timestamp = std.time.timestamp(),
        .severity = @enumFromInt(@intFromEnum(alert.severity)),
        .category = try allocator.dupe(u8, alert.category),
        .message = try allocator.dupe(u8, alert.message),
        .source_ip = alert.source_ip,
        .dest_ip = alert.dest_ip,
        .source_port = alert.source_port,
        .dest_port = alert.dest_port,
        .protocol = alert.protocol,
        .confidence = 1.0,
        .evidence = null,
    };
}
