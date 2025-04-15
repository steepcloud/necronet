const std = @import("std");
const common = @import("common");
const Allocator = std.mem.Allocator;

/// Represents a message that can be sent between processes
pub const Message = struct {
    /// Type of message
    message_type: MessageType,
    /// Timestamp when message was created
    timestamp: i64,
    /// Payload data (varies based on message type)
    data: MessageData,

    pub fn init(message_type: MessageType, data: MessageData) Message {
        return Message{
            .message_type = message_type,
            .timestamp = std.time.timestamp(),
            .data = data,
        };
    }
};

/// Types of messages that can be exchanged
pub const MessageType = enum {
    /// New packet captured
    PacketCaptured,
    /// Alert about suspicious activity
    Alert,
    /// Command to start/stop capture
    Command,
    /// Response to a command
    Response,
};

/// Data carried in messages
pub const MessageData = union(MessageType) {
    PacketCaptured: PacketData,
    Alert: AlertData,
    Command: CommandData,
    Response: ResponseData,
};

/// Data for a captured packet
pub const PacketData = struct {
    source_ip: [4]u8,
    dest_ip: [4]u8,
    source_port: u16,
    dest_port: u16,
    protocol: common.Protocol,
    size: usize,
};

/// Data for an alert message
pub const AlertData = struct {
    alert_type: AlertType,
    message: []const u8,
    severity: u8,
};

/// Different types of alerts
pub const AlertType = enum {
    MalformedPacket,
    PortScan,
    SuspiciousTraffic,
};

/// Data for a command message
pub const CommandData = struct {
    command: CommandType,
    parameters: ?[]const u8 = null,
};

/// Types of commands
pub const CommandType = enum {
    StartCapture,
    StopCapture,
    SetFilter,
};

/// Data for a response message
pub const ResponseData = struct {
    success: bool,
    message: ?[]const u8 = null,
};

/// Basic IPC channel - will be expanded in Phase 3
pub const IPCChannel = struct {
    allocator: Allocator,
    
    /// Initialize a new IPC channel
    pub fn init(allocator: Allocator) IPCChannel {
        return IPCChannel{
            .allocator = allocator,
        };
    }
    
    /// Send a message (placeholder for now)
    pub fn sendMessage(self: *IPCChannel, message: Message) !void {
        _ = self;
        // This will be implemented in Phase 3
        std.debug.print("Would send message: {s}\n", .{@tagName(message.message_type)});
    }
    
    /// Receive a message (placeholder for now)
    pub fn receiveMessage(self: *IPCChannel) !?Message {
        _ = self;
        // This will be implemented in Phase 3
        return null;
    }
    
    /// Close the IPC channel
    pub fn deinit(self: *IPCChannel) void {
        _ = self;
        // This will be implemented in Phase 3
    }
};