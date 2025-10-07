const std = @import("std");
const ipc = @import("../ipc/ipc.zig");
const msg = @import("../ipc/messages.zig");
const Allocator = std.mem.Allocator;

pub const ScanRequest = struct {
    request_id: []const u8,
    target_ip: [4]u8,
    ports: []const u16,
    reason: []const u8,
    severity: []const u8,
    attack_type: []const u8,
    payload_sample: ?[]const u8,
    scan_options: ScanOptions,
};

pub const ScanOptions = struct {
    depth: []const u8 = "standard", // quick|standard|full
    timeout: u32 = 300,
    priority: []const u8 = "high",
    scan_types: []const []const u8 = &[_][]const u8{ "port", "service", "vuln" },
};

/// Scan result structure from Shrykull
pub const ScanResult = struct {
    response_id: []const u8,
    status: []const u8,
    target: []const u8,
    scan_duration: f64,
    findings: []const Finding,
    summary: ScanSummary,
    
    pub fn deinit(self: *ScanResult, allocator: Allocator) void {
        allocator.free(self.response_id);
        allocator.free(self.status);
        allocator.free(self.target);
        
        for (self.findings) |*finding| {
            allocator.free(finding.finding_type);
            allocator.free(finding.severity);
            allocator.free(finding.service);
            allocator.free(finding.oddworld_theme);
            allocator.free(finding.details);
            for (finding.cve_matches) |cve| {
                allocator.free(cve);
            }
            allocator.free(finding.cve_matches);
            allocator.free(finding.remediation);
        }
        allocator.free(self.findings);
    }
};

pub const Finding = struct {
    finding_type: []const u8,
    severity: []const u8,
    port: u16,
    service: []const u8,
    oddworld_theme: []const u8,
    details: []const u8,
    cve_matches: []const []const u8,
    exploit_available: bool = false,
    remediation: []const u8,
};

pub const ScanSummary = struct {
    total_ports_scanned: u32,
    open_ports: u32,
    vulnerabilities_found: u32,
    risk_score: f64,
};

/// Manages the Shrykull scanner process and IPC communication
pub const ShrykullManager = struct {
    allocator: Allocator,
    process: ?std.process.Child = null,
    ipc_channel: ?*ipc.IPCChannel = null,
    shrykull_path: []const u8,
    is_running: bool = false,
    
    pub fn init(allocator: Allocator, shrykull_path: []const u8) !*ShrykullManager {
        const manager = try allocator.create(ShrykullManager);
        manager.* = .{
            .allocator = allocator,
            .shrykull_path = try allocator.dupe(u8, shrykull_path),
        };
        return manager;
    }
    
    /// Start the Shrykull scanner process
    pub fn start(self: *ShrykullManager) !void {
        if (self.is_running) return;
        
        // Spawn Shrykull as child process
        var process = std.process.Child.init(
            &[_][]const u8{self.shrykull_path},
            self.allocator
        );
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;
        process.stderr_behavior = .Inherit;
        
        try process.spawn();
        self.process = process;
        
        // Initialize IPC channel using stdio
        const ipc_config = ipc.IPCConfig{
            .channel_type = .StdIO,
            .serialization = .Json,
            .buffer_size = 1024 * 1024, // 1MB for scan results
        };
        
        self.ipc_channel = try ipc.IPCChannel.init(self.allocator, ipc_config);
        self.is_running = true;
        
        std.log.info("Shrykull scanner started successfully", .{});
    }
    
    /// Send a scan request to Shrykull
    pub fn requestScan(self: *ShrykullManager, request: ScanRequest) !void {
        if (!self.is_running or self.ipc_channel == null) {
            return error.ShrykullNotRunning;
        }
        
        // Generate unique request ID
        var uuid_buf: [36]u8 = undefined;
        const request_id = try std.fmt.bufPrint(&uuid_buf, "scan-{d}", .{std.time.milliTimestamp()});
        
        // Build JSON message
        var json_buf = std.ArrayList(u8).init(self.allocator);
        defer json_buf.deinit();
        
        const writer = json_buf.writer();
        try writer.writeAll("{");
        try writer.print("\"command\":\"scan\",", .{});
        try writer.print("\"request_id\":\"{s}\",", .{request_id});
        try writer.writeAll("\"target\":{");
        try writer.print("\"ip\":\"{d}.{d}.{d}.{d}\",", .{
            request.target_ip[0], request.target_ip[1],
            request.target_ip[2], request.target_ip[3]
        });
        try writer.writeAll("\"ports\":[");
        for (request.ports, 0..) |port, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("{d}", .{port});
        }
        try writer.writeAll("],");
        try writer.print("\"reason\":\"{s}\",", .{request.reason});
        try writer.print("\"severity\":\"{s}\",", .{request.severity});
        try writer.writeAll("\"context\":{");
        try writer.print("\"attack_type\":\"{s}\"", .{request.attack_type});
        if (request.payload_sample) |payload| {
            try writer.print(",\"payload_sample\":\"{s}\"", .{payload});
        }
        try writer.writeAll("}},");
        try writer.writeAll("\"scan_options\":{");
        try writer.print("\"depth\":\"{s}\",", .{request.scan_options.depth});
        try writer.print("\"timeout\":{d},", .{request.scan_options.timeout});
        try writer.print("\"priority\":\"{s}\",", .{request.scan_options.priority});
        try writer.writeAll("\"scan_types\":[");
        for (request.scan_options.scan_types, 0..) |scan_type, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{scan_type});
        }
        try writer.writeAll("]}}");
        
        // Create IPC message
        const payload = msg.Payload{
            .json = msg.JsonPayload{ .data = try json_buf.toOwnedSlice() },
        };
        
        const message = msg.Message{
            .header = .{
                .version = 1,
                .sequence = self.ipc_channel.?.next_sequence,
                .timestamp = std.time.microTimestamp(),
                .msg_type = .ScanRequest,
                .payload_size = @intCast(payload.json.data.len),
            },
            .payload = payload,
        };
        
        try self.ipc_channel.?.sendMessage(&message);
        
        std.log.info("Scan request sent for {d}.{d}.{d}.{d}", .{
            request.target_ip[0], request.target_ip[1],
            request.target_ip[2], request.target_ip[3]
        });
    }
    
    /// Receive scan result from Shrykull (non-blocking)
    pub fn receiveScanResult(self: *ShrykullManager) !?ScanResult {
        if (!self.is_running or self.ipc_channel == null) {
            return error.ShrykullNotRunning;
        }
        
        const message = try self.ipc_channel.?.receiveMessage();
        if (message == null) return null;
        
        const msg_data = message.?;
        if (msg_data.header.msg_type != .ScanResult) {
            std.log.warn("Unexpected message type: {}", .{msg_data.header.msg_type});
            return null;
        }
        
        // Parse JSON result
        const json_data = msg_data.payload.json.data;
        const parsed = try std.json.parseFromSlice(
            ScanResult,
            self.allocator,
            json_data,
            .{ .allocate = .alloc_always }
        );
        
        return parsed.value;
    }
    
    /// Check if Shrykull is still running
    pub fn isHealthy(self: *ShrykullManager) bool {
        if (!self.is_running or self.process == null) return false;
        
        // Try to get process status
        const term = self.process.?.kill() catch return false;
        _ = term;
        return true;
    }
    
    /// Stop the Shrykull process
    pub fn stop(self: *ShrykullManager) void {
        if (!self.is_running) return;
        
        // Send shutdown command
        if (self.ipc_channel) |channel| {
            const shutdown_msg = msg.Message{
                .header = .{
                    .version = 1,
                    .sequence = channel.next_sequence,
                    .timestamp = std.time.microTimestamp(),
                    .msg_type = .Control,
                    .payload_size = 8,
                },
                .payload = .{ .json = .{ .data = "shutdown" } },
            };
            channel.sendMessage(&shutdown_msg) catch {};
        }
        
        // Terminate process
        if (self.process) |*proc| {
            _ = proc.kill() catch {};
            _ = proc.wait() catch {};
        }
        
        self.is_running = false;
        std.log.info("Shrykull scanner stopped", .{});
    }
    
    pub fn deinit(self: *ShrykullManager) void {
        self.stop();
        
        if (self.ipc_channel) |channel| {
            channel.deinit();
        }
        
        self.allocator.free(self.shrykull_path);
        self.allocator.destroy(self);
    }
};