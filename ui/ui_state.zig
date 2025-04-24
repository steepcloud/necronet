const std = @import("std");
const ipc = @import("ipc");
const msg = @import("messages");

/// UI State Manager
pub const UIState = struct {
    // Current view mode
    view_mode: enum {
        Overview,
        FlowDetail,
        AlertsOnly,
    } = .Overview,
    
    // Currently selected flow for detailed view
    selected_flow_id: ?u64 = null,
    
    // UI notification state
    notification: ?struct {
        message: []const u8,
        expire_time: i64,
        severity: u8,
    } = null,
    
    // Display filters
    show_tcp: bool = true,
    show_udp: bool = true,
    show_icmp: bool = true,
    show_other: bool = false,
    
    // Performance metrics
    fps: f32 = 0.0,
    frame_time: f32 = 0.0,
    backend_latency: f32 = 0.0,
    
    // Detection statistics from backend
    detection_stats: ?msg.DetectionStats = null,
    
    // UI animation state
    animation_time: f32 = 0.0,
    
    /// Initialize a new UI state
    pub fn init(allocator: std.mem.Allocator) UIState {
        _ = allocator; // Not used in initialization, but kept for consistency
        return UIState{};
    }
    
    /// Show a notification in the UI
    pub fn showNotification(self: *UIState, allocator: std.mem.Allocator, message: []const u8, severity: u8) !void {
        if (self.notification != null and self.notification.?.message.len > 0) {
            allocator.free(self.notification.?.message);
        }
        
        self.notification = .{
            .message = try allocator.dupe(u8, message),
            .expire_time = std.time.timestamp() + 5, // 5 seconds
            .severity = severity,
        };
    }
    
    /// Update state based on time
    pub fn update(self: *UIState, delta_sec: f32) void {
        // Update animation time
        self.animation_time += delta_sec;
        
        // Check if notification expired
        if (self.notification != null) {
            if (std.time.timestamp() > self.notification.?.expire_time) {
                self.notification = null;
            }
        }
    }
    
    /// Update detection stats from backend
    pub fn setDetectionStats(self: *UIState, stats: msg.DetectionStats) void {
        self.detection_stats = stats;
    }
    
    /// Cycle through different view modes
    pub fn cycleViewMode(self: *UIState) void {
        self.view_mode = switch (self.view_mode) {
            .Overview => .FlowDetail,
            .FlowDetail => .AlertsOnly,
            .AlertsOnly => .Overview,
        };
    }
    
    /// Select a specific flow for detailed view
    pub fn selectFlow(self: *UIState, flow_id: u64) void {
        self.selected_flow_id = flow_id;
        self.view_mode = .FlowDetail;
    }
    
    /// Clean up resources
    pub fn deinit(self: *UIState, allocator: std.mem.Allocator) void {
        if (self.notification != null and self.notification.?.message.len > 0) {
            allocator.free(self.notification.?.message);
            self.notification = null;
        }
    }
};