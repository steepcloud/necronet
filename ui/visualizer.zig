const std = @import("std");
const sdl = @cImport({
    @cInclude("SDL3/SDL.h");
});
const msg = @import("messages");
const common = @import("common");
const rend = @import("renderer");

// Visual representation of a network flow
pub const NetworkFlow = struct {
    flow_id: u64,
    source_ip: [4]u8,
    dest_ip: [4]u8,
    source_port: u16,
    dest_port: u16,
    protocol: common.Protocol,
    state: msg.FlowUpdate.FlowState,
    
    // Visual properties
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    color: [4]u8, // RGBA
    
    // Packets in flight
    packets: std.ArrayList(VisualPacket),
    
    // Activity metrics
    packet_rate: f32, 
    byte_rate: f32,
    active_time: f64,
    last_update: i64,
};

// Visual representation of a packet
pub const VisualPacket = struct {
    protocol: common.Protocol,
    position: f32,  // Position along the flow pipe (0.0 to 1.0)
    size: f32,      // Visual size based on packet size
    color: [4]u8,   // RGBA color
    speed: f32,     // Movement speed
    is_malicious: bool,
};

// Visual representation of an alert
pub const SligAlert = struct {
    alert_id: u64,
    flow_id: u64,
    severity: u8,
    category: []const u8,
    message: []const u8,
    
    // Visual properties
    x: f32,
    y: f32,
    scale: f32,
    animated: bool,
    creation_time: i64,
    frame: u8,
};

pub const Visualizer = struct {
    allocator: std.mem.Allocator,
    renderer: rend.Renderer,
    flows: std.AutoHashMap(u64, NetworkFlow),
    alerts: std.ArrayList(SligAlert),
    
    // Asset references (will be expanded later)
    pipe_texture: ?*sdl.SDL_Texture,
    packet_textures: [4]?*sdl.SDL_Texture,
    slig_textures: [3]?*sdl.SDL_Texture,
    view_mode: ViewMode,
    
    // Layout parameters
    layout_columns: u32,
    pipe_spacing: f32,
    pipe_length: f32,

    visualization_mode: u8,
    animation_time: f32,

    pub const ViewMode = enum {
        Overview,
        FlowDetail,
        AlertsOnly,
    };
    
    // Create a new visualizer
    pub fn create(allocator: std.mem.Allocator, sdl_renderer: *sdl.SDL_Renderer) !*Visualizer {
        var viz = try allocator.create(Visualizer);
        viz.* = Visualizer{
            .allocator = allocator,
            .renderer = try rend.Renderer.init(allocator, sdl_renderer),
            .flows = std.AutoHashMap(u64, NetworkFlow).init(allocator),
            .alerts = std.ArrayList(SligAlert).init(allocator),
            .pipe_texture = null,
            .packet_textures = [_]?*sdl.SDL_Texture{null} ** 4,
            .slig_textures = [_]?*sdl.SDL_Texture{null} ** 3,
            .view_mode = .Overview,
            .layout_columns = 4,
            .pipe_spacing = 20,
            .pipe_length = 200,
            .visualization_mode = 0,
            .animation_time = 0,
        };
        
        try viz.loadAssets();
        
        return viz;
    }
    
    // Load textures and assets (with fallback to colored rectangles)
    fn loadAssets(self: *Visualizer) !void {
        // Try to load textures, but don't fail if they're missing
        self.pipe_texture = loadTexture(self.renderer, "assets/pipes/pipe_normal.png") catch |err| {
            std.log.warn("Could not load pipe texture: {}, using fallback", .{err});
            return; // Continue without textures
        };
        
        // Load packet textures for different protocols
        self.packet_textures[0] = loadTexture(self.renderer, "assets/pipes/packet_tcp.png") catch null;
        self.packet_textures[1] = loadTexture(self.renderer, "assets/pipes/packet_udp.png") catch null;
        self.packet_textures[2] = loadTexture(self.renderer, "assets/pipes/packet_icmp.png") catch null;
        self.packet_textures[3] = loadTexture(self.renderer, "assets/pipes/packet_other.png") catch null;
        
        
        // Load slig textures for alerts
        self.slig_textures[0] = loadTexture(self.renderer, "assets/threats/slig_normal.png") catch null;
        self.slig_textures[1] = loadTexture(self.renderer, "assets/threats/slig_alert.png") catch null;
        self.slig_textures[2] = loadTexture(self.renderer, "assets/threats/slig_critical.png") catch null;
    }
    
    // Helper to load a texture
    fn loadTexture(renderer: rend.Renderer, path: [*:0]const u8) !*sdl.SDL_Texture {
        return renderer.loadTexture(path) catch |err| {
            std.log.err("Failed to load texture {s}: {}", .{path, err});
            return error.ImageLoadFailed;
        };
    }
    
    // Add a new packet to visualize
    pub fn addPacket(self: *Visualizer, packet: msg.PacketEvent) !void {
        var flow = self.flows.get(packet.flow_id) orelse {
            // Create a new flow if we haven't seen this ID before
            const new_flow = try self.createFlow(packet);
            try self.flows.put(packet.flow_id, new_flow);
            return;
        };
        
        // Create packet visualization
        const visual_packet = VisualPacket{
            .protocol = packet.protocol,
            .position = 0.0,
            .size = @min(10.0, @as(f32, @floatFromInt(packet.packet_size)) / 200.0),
            .color = protocolToColor(packet.protocol),
            .speed = 0.2 + std.crypto.random.float(f32) * 0.1,
            .is_malicious = false,
        };
        
        try flow.packets.append(visual_packet);
    }
    
    // Create a new flow visualization
    fn createFlow(self: *Visualizer, packet: msg.PacketEvent) !NetworkFlow {
        const flow_count = self.flows.count();
        const column = flow_count % self.layout_columns;
        const row = flow_count / self.layout_columns;
        
        const x = 100.0 + @as(f32, @floatFromInt(column)) * (self.pipe_length + self.pipe_spacing);
        const y = 100.0 + @as(f32, @floatFromInt(row)) * (50.0 + self.pipe_spacing);
        
        return NetworkFlow{
            .flow_id = packet.flow_id,
            .source_ip = packet.source_ip,
            .dest_ip = packet.dest_ip,
            .source_port = packet.source_port,
            .dest_port = packet.dest_port,
            .protocol = packet.protocol,
            .state = .Unknown,
            
            .x = x,
            .y = y,
            .width = self.pipe_length,
            .height = 30.0,
            .color = [_]u8{ 100, 100, 100, 255 },
            
            .packets = std.ArrayList(VisualPacket).init(self.allocator),
            
            .packet_rate = 0.0,
            .byte_rate = 0.0,
            .active_time = 0.0,
            .last_update = std.time.timestamp(),
        };
    }
    
    // Update a flow's status
    pub fn updateFlow(self: *Visualizer, flow: msg.FlowUpdate) !void {
        var existing = self.flows.getPtr(flow.flow_id) orelse {
            // Create placeholder flow if we haven't seen it yet
            const placeholder = try self.createPlaceholderFlow(flow);
            try self.flows.put(flow.flow_id, placeholder);
            return;
        };
        
        // Update flow properties
        existing.state = flow.state;
        existing.packet_rate = flow.packets_per_sec;
        existing.byte_rate = flow.bytes_per_sec;
        existing.last_update = flow.last_update;
        
        // Update colors based on state
        existing.color = flowStateToColor(flow.state);
    }
    
    // Add a new alert
    pub fn addAlert(self: *Visualizer, alert: msg.SligAlert) !void {
        // Find the associated flow
        const flow = self.flows.get(alert.flow_id) orelse return;
        
        // Create a new visual alert
        const slig_alert = SligAlert{
            .alert_id = alert.alert_id,
            .flow_id = alert.flow_id,
            .severity = @intFromEnum(alert.severity),
            .category = try self.allocator.dupe(u8, alert.category),
            .message = try self.allocator.dupe(u8, alert.message),
            
            .x = flow.x + flow.width,
            .y = flow.y - 20.0,
            .scale = 1.0 + @as(f32, @floatFromInt(@intFromEnum(alert.severity))) * 0.25,
            .animated = true,
            .creation_time = std.time.timestamp(),
            .frame = 0,
        };
        
        try self.alerts.append(slig_alert);
        
        // Mark the flow as contaminated
        if (self.flows.getPtr(alert.flow_id)) |flow_ptr| {
            flow_ptr.state = .Contaminated;
            flow_ptr.color = flowStateToColor(.Contaminated);
        }
    }
    
    // Update visualization state
    pub fn update(self: *Visualizer, delta_sec: f32) !void {
        var flow_it = self.flows.valueIterator();
        while (flow_it.next()) |flow| {
            // Update packets in this flow
            var i: usize = 0;
            while (i < flow.packets.items.len) {
                var packet = &flow.packets.items[i];
                
                // Move packet along the pipe
                packet.position += packet.speed * delta_sec;
                
                // Remove packets that have reached the end
                if (packet.position >= 1.0) {
                    _ = flow.packets.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }
        
        // Update alerts (animation, etc)
        var i: usize = 0;
        while (i < self.alerts.items.len) {
            var alert = &self.alerts.items[i];
            
            // Animate frame
            if (alert.animated) {
                alert.frame = @intCast(@mod(std.time.timestamp() - alert.creation_time, 4));
            }
            
            // Remove alerts after 10 seconds
            if (std.time.timestamp() - alert.creation_time > 10) {
                const removed = self.alerts.swapRemove(i);
                self.allocator.free(removed.category);
                self.allocator.free(removed.message);
            } else {
                i += 1;
            }
        }
    }
    
    // Render the visualization
    pub fn render(self: *Visualizer) !void {
        // Render flows (pipes)
        var flow_it = self.flows.valueIterator();
        while (flow_it.next()) |flow| {
            try self.renderFlow(flow);

            // render packets in this flow
            for (flow.packets.items) |*packet| {
                try self.renderPacket(flow, packet);
            }
        }
        
        // Render alerts (Sligs)
        for (self.alerts.items) |alert| {
            try self.renderAlert(&alert);
        }

        // optional: drawing debug info
        //if (self.visualization_mode == 1) {
        //    try self.drawDebugInfo();
        //}
    }
    
    // Handle SDL events
    pub fn handleEvent(self: *Visualizer, event: *const sdl.SDL_Event) void {
        // Handle mouse interactions, etc.
        _ = self;
        _ = event;
    }
    
    // Cleanup resources
    pub fn destroy(self: *Visualizer) void {
        // Free flows and contained packets
        var flow_it = self.flows.valueIterator();
        while (flow_it.next()) |flow| {
            flow.packets.deinit();
        }
        self.flows.deinit();
        
        // Free alerts
        for (self.alerts.items) |alert| {
            self.allocator.free(alert.category);
            self.allocator.free(alert.message);
        }
        self.alerts.deinit();
        
        // Free textures
        if (self.pipe_texture) |texture| {
            sdl.SDL_DestroyTexture(texture);
        }
        
        for (self.packet_textures) |texture| {
            if (texture) |tex| {
                sdl.SDL_DestroyTexture(tex);
            }
        }
        
        for (self.slig_textures) |texture| {
            if (texture) |tex| {
                sdl.SDL_DestroyTexture(tex);
            }
        }
        
        self.allocator.destroy(self);
    }
    
    // Helper to render a flow
    fn renderFlow(self: *Visualizer, flow: *const NetworkFlow) !void {
        const rect = rend.Rect{
            .x = flow.x,
            .y = flow.y,
            .w = flow.width,
            .h = flow.height,
        };

        if (self.pipe_texture) |texture| {
            // rendering using texture if available
            const src_rect = sdl.SDL_FRect {
                .x = 0.0,
                .y = 0.0,
                .w = 100.0,
                .h = 30.0,
            };

                    
            // Set pipe color based on flow state
            const color = rend.Color{
                .r = flow.color[0],
                .g = flow.color[1],
                .b = flow.color[2],
                .a = flow.color[3],
            };
            
            try self.renderer.drawColoredTexture(texture, src_rect, rect.toSDLRect(), color);
        } else {
            // fallback: just draw a colored rectangle
            try self.renderer.fillRect(rect, rend.Color{
                .r = flow.color[0],
                .g = flow.color[1],
                .b = flow.color[2],
                .a = flow.color[3],
            });
        }
    }
    
    fn renderPacket(self: *Visualizer, flow: *const NetworkFlow, packet: *const VisualPacket) !void {
        const size = @max(10.0, packet.size * 20.0);
        const x = flow.x + flow.width * packet.position - size / 2.0;
        const y = flow.y + flow.height / 2.0 - size / 2.0;
        
        const packet_rect = rend.Rect{
            .x = x,
            .y = y,
            .w = size,
            .h = size,
        };
        
        const texture_index = @min(3, @intFromEnum(packet.protocol));
        
        if (self.packet_textures[texture_index]) |texture| {
            // Render using texture if available
            const src_rect = sdl.SDL_FRect{
                .x = 0.0,
                .y = 0.0,
                .w = 32.0,
                .h = 32.0,
            };
            
            const color = rend.Color{
                .r = packet.color[0],
                .g = packet.color[1],
                .b = packet.color[2],
                .a = 255,
            };
            
            try self.renderer.drawColoredTexture(texture, src_rect, packet_rect.toSDLRect(), color);
        } else {
            // Fallback: draw a circle or rectangle
            const color = rend.Color{
                .r = packet.color[0],
                .g = packet.color[1],
                .b = packet.color[2],
                .a = 255,
            };

            // using either a circle or rectangle
            if (packet.is_malicious) {
                // using a circle for malicious packets to make them stand out
                try self.renderer.fillCircle(
                    x + size / 2.0,
                    y + size / 2.0,
                    size / 2.0,
                    color
                );
            } else {
                try self.renderer.fillRect(packet_rect, color);
            }
        }
    }

    fn renderAlert(self: *Visualizer, alert: *const SligAlert) !void {
        const size = 64.0 * alert.scale;
        const alert_rect = rend.Rect{
            .x = alert.x,
            .y = alert.y,
            .w = size,
            .h = size,
        };
        
        const texture_index = @min(2, alert.severity);
        
        if (self.slig_textures[texture_index]) |texture| {
            // Render using texture if available
            const src_rect = sdl.SDL_FRect{
                .x = @as(f32, @floatFromInt(alert.frame)) * 64.0,
                .y = 0.0,
                .w = 64.0,
                .h = 64.0,
            };
            
            try self.renderer.drawTexture(texture, src_rect, alert_rect.toSDLRect());
        } else {
            // Fallback: draw a distinctive shape for alerts
            const severity_color = switch (alert.severity) {
                0 => rend.Color{ .r = 100, .g = 200, .b = 100, .a = 255 }, // Green for low
                1 => rend.Color{ .r = 255, .g = 200, .b = 0, .a = 255 },   // Yellow for medium
                else => rend.Color{ .r = 255, .g = 0, .b = 0, .a = 255 },  // Red for high
            };

            // diamond shape for alerts
            if (alert.severity > 1) {
                // for severe alerts, filled circle
                try self.renderer.fillCircle(
                    alert.x + size / 2.0,
                    alert.y + size / 2.0,
                    size / 2.0,
                    severity_color
                );
            } else {
                // for less severe alerts, rounded rectangle
                try self.renderer.fillRoundedRect(alert_rect, 8.0, severity_color);
            }
        }
    }
    
    // Helper to render text (placeholder - would use SDL_ttf in full implementation)
    fn renderText(self: *Visualizer, x: f32, y: f32, text: []const u8) void {
        _ = self;
        _ = x;
        _ = y;
        _ = text;
        // In real implementation, would use SDL_ttf to render text
    }
    
    // Helper to create a placeholder flow for a FlowUpdate without a preceding packet
    fn createPlaceholderFlow(self: *Visualizer, flow: msg.FlowUpdate) !NetworkFlow {
        const flow_count = self.flows.count();
        const column = flow_count % self.layout_columns;
        const row = flow_count / self.layout_columns;
        
        const x = 100.0 + @as(f32, @floatFromInt(column)) * (self.pipe_length + self.pipe_spacing);
        const y = 100.0 + @as(f32, @floatFromInt(row)) * (50.0 + self.pipe_spacing);
        
        return NetworkFlow{
            .flow_id = flow.flow_id,
            .source_ip = flow.source_ip,
            .dest_ip = flow.dest_ip,
            .source_port = flow.source_port,
            .dest_port = flow.dest_port,
            .protocol = flow.protocol,
            .state = flow.state,
            
            .x = x,
            .y = y,
            .width = self.pipe_length,
            .height = 30.0,
            .color = flowStateToColor(flow.state),
            
            .packets = std.ArrayList(VisualPacket).init(self.allocator),
            
            .packet_rate = flow.packets_per_sec,
            .byte_rate = flow.bytes_per_sec,
            .active_time = @as(f64, @floatFromInt(flow.active_time_ms)) / 1000.0,
            .last_update = flow.last_update,
        };
    }

    pub fn clearAlerts(self: *Visualizer) void {
        // Free memory for alert strings
        for (self.alerts.items) |alert| {
            self.allocator.free(alert.category);
            self.allocator.free(alert.message);
        }
        
        // Clear the list
        self.alerts.clearRetainingCapacity();
    }

    pub fn handleMouseClick(self: *Visualizer, x: i32, y: i32, is_left_click: bool) void {
        // Find if we clicked on any flow or alert
        _ = self;
        _ = x;
        _ = y;
        _ = is_left_click;
        // Will implement interaction logic later
    }

    pub fn handleResize(self: *Visualizer, width: i32, height: i32) void {
        _ = self;
        _ = width;
        _ = height;
        // Will adjust layout based on new dimensions later
    }

    pub fn setVisualizationMode(self: *Visualizer, mode: u8) void {
        _ = self;
        _ = mode;
        // Will switch between different visualization styles later
    }
};

// Helper to convert a protocol to a color
fn protocolToColor(protocol: common.Protocol) [4]u8 {
    return switch (protocol) {
        .TCP => [_]u8{ 0, 150, 255, 255 },    // Blue
        .UDP => [_]u8{ 0, 255, 150, 255 },    // Green
        .ICMP => [_]u8{ 255, 150, 0, 255 },   // Orange
        .HTTP => [_]u8{ 150, 0, 255, 255 },   // Purple
        .DNS => [_]u8{ 255, 255, 0, 255 },    // Yellow
        .Unknown => [_]u8{ 150, 150, 150, 255 }, // Gray
    };
}

// Helper to convert flow state to color
fn flowStateToColor(state: msg.FlowUpdate.FlowState) [4]u8 {
    return switch (state) {
        .Unknown => [_]u8{ 150, 150, 150, 255 },  // Gray
        .Established => [_]u8{ 100, 200, 100, 255 }, // Green
        .Terminated => [_]u8{ 100, 100, 100, 255 },  // Dark Gray
        .Blocked => [_]u8{ 200, 100, 100, 255 },     // Red
        .Suspicious => [_]u8{ 255, 200, 0, 255 },    // Yellow
        .Contaminated => [_]u8{ 255, 0, 0, 255 },    // Bright Red
    };
}

// Helper to format IP:port
fn formatIpPort(ip: [4]u8, port: u16) []const u8 {
    // In a real implementation, would format properly
    _ = ip;
    _ = port;
    return "IP:Port";
}
