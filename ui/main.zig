const std = @import("std");
const sdl = @cImport({
    @cInclude("SDL3/SDL.h");
});
const ipc = @import("ipc");
const msg = @import("messages");
const common = @import("common");

const visualizer = @import("visualizer");
const renderer = @import("renderer");
const sprites = @import("sprites");
const ui_state = @import("ui_state");

/// UI Configuration Constants
const WINDOW_WIDTH = 1280;
const WINDOW_HEIGHT = 720;
const WINDOW_TITLE = "Necronet - Slig Security Monitor";
const FPS = 60;
const FRAME_TIME_MS = 1000 / FPS;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY_MS = 500;

/// Oddworld-themed UI elements
const THEME = struct {
    // UI regions
    const REGIONS = struct {
        const SECURITY_MONITOR = "Slig Barracks Monitor";
        const FLOW_ANALYZER = "RuptureFarms Pipeline Monitor";
        const ALERTS_PANEL = "SligSec Alert Station";
    };
    
    // Alert severity levels with Oddworld terminology
    const SEVERITY = struct {
        const INFO = "Mudokon Activity";
        const WARNING = "Suspicious Movement";
        const CRITICAL = "Security Breach!";
    };
    
    // Status messages
    const STATUS = struct {
        const MONITORING = "Security systems operational. Scanning for escapees...";
        const ALERT = "Intruders detected! Dispatching Sligs...";
        const IDLE = "RuptureFarms security - standby mode";
    };
    
    // Background colors
    const COLORS = struct {
        const BACKGROUND = [4]u8{ 20, 20, 30, 255 };  // Dark blue-gray
        const PANEL = [4]u8{ 40, 40, 50, 200 };       // Slightly lighter with transparency
        const ALERT = [4]u8{ 150, 30, 30, 255 };      // Alert red
    };
};

/// Error types specific to the UI
const UIError = error{
    InitializationFailed,
    ConnectionLost,
    AssetLoadingFailed,
    RenderingFailed,
};

/// UI Context with integrated state management
pub const UIContext = struct {
    allocator: std.mem.Allocator,
    ipc_channel: *ipc.IPCChannel,
    window: *sdl.SDL_Window,
    renderer: *sdl.SDL_Renderer,
    visualizer: *visualizer.Visualizer,
    state: ui_state.UIState,
    flows: std.AutoHashMap(u64, visualizer.NetworkFlow),
    alerts: std.ArrayList(visualizer.SligAlert),
    last_update_time: u64,
    last_ipc_check: i64,
    fps_counter: FPSCounter,
    running: bool,
    connection_status: enum {
        Connected,
        Disconnected,
        Reconnecting,
    } = .Connected,
    reconnect_attempts: u32 = 0,
    
    // Performance tracking
    const FPSCounter = struct {
        frames: u32 = 0,
        last_check: u64 = 0,
        current_fps: f32 = 0,
        
        pub fn update(self: *FPSCounter, current_time: u64) void {
            self.frames += 1;
            
            // Update FPS every second
            if (current_time - self.last_check >= 1000) {
                self.current_fps = @as(f32, @floatFromInt(self.frames)) / 
                                  (@as(f32, @floatFromInt(current_time - self.last_check)) / 1000.0);
                self.frames = 0;
                self.last_check = current_time;
            }
        }
    };
    
    /// Display a notification in the UI
    pub fn notify(self: *UIContext, message: []const u8, severity: u8) !void {
        try self.state.showNotification(self.allocator, message, severity);
        std.log.info("{s}", .{message});
    }
    
    /// Attempt to reconnect to the backend
    pub fn attemptReconnect(self: *UIContext) !bool {
        if (self.reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {
            return false;
        }
        
        // Clean up old connection
        self.ipc_channel.deinit();
        
        // Calculate backoff with exponential increase
        const backoff_ms = RECONNECT_DELAY_MS * std.math.pow(u32, 2, self.reconnect_attempts);
        sdl.SDL_Delay(backoff_ms);
        
        // Try to establish a new connection
        const ipc_config = ipc.createDefaultConfig();
        self.ipc_channel = ipc.IPCChannel.init(self.allocator, ipc_config) catch {
            self.reconnect_attempts += 1;
            return false;
        };
        
        // Send a hello message to establish the connection
        const hello_msg = msg.createHelloMsg(
            1, // sequence
            "NecronetUI", 
            1, // version  
            0  // capabilities
        );
        
        self.ipc_channel.sendMessage(&hello_msg) catch {
            self.reconnect_attempts += 1;
            return false;
        };
        
        // Reset reconnect counter on success
        self.reconnect_attempts = 0;
        self.connection_status = .Connected;
        return true;
    }
    
    /// Check IPC connection status periodically
    pub fn checkConnectionStatus(self: *UIContext) !void {
        const current_time = std.time.timestamp();
        
        // Only check every 5 seconds to avoid overhead
        if (current_time - self.last_ipc_check < 5) {
            return;
        }
        
        self.last_ipc_check = current_time;
        
        // If we're already disconnected or reconnecting, don't check
        if (self.connection_status != .Connected) {
            return;
        }
        
        // Send a heartbeat message to check connection
        const heartbeat = msg.createHeartbeatMsg(
            1, // sequence
            @intCast(current_time) // uptime in seconds
        );
        
        self.ipc_channel.sendMessage(&heartbeat) catch |err| {
            if (err == ipc.IPCError.Disconnected) {
                self.connection_status = .Disconnected;
                try self.notify("Connection to Slig Barracks lost! Attempting to reconnect...", 2);
            }
        };
    }
};

// Initialize SDL and create window with error handling
fn initSDL(allocator: std.mem.Allocator) !UIContext {
    // Initialize SDL with proper error handling
    if (!sdl.SDL_Init(sdl.SDL_INIT_VIDEO | sdl.SDL_INIT_AUDIO)) {
        const err_msg = sdl.SDL_GetError();
        std.log.err("Failed to initialize SDL: {s}", .{err_msg});
        return UIError.InitializationFailed;
    }
    errdefer sdl.SDL_Quit();

    // Set hints for better rendering
    _ = sdl.SDL_SetHint("SDL_RENDER_SCALE_QUALITY", "1");

    // Create window
    const window = sdl.SDL_CreateWindow(
        WINDOW_TITLE,
        WINDOW_WIDTH,
        WINDOW_HEIGHT,
        0 | sdl.SDL_WINDOW_RESIZABLE
    ) orelse {
        const err_msg = sdl.SDL_GetError();
        std.log.err("Failed to create window: {s}", .{err_msg});
        return UIError.InitializationFailed;
    };
    errdefer sdl.SDL_DestroyWindow(window);

    // Create renderer
    //const renderer_flags = @as(u32, 1);
    const renderer_context = sdl.SDL_CreateRenderer(window, null) orelse {
        const err_msg = sdl.SDL_GetError();
        std.log.err("Failed to create renderer: {s}", .{err_msg});
        return UIError.InitializationFailed;
    };
    errdefer sdl.SDL_DestroyRenderer(renderer_context);

    _ = sdl.SDL_SetRenderVSync(renderer_context, 1);
    // Set blend mode for transparency
    _ = sdl.SDL_SetRenderDrawBlendMode(renderer_context, sdl.SDL_BLENDMODE_BLEND);

    // Create visualizer
    const viz = visualizer.Visualizer.create(allocator, @ptrCast(renderer_context)) catch {
        std.log.err("Failed to initialize visualizer", .{});
        return UIError.AssetLoadingFailed;
    };
    errdefer viz.destroy();

    // Create IPC channel for communicating with backend
    const ipc_config = ipc.createDefaultConfig();
    const channel = ipc.IPCChannel.init(allocator, ipc_config) catch |err| {
        std.log.err("Failed to initialize IPC: {}", .{err});
        return UIError.ConnectionLost;
    };
    
    // Create UI state
    const state = ui_state.UIState.init(allocator);

    return UIContext{
        .allocator = allocator,
        .ipc_channel = channel,
        .window = window,
        .renderer = renderer_context,
        .visualizer = viz,
        .state = state,
        .flows = std.AutoHashMap(u64, visualizer.NetworkFlow).init(allocator),
        .alerts = std.ArrayList(visualizer.SligAlert).init(allocator),
        .last_update_time = sdl.SDL_GetTicks(),
        .last_ipc_check = std.time.timestamp(),
        .fps_counter = .{},
        .running = true,
    };
}

// Process IPC messages with improved error handling
fn processMessages(ctx: *UIContext) !void {
    // If disconnected, try to reconnect
    if (ctx.connection_status != .Connected) {
        ctx.connection_status = .Reconnecting;
        const reconnected = try ctx.attemptReconnect();
        
        if (!reconnected) {
            // Skip message processing this frame
            return;
        }
        
        try ctx.notify("Reconnected to Slig Barracks!", 0);
    }

    // Process available messages with proper error handling
    var message_count: u32 = 0;
    const MAX_MESSAGES_PER_FRAME = 100; // Prevent processing too many in a single frame
    
    while (message_count < MAX_MESSAGES_PER_FRAME) {
        const message = ctx.ipc_channel.receiveMessage() catch |err| {
            switch (err) {
                ipc.IPCError.Disconnected => {
                    ctx.connection_status = .Disconnected;
                    return;
                },
                ipc.IPCError.ReceiveFailed => {
                    std.log.warn("Failed to receive message, will retry", .{});
                    return;
                },
                else => return err,
            }
        } orelse break; // No more messages to process
        
        message_count += 1;

        switch (message.header.msg_type) {
            .PacketEvent => {
                const packet = message.payload.PacketEvent;
                try ctx.visualizer.addPacket(packet);
            },
            .FlowUpdate => {
                const flow = message.payload.FlowUpdate;
                try ctx.visualizer.updateFlow(flow);
                
                // If this flow has a serious state change, notify
                if (flow.state == .Contaminated or flow.state == .Suspicious) {
                    const flow_str = try std.fmt.allocPrint(
                        ctx.allocator, 
                        "{}.{}.{}.{}:{} → {}.{}.{}.{}:{}", 
                        .{
                            flow.source_ip[0], flow.source_ip[1], 
                            flow.source_ip[2], flow.source_ip[3], 
                            flow.source_port,
                            flow.dest_ip[0], flow.dest_ip[1], 
                            flow.dest_ip[2], flow.dest_ip[3], 
                            flow.dest_port
                        }
                    );
                    defer ctx.allocator.free(flow_str);
                    
                    const msg_text = try std.fmt.allocPrint(
                        ctx.allocator,
                        "Flow {s} is now {s}!",
                        .{ flow_str, @tagName(flow.state) }
                    );
                    defer ctx.allocator.free(msg_text);
                    
                    try ctx.notify(msg_text, 1);
                }
            },
            .SligAlert => {
                const alert = message.payload.SligAlert;
                try ctx.visualizer.addAlert(alert);
                
                // Also notify the user
                try ctx.notify(alert.message, @intFromEnum(alert.severity));
            },
            .Heartbeat => {
                // Update connection status
                if (ctx.connection_status != .Connected) {
                    ctx.connection_status = .Connected;
                }
            },
            .DetectionStats => {
                const stats = message.payload.DetectionStats;
                ctx.state.setDetectionStats(stats);
            },
            else => {}, // Ignore other message types for now
        }
    }
}

// Handle SDL events with improved flow
fn handleEvents(ctx: *UIContext) void {
    var event: sdl.SDL_Event = undefined;
    while (sdl.SDL_PollEvent(&event)) {
        switch (event.type) {
            sdl.SDL_EVENT_QUIT => {
                ctx.running = false;
            },
            sdl.SDL_EVENT_KEY_DOWN => {
                handleKeyPress(ctx, @intCast(event.key.key));
            },
            sdl.SDL_EVENT_MOUSE_BUTTON_DOWN => {
                ctx.visualizer.handleMouseClick(
                    @intFromFloat(event.button.x), 
                    @intFromFloat(event.button.y), 
                    event.button.button == sdl.SDL_BUTTON_LEFT
                );
            },
            sdl.SDL_EVENT_WINDOW_RESIZED => {
                ctx.visualizer.handleResize(event.window.data1, event.window.data2);
            },
            else => {},
        }
        
        // Let the visualizer handle events too
        switch (event.type) {
            sdl.SDL_EVENT_MOUSE_BUTTON_DOWN => {
                ctx.visualizer.handleMouseClick(
                    @intFromFloat(event.button.x),
                    @intFromFloat(event.button.y),
                    event.button.button == sdl.SDL_BUTTON_LEFT
                );
            },
            sdl.SDL_EVENT_WINDOW_RESIZED => {
                ctx.visualizer.handleResize(event.window.data1, event.window.data2);
            },
            else => {}, // Ignore other events
        }
    }
}

// Handle keyboard input separately for clarity
fn handleKeyPress(ctx: *UIContext, key: i32) void {
    switch (key) {
        sdl.SDLK_ESCAPE => {
            ctx.running = false;
        },
        sdl.SDLK_F => {
            // Toggle fullscreen
            const flags = sdl.SDL_GetWindowFlags(ctx.window);
            if (flags & sdl.SDL_WINDOW_FULLSCREEN != 0) {
                _ = sdl.SDL_SetWindowFullscreen(ctx.window, false);
            } else {
                _ = sdl.SDL_SetWindowFullscreen(ctx.window, true);
            }
        },
        sdl.SDLK_V => {
            // Cycle through view modes
            ctx.state.cycleViewMode();
        },
        sdl.SDLK_C => {
            // Clear all alerts
            ctx.alerts.clearRetainingCapacity();
            ctx.visualizer.clearAlerts();
        },
        sdl.SDLK_1, sdl.SDLK_2, sdl.SDLK_3 => {
            // Switch visualization modes
            const mode = key - sdl.SDLK_1; // 0, 1, or 2
            ctx.visualizer.setVisualizationMode(@intCast(mode));
        },
        else => {},
    }
}

// Render UI overlay with stats and status information
fn renderUIOverlay(ctx: *UIContext, _: f32) !void {
    // Get window size for layout calculations
    var width: i32 = 0;
    var height: i32 = 0;
    _ = sdl.SDL_GetWindowSize(ctx.window, &width, &height);
    
    // Render status panel with connection status, FPS, etc.
    try renderStatusPanel(ctx, 10, 10, 200, 80);
    
    // Render notification if active
    if (ctx.state.notification) |notification| {
        const severity_color = switch (notification.severity) {
            0 => [4]u8{ 100, 200, 100, 255 },  // Info - green
            1 => [4]u8{ 200, 200, 50, 255 },   // Warning - yellow
            else => [4]u8{ 200, 50, 50, 255 }, // Critical - red
        };
        
        try renderNotification(
            ctx, 
            notification.message, 
            @intCast(@divTrunc(width, 2) - 150), 
            height - 60, 
            300, 
            50, 
            severity_color
        );
    }
}

// Render a status panel with current stats
fn renderStatusPanel(ctx: *UIContext, x: i32, y: i32, width: i32, height: i32) !void {
    // Draw panel background
    const panel_rect = sdl.SDL_FRect{
        .x = @floatFromInt(x),
        .y = @floatFromInt(y),
        .w = @floatFromInt(width),
        .h = @floatFromInt(height),
    };
    
    _ = sdl.SDL_SetRenderDrawColor(
        ctx.renderer, 
        THEME.COLORS.PANEL[0], 
        THEME.COLORS.PANEL[1], 
        THEME.COLORS.PANEL[2], 
        THEME.COLORS.PANEL[3]
    );
    _ = sdl.SDL_RenderFillRect(ctx.renderer, &panel_rect);
    
    // Draw status information
    // Note: In a real implementation you'd use proper text rendering with SDL_ttf
    // But for now we'll just say it's placeholder
    
    // Draw connection status indicator
    const status_color = switch (ctx.connection_status) {
        .Connected => [4]u8{ 50, 200, 50, 255 },     // Green
        .Disconnected => [4]u8{ 200, 50, 50, 255 },  // Red
        .Reconnecting => [4]u8{ 200, 200, 50, 255 }, // Yellow
    };
    
    const indicator_rect = sdl.SDL_FRect{
        .x = @floatFromInt(x + 10),
        .y = @floatFromInt(y + 10),
        .w = 10,
        .h = 10,
    };
    
    _ = sdl.SDL_SetRenderDrawColor(
        ctx.renderer, 
        status_color[0], 
        status_color[1], 
        status_color[2], 
        status_color[3]
    );
    _ = sdl.SDL_RenderFillRect(ctx.renderer, &indicator_rect);
}

// Render a notification message
fn renderNotification(
    ctx: *UIContext, 
    message: []const u8, 
    x: i32, 
    y: i32, 
    width: i32, 
    height: i32,
    color: [4]u8
) !void {
    const notification_rect = sdl.SDL_FRect{
        .x = @floatFromInt(x),
        .y = @floatFromInt(y),
        .w = @floatFromInt(width),
        .h = @floatFromInt(height),
    };
    
    _ = sdl.SDL_SetRenderDrawColor(ctx.renderer, color[0], color[1], color[2], 180);
    _ = sdl.SDL_RenderFillRect(ctx.renderer, &notification_rect);
    
    // In a real implementation, render text here with SDL_ttf
    _ = message;
}

// Main UI loop with improved structure and error handling
pub fn run(allocator: std.mem.Allocator) !void {
    var ctx = try initSDL(allocator);
    defer {
        // Cleanup in reverse order of creation
        std.log.info("Shutting down UI...", .{});
        
        ctx.alerts.deinit();
        ctx.flows.deinit();
        ctx.state.deinit(allocator);
        ctx.visualizer.destroy();
        ctx.ipc_channel.deinit();
        sdl.SDL_DestroyRenderer(ctx.renderer);
        sdl.SDL_DestroyWindow(ctx.window);
        sdl.SDL_Quit();
    }

    std.log.info("Necronet UI started - Oddworld Network Monitor", .{});
    try ctx.notify("Slig Security Monitor activated! Watching for intruders...", 0);

    // Main loop with proper frame timing
    while (ctx.running) {
        const frame_start = sdl.SDL_GetTicks();
        
        // Check IPC connection periodically
        try ctx.checkConnectionStatus();
        
        // Process IPC messages from backend
        processMessages(&ctx) catch |err| {
            std.log.err("Error processing messages: {}", .{err});
            // Continue running despite errors
        };
        
        // Handle SDL events
        handleEvents(&ctx);
        
        // Calculate delta time
        const current_time = sdl.SDL_GetTicks();
        const delta_ms = current_time - ctx.last_update_time;
        ctx.last_update_time = current_time;
        const delta_sec = @as(f32, @floatFromInt(delta_ms)) / 1000.0;
        
        // Update state
        ctx.state.update(delta_sec);
        
        // Update visualization
        ctx.visualizer.update(delta_sec) catch |err| {
            std.log.err("Error updating visualizer: {}", .{err});
        };
        
        // Render frame
        _ = sdl.SDL_SetRenderDrawColor(
            ctx.renderer, 
            THEME.COLORS.BACKGROUND[0], 
            THEME.COLORS.BACKGROUND[1], 
            THEME.COLORS.BACKGROUND[2], 
            THEME.COLORS.BACKGROUND[3]
        );
        _ = sdl.SDL_RenderClear(ctx.renderer);
        
        // Render visualization
        ctx.visualizer.render() catch |err| {
            std.log.err("Error rendering visualization: {}", .{err});
        };
        
        // Render UI overlays
        renderUIOverlay(&ctx, delta_sec) catch |err| {
            std.log.err("Error rendering UI overlay: {}", .{err});
        };
        
        // Present final frame
        _ = sdl.SDL_RenderPresent(ctx.renderer);
        
        // Update FPS counter
        ctx.fps_counter.update(current_time);
        
        // Cap framerate
        const frame_time = sdl.SDL_GetTicks() - frame_start;
        if (frame_time < FRAME_TIME_MS) {
            sdl.SDL_Delay(@intCast(FRAME_TIME_MS - frame_time));
        }
    }
}

// Entry point for the UI module
pub fn main() !void {
    std.log.info("Initializing Necronet UI...", .{});
    
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const leaked = gpa.deinit();
        if (leaked) {
            std.log.err("Memory leak detected!", .{});
        }
    }
    
    const allocator = gpa.allocator();
    try run(allocator);
    
    std.log.info("Necronet UI shutdown complete", .{});
}