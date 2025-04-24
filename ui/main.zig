const std = @import("std");
const sdl = @cImport({
    @cInclude("SDL3/SDL.h");
});
const ipc = @import("ipc");
const msg = @import("messages");
const common = @import("common");

const visualizer = @import("visualizer.zig");
const renderer = @import("renderer.zig");
const sprites = @import("sprites.zig");
const ui_state = @import("ui_state.zig");

// Configuration
const WINDOW_WIDTH = 1280;
const WINDOW_HEIGHT = 720;
const WINDOW_TITLE = "Necronet - Oddworld Network Monitor";
const FPS = 60;
const FRAME_TIME_MS = 1000 / FPS;

// UI State
pub const UIContext = struct {
    allocator: std.mem.Allocator,
    ipc_channel: *ipc.IPCChannel,
    window: *sdl.SDL_Window,
    renderer: *sdl.SDL_Renderer,
    visualizer: *visualizer.Visualizer,
    flows: std.ArrayList(visualizer.NetworkFlow),
    alerts: std.ArrayList(visualizer.SligAlert),
    last_update_time: u64,
    running: bool,
};

// Initialize SDL and create window
fn initSDL(allocator: std.mem.Allocator) !UIContext {
    if (sdl.SDL_Init(sdl.SDL_INIT_VIDEO | sdl.SDL_INIT_TIMER | sdl.SDL_INIT_AUDIO) < 0) {
        std.log.err("Failed to initialize SDL: {s}", .{sdl.SDL_GetError()});
        return error.SDLInitFailed;
    }

    const window = sdl.SDL_CreateWindow(
        WINDOW_TITLE,
        WINDOW_WIDTH,
        WINDOW_HEIGHT,
        sdl.SDL_WINDOW_SHOWN
    ) orelse {
        std.log.err("Failed to create window: {s}", .{sdl.SDL_GetError()});
        return error.WindowCreationFailed;
    };

    const renderer_flags = sdl.SDL_RENDERER_ACCELERATED | sdl.SDL_RENDERER_PRESENTVSYNC;
    const renderer_context = sdl.SDL_CreateRenderer(window, null, renderer_flags) orelse {
        std.log.err("Failed to create renderer: {s}", .{sdl.SDL_GetError()});
        sdl.SDL_DestroyWindow(window);
        return error.RendererCreationFailed;
    };

    // Create visualizer
    const viz = try visualizer.create(allocator, renderer_context);

    // Create IPC channel for communicating with backend
    const ipc_config = ipc.createDefaultConfig();
    const channel = try ipc.IPCChannel.init(allocator, ipc_config);

    return UIContext{
        .allocator = allocator,
        .ipc_channel = channel,
        .window = window,
        .renderer = renderer_context,
        .visualizer = viz,
        .flows = std.ArrayList(visualizer.NetworkFlow).init(allocator),
        .alerts = std.ArrayList(visualizer.SligAlert).init(allocator),
        .last_update_time = sdl.SDL_GetTicks(),
        .running = true,
    };
}

// Process IPC messages from backend
fn processMessages(ctx: *UIContext) !void {
    while (true) {
        const message = ctx.ipc_channel.receiveMessage() catch |err| {
            if (err == ipc.IPCError.Disconnected) {
                std.log.warn("IPC connection lost to backend", .{});
                return;
            }
            return err;
        } orelse break; // No more messages to process

        switch (message.header.msg_type) {
            .PacketEvent => {
                const packet = message.payload.PacketEvent;
                try ctx.visualizer.addPacket(packet);
            },
            .FlowUpdate => {
                const flow = message.payload.FlowUpdate;
                try ctx.visualizer.updateFlow(flow);
            },
            .SligAlert => {
                const alert = message.payload.SligAlert;
                try ctx.visualizer.addAlert(alert);
                
                // Also log the alert to console
                std.log.info("SLIG ALERT: {s} - {s}", .{
                    alert.category,
                    alert.message,
                });
            },
            else => {}, // Ignore other message types for now
        }
    }
}

// Handle SDL events
fn handleEvents(ctx: *UIContext) void {
    var event: sdl.SDL_Event = undefined;
    while (sdl.SDL_PollEvent(&event) != 0) {
        switch (event.type) {
            sdl.SDL_QUIT => {
                ctx.running = false;
            },
            sdl.SDL_KEYDOWN => {
                if (event.key.keysym.sym == sdl.SDLK_ESCAPE) {
                    ctx.running = false;
                }
            },
            else => {},
        }
        
        // Let the visualizer handle events too
        ctx.visualizer.handleEvent(&event);
    }
}

// Main UI loop
pub fn run(allocator: std.mem.Allocator) !void {
    var ctx = try initSDL(allocator);
    defer {
        // Cleanup
        ctx.flows.deinit();
        ctx.alerts.deinit();
        ctx.visualizer.destroy();
        ctx.ipc_channel.deinit();
        sdl.SDL_DestroyRenderer(ctx.renderer);
        sdl.SDL_DestroyWindow(ctx.window);
        sdl.SDL_Quit();
    }

    std.log.info("Necronet UI started - Oddworld Network Monitor", .{});

    // Main loop
    while (ctx.running) {
        // Process IPC messages from backend
        try processMessages(&ctx);
        
        // Handle SDL events
        handleEvents(&ctx);
        
        // Calculate delta time
        const current_time = sdl.SDL_GetTicks();
        const delta_ms = current_time - ctx.last_update_time;
        ctx.last_update_time = current_time;
        const delta_sec = @as(f32, @floatFromInt(delta_ms)) / 1000.0;
        
        // Update visualization
        try ctx.visualizer.update(delta_sec);
        
        // Render frame
        sdl.SDL_SetRenderDrawColor(ctx.renderer, 0, 0, 0, 255); // Black background
        sdl.SDL_RenderClear(ctx.renderer);
        
        try ctx.visualizer.render();
        
        sdl.SDL_RenderPresent(ctx.renderer);
        
        // Cap framerate
        const frame_time = sdl.SDL_GetTicks() - current_time;
        if (frame_time < FRAME_TIME_MS) {
            sdl.SDL_Delay(FRAME_TIME_MS - frame_time);
        }
    }
}

// Entry point for the UI module
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    const allocator = gpa.allocator();
    try run(allocator);
}