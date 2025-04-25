const std = @import("std");
const sdl = @cImport({
    @cInclude("SDL3/SDL.h");
});

/// Error set for renderer operations
pub const RendererError = error{
    TextureCreationFailed,
    RenderingFailed,
    InvalidParameters,
    ResourceInitFailed,
    ResourceNotAvailable,
};

/// RGBA color representation
pub const Color = struct {
    r: u8 = 255,
    g: u8 = 255,
    b: u8 = 255,
    a: u8 = 255,

    /// Create color from hex value (0xRRGGBBAA)
    pub fn fromHex(hex: u32) Color {
        return Color{
            .r = @truncate((hex >> 24) & 0xFF),
            .g = @truncate((hex >> 16) & 0xFF),
            .b = @truncate((hex >> 8) & 0xFF),
            .a = @truncate(hex & 0xFF),
        };
    }

    /// Predefined colors for convenience
    pub const white = Color{ .r = 255, .g = 255, .b = 255 };
    pub const black = Color{ .r = 0, .g = 0, .b = 0 };
    pub const red = Color{ .r = 255, .g = 0, .b = 0 };
    pub const green = Color{ .r = 0, .g = 255, .b = 0 };
    pub const blue = Color{ .r = 0, .g = 0, .b = 255 };
    pub const yellow = Color{ .r = 255, .g = 255, .b = 0 };
    pub const cyan = Color{ .r = 0, .g = 255, .b = 255 };
    pub const magenta = Color{ .r = 255, .g = 0, .b = 255 };
    pub const orange = Color{ .r = 255, .g = 165, .b = 0 };
    pub const purple = Color{ .r = 128, .g = 0, .b = 128 };
    pub const transparent = Color{ .r = 0, .g = 0, .b = 0, .a = 0 };

    /// Create a color with modified alpha
    pub fn withAlpha(self: Color, new_alpha: u8) Color {
        var result = self;
        result.a = new_alpha;
        return result;
    }

    /// Blend two colors based on a ratio (0.0 = self, 1.0 = other)
    pub fn blend(self: Color, other: Color, ratio: f32) Color {
        const clamped = @min(1.0, @max(0.0, ratio));
        const inv_ratio = 1.0 - clamped;
        
        return Color{
            .r = @intFromFloat(@as(f32, @floatFromInt(self.r)) * inv_ratio + @as(f32, @floatFromInt(other.r)) * clamped),
            .g = @intFromFloat(@as(f32, @floatFromInt(self.g)) * inv_ratio + @as(f32, @floatFromInt(other.g)) * clamped),
            .b = @intFromFloat(@as(f32, @floatFromInt(self.b)) * inv_ratio + @as(f32, @floatFromInt(other.b)) * clamped),
            .a = @intFromFloat(@as(f32, @floatFromInt(self.a)) * inv_ratio + @as(f32, @floatFromInt(other.a)) * clamped),
        };
    }
};

/// Rectangle shape definition
pub const Rect = struct {
    x: f32,
    y: f32,
    w: f32,
    h: f32,

    /// Convert to SDL_FRect
    pub fn toSDLRect(self: Rect) sdl.SDL_FRect {
        return sdl.SDL_FRect{
            .x = self.x,
            .y = self.y,
            .w = self.w,
            .h = self.h,
        };
    }
    
    /// Check if a point is inside the rectangle
    pub fn containsPoint(self: Rect, x: f32, y: f32) bool {
        return x >= self.x and 
               x <= self.x + self.w and 
               y >= self.y and 
               y <= self.y + self.h;
    }

    /// Get the center of the rectangle
    pub fn center(self: Rect) struct { x: f32, y: f32 } {
        return .{
            .x = self.x + self.w / 2.0,
            .y = self.y + self.h / 2.0,
        };
    }
};

/// Main renderer type that abstracts SDL rendering operations
pub const Renderer = struct {
    allocator: std.mem.Allocator,
    sdl_renderer: *sdl.SDL_Renderer,
    width: i32,
    height: i32,
    background_color: Color,
    
    /// Initialize renderer with SDL renderer
    pub fn init(allocator: std.mem.Allocator, sdl_renderer: *sdl.SDL_Renderer) !Renderer {
        var width: i32 = undefined;
        var height: i32 = undefined;
        
        if (sdl.SDL_GetRenderSize(sdl_renderer, &width, &height) != 0) {
            std.log.err("Failed to get renderer size: {s}", .{sdl.SDL_GetError()});
            return RendererError.ResourceInitFailed;
        }
        
        return Renderer{
            .allocator = allocator,
            .sdl_renderer = sdl_renderer,
            .width = width,
            .height = height,
            .background_color = Color.black,
        };
    }

    /// Set the background color for clear operations
    pub fn setBackgroundColor(self: *Renderer, color: Color) void {
        self.background_color = color;
    }

    /// Clear the entire rendering target with the background color
    pub fn clear(self: *Renderer) !void {
        _ = sdl.SDL_SetRenderDrawColor(
            self.sdl_renderer, 
            self.background_color.r, 
            self.background_color.g, 
            self.background_color.b, 
            self.background_color.a
        );
        
        if (sdl.SDL_RenderClear(self.sdl_renderer) != 0) {
            std.log.err("Failed to clear renderer: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Present the rendered content to the screen
    pub fn present(self: *Renderer) void {
        sdl.SDL_RenderPresent(self.sdl_renderer);
    }

    /// Set current drawing color
    pub fn setDrawColor(self: *Renderer, color: Color) !void {
        if (sdl.SDL_SetRenderDrawColor(
            self.sdl_renderer, color.r, color.g, color.b, color.a
        ) != 0) {
            std.log.err("Failed to set render color: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Draw a filled rectangle
    pub fn fillRect(self: *Renderer, rect: Rect, color: Color) !void {
        try self.setDrawColor(color);
        
        const sdl_rect = rect.toSDLRect();
        if (sdl.SDL_RenderFillRect(self.sdl_renderer, &sdl_rect) != 0) {
            std.log.err("Failed to render filled rect: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Draw an outlined rectangle
    pub fn drawRect(self: *Renderer, rect: Rect, color: Color) !void {
        try self.setDrawColor(color);
        
        const sdl_rect = rect.toSDLRect();
        if (sdl.SDL_RenderRect(self.sdl_renderer, &sdl_rect) != 0) {
            std.log.err("Failed to render rect outline: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Draw a line between two points
    pub fn drawLine(self: *Renderer, x1: f32, y1: f32, x2: f32, y2: f32, color: Color) !void {
        try self.setDrawColor(color);
        
        if (sdl.SDL_RenderLine(self.sdl_renderer, x1, y1, x2, y2) != 0) {
            std.log.err("Failed to render line: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Draw a point
    pub fn drawPoint(self: *Renderer, x: f32, y: f32, color: Color) !void {
        try self.setDrawColor(color);
        
        if (sdl.SDL_RenderPoint(self.sdl_renderer, x, y) != 0) {
            std.log.err("Failed to render point: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Draw multiple connected lines
    pub fn drawLines(self: *Renderer, points: []const sdl.SDL_FPoint, color: Color) !void {
        try self.setDrawColor(color);
        
        if (sdl.SDL_RenderLines(self.sdl_renderer, points.ptr, @intCast(points.len)) != 0) {
            std.log.err("Failed to render lines: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Draw a filled circle
    pub fn fillCircle(self: *Renderer, cx: f32, cy: f32, radius: f32, color: Color) !void {
        try self.setDrawColor(color);

        // Use midpoint circle algorithm with horizontal scanlines for filling
        var x: i32 = 0;
        var y: i32 = @intFromFloat(radius);
        var d: i32 = 3 - 2 * @as(i32, @intFromFloat(radius));

        while (y >= x) {
            // Draw horizontal lines for each octant to fill the circle
            try self._drawHorizontalLine(cx - @as(f32, @floatFromInt(x)), cx + @as(f32, @floatFromInt(x)), cy - @as(f32, @floatFromInt(y)));
            try self._drawHorizontalLine(cx - @as(f32, @floatFromInt(y)), cx + @as(f32, @floatFromInt(y)), cy - @as(f32, @floatFromInt(x)));
            try self._drawHorizontalLine(cx - @as(f32, @floatFromInt(x)), cx + @as(f32, @floatFromInt(x)), cy + @as(f32, @floatFromInt(y)));
            try self._drawHorizontalLine(cx - @as(f32, @floatFromInt(y)), cx + @as(f32, @floatFromInt(y)), cy + @as(f32, @floatFromInt(x)));

            if (d > 0) {
                y -= 1;
                d = d + 4 * (x - y) + 10;
            } else {
                d = d + 4 * x + 6;
            }
            x += 1;
        }
    }

    /// Draw a circle outline
    pub fn drawCircle(self: *Renderer, cx: f32, cy: f32, radius: f32, color: Color) !void {
        try self.setDrawColor(color);

        // Use midpoint circle algorithm
        var x: i32 = 0;
        var y: i32 = @intFromFloat(radius);
        var d: i32 = 3 - 2 * @as(i32, @intFromFloat(radius));

        while (y >= x) {
            // Draw 8 points (one in each octant)
            try self.drawPoint(cx + @as(f32, @floatFromInt(x)), cy + @as(f32, @floatFromInt(y)), color);
            try self.drawPoint(cx + @as(f32, @floatFromInt(y)), cy + @as(f32, @floatFromInt(x)), color);
            try self.drawPoint(cx - @as(f32, @floatFromInt(x)), cy + @as(f32, @floatFromInt(y)), color);
            try self.drawPoint(cx - @as(f32, @floatFromInt(y)), cy + @as(f32, @floatFromInt(x)), color);
            try self.drawPoint(cx + @as(f32, @floatFromInt(x)), cy - @as(f32, @floatFromInt(y)), color);
            try self.drawPoint(cx + @as(f32, @floatFromInt(y)), cy - @as(f32, @floatFromInt(x)), color);
            try self.drawPoint(cx - @as(f32, @floatFromInt(x)), cy - @as(f32, @floatFromInt(y)), color);
            try self.drawPoint(cx - @as(f32, @floatFromInt(y)), cy - @as(f32, @floatFromInt(x)), color);

            if (d > 0) {
                y -= 1;
                d = d + 4 * (x - y) + 10;
            } else {
                d = d + 4 * x + 6;
            }
            x += 1;
        }
    }

    /// Draw a texture at specified position
    pub fn drawTexture(self: *Renderer, texture: *sdl.SDL_Texture, src_rect: ?sdl.SDL_FRect, dest_rect: sdl.SDL_FRect) !void {
        if (sdl.SDL_RenderTexture(self.sdl_renderer, texture, if (src_rect) |r| &r else null, &dest_rect) != 0) {
            std.log.err("Failed to render texture: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Draw a colored texture at specified position
    pub fn drawColoredTexture(self: *Renderer, texture: *sdl.SDL_Texture, src_rect: ?sdl.SDL_FRect, dest_rect: sdl.SDL_FRect, color: Color) !void {
        _ = sdl.SDL_SetTextureColorMod(texture, color.r, color.g, color.b);
        _ = sdl.SDL_SetTextureAlphaMod(texture, color.a);
        
        try self.drawTexture(texture, src_rect, dest_rect);
    }

    /// Draw a rotated texture at specified position
    pub fn drawRotatedTexture(
        self: *Renderer, 
        texture: *sdl.SDL_Texture, 
        src_rect: ?sdl.SDL_FRect, 
        dest_rect: sdl.SDL_FRect, 
        angle_degrees: f64, 
        center: ?sdl.SDL_FPoint,
        flip: sdl.SDL_FlipMode
    ) !void {
        if (sdl.SDL_RenderTextureRotated(
            self.sdl_renderer, 
            texture, 
            if (src_rect) |r| &r else null, 
            &dest_rect, 
            angle_degrees, 
            if (center) |c| &c else null, 
            flip
        ) != 0) {
            std.log.err("Failed to render rotated texture: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }

    /// Create a texture from a surface
    pub fn createTextureFromSurface(self: *Renderer, surface: *sdl.SDL_Surface) !*sdl.SDL_Texture {
        const texture = sdl.SDL_CreateTextureFromSurface(self.sdl_renderer, surface) orelse {
            std.log.err("Failed to create texture from surface: {s}", .{sdl.SDL_GetError()});
            return RendererError.TextureCreationFailed;
        };
        
        return texture;
    }

    /// Create a blank texture with dimensions
    pub fn createTexture(
        self: *Renderer,
        format: u32,
        access: sdl.SDL_TextureAccess,
        width: i32,
        height: i32
    ) !*sdl.SDL_Texture {
        const texture = sdl.SDL_CreateTexture(
            self.sdl_renderer,
            format,
            access,
            width,
            height
        ) orelse {
            std.log.err("Failed to create texture: {s}", .{sdl.SDL_GetError()});
            return RendererError.TextureCreationFailed;
        };
        
        return texture;
    }

    /// Load a texture from a file path
    pub fn loadTexture(self: *Renderer, path: [*:0]const u8) !*sdl.SDL_Texture {
        const surface = sdl.SDL_LoadBMP(path) orelse {
            std.log.err("Failed to load image {s}: {s}", .{path, sdl.SDL_GetError()});
            return RendererError.ResourceNotAvailable;
        };
        defer sdl.SDL_DestroySurface(surface);
        
        return try self.createTextureFromSurface(surface);
    }

    /// Get the dimensions of the rendering target
    pub fn getSize(self: *const Renderer) struct { width: i32, height: i32 } {
        return .{
            .width = self.width,
            .height = self.height,
        };
    }

    /// Update the stored dimensions (call after window resize)
    pub fn updateSize(self: *Renderer) !void {
        var width: i32 = undefined;
        var height: i32 = undefined;
        
        if (sdl.SDL_GetRenderSize(self.sdl_renderer, &width, &height) != 0) {
            std.log.err("Failed to update renderer size: {s}", .{sdl.SDL_GetError()});
            return RendererError.ResourceInitFailed;
        }
        
        self.width = width;
        self.height = height;
    }

    /// Draw a filled rectangle with a gradient (vertical)
    pub fn fillGradientRect(self: *Renderer, rect: Rect, top_color: Color, bottom_color: Color) !void {
        const height = @as(i32, @intFromFloat(rect.h));
        
        var y: i32 = 0;
        while (y < height) : (y += 1) {
            const ratio = @as(f32, @floatFromInt(y)) / @as(f32, @floatFromInt(height));
            const color = top_color.blend(bottom_color, ratio);
            
            try self.setDrawColor(color);
            try self.drawLine(
                rect.x, 
                rect.y + @as(f32, @floatFromInt(y)), 
                rect.x + rect.w, 
                rect.y + @as(f32, @floatFromInt(y)), 
                color
            );
        }
    }

    /// Draw a rounded rectangle outline
    pub fn drawRoundedRect(self: *Renderer, rect: Rect, radius: f32, color: Color) !void {
        try self.setDrawColor(color);
        
        // Draw four straight edges
        try self.drawLine(rect.x + radius, rect.y, rect.x + rect.w - radius, rect.y, color);
        try self.drawLine(rect.x + radius, rect.y + rect.h, rect.x + rect.w - radius, rect.y + rect.h, color);
        try self.drawLine(rect.x, rect.y + radius, rect.x, rect.y + rect.h - radius, color);
        try self.drawLine(rect.x + rect.w, rect.y + radius, rect.x + rect.w, rect.y + rect.h - radius, color);
        
        // Draw four quarter-circles at corners
        try self.drawArc(rect.x + radius, rect.y + radius, radius, 180, 270, color);
        try self.drawArc(rect.x + rect.w - radius, rect.y + radius, radius, 270, 360, color);
        try self.drawArc(rect.x + radius, rect.y + rect.h - radius, radius, 90, 180, color);
        try self.drawArc(rect.x + rect.w - radius, rect.y + rect.h - radius, radius, 0, 90, color);
    }

    /// Draw a filled rounded rectangle
    pub fn fillRoundedRect(self: *Renderer, rect: Rect, radius: f32, color: Color) !void {
        // Draw main rectangle
        try self.fillRect(Rect{
            .x = rect.x,
            .y = rect.y + radius,
            .w = rect.w,
            .h = rect.h - 2 * radius,
        }, color);
        
        // Draw top rectangle
        try self.fillRect(Rect{
            .x = rect.x + radius,
            .y = rect.y,
            .w = rect.w - 2 * radius,
            .h = radius,
        }, color);
        
        // Draw bottom rectangle
        try self.fillRect(Rect{
            .x = rect.x + radius,
            .y = rect.y + rect.h - radius,
            .w = rect.w - 2 * radius,
            .h = radius,
        }, color);
        
        // Draw four quarter-circles at corners
        try self.fillArc(rect.x + radius, rect.y + radius, radius, 180, 270, color);
        try self.fillArc(rect.x + rect.w - radius, rect.y + radius, radius, 270, 360, color);
        try self.fillArc(rect.x + radius, rect.y + rect.h - radius, radius, 90, 180, color);
        try self.fillArc(rect.x + rect.w - radius, rect.y + rect.h - radius, radius, 0, 90, color);
    }

    /// Draw an arc (portion of a circle outline)
    pub fn drawArc(self: *Renderer, cx: f32, cy: f32, radius: f32, start_angle: f32, end_angle: f32, color: Color) !void {
        try self.setDrawColor(color);
        
        const step: f32 = 1.0; // Step in degrees
        const start_rad = start_angle * std.math.pi / 180.0;
        const end_rad = end_angle * std.math.pi / 180.0;
        
        var angle = start_rad;
        while (angle <= end_rad) : (angle += step * std.math.pi / 180.0) {
            const x = cx + radius * @cos(angle);
            const y = cy + radius * @sin(angle);
            try self.drawPoint(x, y, color);
        }
    }

    /// Draw a filled arc (pie slice)
    pub fn fillArc(self: *Renderer, cx: f32, cy: f32, radius: f32, start_angle: f32, end_angle: f32, color: Color) !void {
        try self.setDrawColor(color);
        
        const step: f32 = 1.0; // Step in degrees
        const start_rad = start_angle * std.math.pi / 180.0;
        const end_rad = end_angle * std.math.pi / 180.0;
        
        var angle = start_rad;
        while (angle <= end_rad) : (angle += step * std.math.pi / 180.0) {
            const x = cx + radius * @cos(angle);
            const y = cy + radius * @sin(angle);
            try self.drawLine(cx, cy, x, y, color);
        }
    }

    /// Helper function to draw a horizontal line efficiently
    fn _drawHorizontalLine(self: *Renderer, x1: f32, x2: f32, y: f32) !void {
        if (sdl.SDL_RenderLine(self.sdl_renderer, x1, y, x2, y) != 0) {
            std.log.err("Failed to render horizontal line: {s}", .{sdl.SDL_GetError()});
            return RendererError.RenderingFailed;
        }
    }
};