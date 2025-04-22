const std = @import("std");
const testing = std.testing;
const backend = @import("backend");
const common = @import("common");

pub const test_capture = @import("test_bnd_capture.zig");
pub const test_detection = @import("test_bnd_detection.zig");

test {
    @import("std").testing.refAllDecls(@This());
}

test "basic test" {
    std.debug.print("RUNNING SIMPLE TEST\n", .{});
    try testing.expect(true);
}

test "capture test" {
    std.debug.print("RUNNING CAPTURE TEST\n", .{});
    try testing.expect(true);
}

test "detection test" {
    std.debug.print("RUNNING DETECTION TEST\n", .{});
    try testing.expect(true);
}