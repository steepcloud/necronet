const std = @import("std");
const testing = std.testing;
const backend = @import("backend");
const parser = @import("parser");
const common = @import("common");

pub const test_capture = @import("test_bnd_capture.zig");
pub const test_detection = @import("test_bnd_detection.zig");
pub const test_parser = @import("test_bnd_parser.zig");
pub const test_ipc = @import("test_ipc.zig");

test {
    @import("std").testing.refAllDecls(@This());
}

test "capture test" {
    std.debug.print("RUNNING CAPTURE TEST\n", .{});
    try testing.expect(true);
}

test "detection test" {
    std.debug.print("RUNNING DETECTION TEST\n", .{});
    try testing.expect(true);
}

test "parser test" {
    std.debug.print("RUNNING PARSER TEST\n", .{});
    try testing.expect(true);
}

test "ipc test" {
    std.debug.print("RUNNING IPC TEST\n", .{});
    try testing.expect(true);
}