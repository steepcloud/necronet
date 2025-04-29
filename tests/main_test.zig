const std = @import("std");
const testing = std.testing;

// This file serves as the main test runner for all Necronet test modules.
// It imports and runs all tests from the specialized test modules.
// To run all tests: `zig build test`

comptime {
    _ = @import("test_bnd_capture.zig");
    _ = @import("test_bnd_detection.zig");
    _ = @import("test_bnd_parser.zig");
    _ = @import("test_ipc.zig");
    _ = @import("test_ipc_messages.zig");
}

test {
    std.testing.refAllDecls(@This());
}
