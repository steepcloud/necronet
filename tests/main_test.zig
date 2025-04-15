const std = @import("std");
const testing = std.testing;
const backend = @import("backend");
const common = @import("common");
const test_bnd_capture = @import("test_bnd_capture.zig");

test "basic test" {
    try testing.expect(true);
}

// You can add more test functions here
// or import other test modules

// Example to test Protocol enum
test "protocol enum exists" {
    const tcp = common.Protocol.TCP;
    try testing.expectEqual(common.Protocol.TCP, tcp);
}