const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create modules for each component
    const backend_module = b.createModule(.{
        .root_source_file = b.path("backend/capture.zig"),
    });

    const ipc_module = b.createModule(.{
        .root_source_file = b.path("ipc/ipc.zig"),
    });

    const common_module = b.createModule(.{
        .root_source_file = b.path("common/types.zig"),
    });

    backend_module.addImport("common", common_module);
    ipc_module.addImport("common", common_module);

    // main executable
    const exe = b.addExecutable(.{
        .name = "necronet",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // add modules to the main executable
    exe.root_module.addImport("backend", backend_module);
    exe.root_module.addImport("ipc", ipc_module);
    exe.root_module.addImport("common", common_module);

    // link with libpcap (Npcap on Windows)
    if (target.result.os.tag == .windows) {
        exe.addIncludePath(b.path("npcap-sdk-1.15/Include"));
        
        if (target.result.cpu.arch == .x86_64) {
            exe.addLibraryPath(b.path("npcap-sdk-1.15/Lib/x64"));
        } else {
            exe.addLibraryPath(b.path("npcap-sdk-1.15/Lib"));
        }
        exe.linkSystemLibrary("wpcap");
        exe.linkSystemLibrary("Packet");
    } else {
        exe.linkSystemLibrary("pcap");
    }
    exe.linkLibC();

    // install assets directory
    b.installDirectory(.{
        .source_dir = b.path("assets"),
        .install_dir = .{ .custom = "assets" },
        .install_subdir = "",
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("tests/main_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    // add modules to the tests
    unit_tests.root_module.addImport("backend", backend_module);
    unit_tests.root_module.addImport("ipc", ipc_module);
    unit_tests.root_module.addImport("common", common_module);

    if (target.result.os.tag == .windows) {
        unit_tests.addIncludePath(b.path("npcap-sdk-1.15/Include"));
        if (target.result.cpu.arch == .x86_64) {
            unit_tests.addLibraryPath(b.path("npcap-sdk-1.15/Lib/x64"));
        } else {
            unit_tests.addLibraryPath(b.path("npcap-sdk-1.15/Lib"));
        }
        unit_tests.linkSystemLibrary("wpcap");
        unit_tests.linkSystemLibrary("Packet");
    } else {
        unit_tests.linkSystemLibrary("pcap");
    }
    unit_tests.linkLibC();

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}