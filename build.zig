const std = @import("std");
// TODO: add tests for ipc/*.zig
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const backend_module = b.createModule(.{
        .root_source_file = b.path("backend/capture.zig"),
    });
    backend_module.addIncludePath(b.path("."));

    const detection_module = b.createModule(.{
        .root_source_file = b.path("backend/detection.zig"),
    });
    detection_module.addIncludePath(b.path("."));

    const parser_module = b.createModule(.{
        .root_source_file = b.path("backend/parser.zig"),
    });
    parser_module.addIncludePath(b.path("."));

    if (target.result.os.tag == .windows) {
        backend_module.addIncludePath(b.path("npcap-sdk-1.15/Include"));
    }

    const ipc_module = b.createModule(.{
        .root_source_file = b.path("ipc/ipc.zig"),
    });
    const ipc_messages_module = b.createModule(.{
        .root_source_file = b.path("ipc/messages.zig"),
    });

    const common_module = b.createModule(.{
        .root_source_file = b.path("common/types.zig"),
    });

    // add SDL dependency
    const sdl_dep = b.dependency("sdl", .{
        .target = target,
        .optimize = optimize,
    });
    const sdl_lib = sdl_dep.artifact("SDL3");

    // UI modules
    const ui_main_module = b.createModule(.{
        .root_source_file = b.path("ui/main.zig"),
    });
    const ui_renderer_module = b.createModule(.{
        .root_source_file = b.path("ui/renderer.zig"),
    });
    const ui_state_module = b.createModule(.{
        .root_source_file = b.path("ui/ui_state.zig"),
    });
    const ui_sprites_module = b.createModule(.{
        .root_source_file = b.path("ui/sprites.zig"),
    });
    const ui_visualizer_module = b.createModule(.{
        .root_source_file = b.path("ui/visualizer.zig"),
    });

    backend_module.addImport("common", common_module);
    detection_module.addImport("common", common_module);
    detection_module.addImport("backend", backend_module);
    parser_module.addImport("common", common_module);
    parser_module.addImport("backend", backend_module);
    ipc_module.addImport("messages", ipc_messages_module);
    ipc_messages_module.addImport("common", common_module);
    ipc_messages_module.addImport("backend", backend_module);
    ipc_messages_module.addImport("detection", detection_module);
    ui_main_module.addImport("common", common_module);
    ui_main_module.addImport("ipc", ipc_module);
    ui_main_module.addImport("messages", ipc_messages_module);
    ui_main_module.addImport("renderer", ui_renderer_module);
    ui_main_module.addImport("ui_state", ui_state_module);
    ui_main_module.addImport("sprites", ui_sprites_module);
    ui_main_module.addImport("visualizer", ui_visualizer_module);
    ui_main_module.addIncludePath(sdl_dep.path("include"));
    
    // UI module dependencies
    ui_main_module.linkLibrary(sdl_lib);

    // main executable
    const exe = b.addExecutable(.{
        .name = "necronet",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // add modules to the main executable
    exe.root_module.addImport("backend", backend_module);
    exe.root_module.addImport("detection", detection_module);
    exe.root_module.addImport("ipc", ipc_module);
    exe.root_module.addImport("messages", ipc_messages_module);
    exe.root_module.addImport("common", common_module);
    exe.root_module.addImport("parser", parser_module);
    exe.root_module.addImport("ui", ui_main_module);
    exe.root_module.addImport("renderer", ui_renderer_module);
    exe.root_module.addImport("ui_state", ui_state_module);
    exe.root_module.addImport("sprites", ui_sprites_module);
    exe.root_module.addImport("visualizer", ui_visualizer_module);

    exe.linkLibrary(sdl_lib);

    // link with libpcap (Npcap on Windows)
    if (target.result.os.tag == .windows) {
        exe.addIncludePath(b.path("."));
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
    unit_tests.root_module.addImport("detection", detection_module);
    unit_tests.root_module.addImport("parser", parser_module);
    unit_tests.root_module.addImport("ipc", ipc_module);
    unit_tests.root_module.addImport("common", common_module);

    if (target.result.os.tag == .windows) {
        unit_tests.addIncludePath(b.path("."));
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