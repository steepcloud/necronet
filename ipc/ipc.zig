///////////////////////////////////////////////////////////////////////////////
// Inter-Process Communication Module
//
// This module provides reliable, bidirectional communication channels between
// processes in the Necronet system. It implements multiple transport mechanisms
// (standard I/O, named pipes, and TCP sockets) with platform-specific
// optimizations for both Windows and Unix-based systems.
//
// The IPC system handles serialization, connection management, error handling,
// and resource cleanup automatically. All operations are designed to be
// non-blocking with configurable timeouts and retry policies.
///////////////////////////////////////////////////////////////////////////////

const std = @import("std");
const os = std.os;
const linux = std.os.linux;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const windows = if (builtin.os.tag == .windows) std.os.windows else void;
const ws2_32 = if (builtin.os.tag == .windows) @cImport({
    @cInclude("winsock2.h");
}) else void;
const builtin = @import("builtin");

/// Windows-specific error code for when a pipe client is already connected
const ERROR_PIPE_CONNECTED = 535; // 0x217 hex

/// Windows API functions not directly exposed by Zig std lib
extern "kernel32" fn ConnectNamedPipe(
    hNamedPipe: windows.HANDLE,
    lpOverlapped: ?*anyopaque,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn SetNamedPipeHandleState(
    hNamedPipe: windows.HANDLE,
    lpMode: ?*windows.DWORD,
    lpMaxCollectionCount: ?*windows.DWORD,
    lpCollectDataTimeout: ?*windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

const msg = @import("messages");
const Message = msg.Message;

fn mkfifo(path: [*:0]const u8, mode: u32) !void {
    const S_IFIFO = 0o010000; // FIFO named pipe flag
    const result = linux.syscall3(.mknod, @intFromPtr(path), mode | S_IFIFO, 0);

    const err = std.posix.errno(result);

    switch (err) {
        .SUCCESS => return,
        .EXIST => return, // FIFO already exists
        .ACCES => return error.AccessDenied,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOSPC => return error.NoSpaceLeft,
        .NOTDIR => return error.NotDir,
        .ROFS => return error.ReadOnlyFileSystem,
        else => return std.posix.unexpectedErrno(err),
    }
}

/// Error types that can occur during IPC operations
/// These provide specific failure reasons for better error handling and recovery
pub const IPCError = error{
    ChannelInitFailed, // failed to initialize the communication channel
    SendFailed, // message transmission failed
    ReceiveFailed, // message reception failed
    Disconnected, // the channel has been closed or disconnected
    InvalidMessage, // received message with invalid format
    BufferTooSmall, // receive buffer is too small for incoming message
    OperationTimedOut, // operation did not complete within timeout period
};

/// Message serialization format options
pub const SerializationFormat = enum {
    Json, // JSON text format (human-readable, flexible)
    Binary, // Binary format (compact, faster)
};

/// Options for how the IPC channel connects processes
pub const ChannelType = enum {
    StdIO, // Standard input/output for parent/child processes
    NamedPipe, // Named pipes (Windows) or FIFOs (Unix)
    Socket, // TCP socket for network communication
};

/// Configuration for IPC channel
/// Controls behavior, performance characteristics, and error handling policy
pub const IPCConfig = struct {
    channel_type: ChannelType = .StdIO, // communication transport mechanism
    serialization: SerializationFormat = .Json, // message encoding format
    path: ?[]const u8 = null, // Path for named pipe, or address for socket
    buffer_size: usize = 65536, // Default read buffer size (64KB)
    timeout_ms: u32 = 5000, // Default timeout in milliseconds
    retry_count: u32 = 3, // Number of retries for failed operations
};

/// Statistics about IPC channel usage
/// Tracks performance metrics and helps with debugging connection issues
pub const ChannelStats = struct {
    messages_sent: u64 = 0, // total messages successfully sent
    messages_received: u64 = 0, // total messages successfully received
    bytes_sent: u64 = 0, // total bytes transmitted
    bytes_received: u64 = 0, // total bytes received
    send_errors: u32 = 0, // count of message send failures
    receive_errors: u32 = 0, // count of message receive failure
    last_activity: i64 = 0, // timestamp of last successful activity
};

/// IPC Channel for Necronet communication
/// Provides a reliable, bidirectional message-passing interface
pub const IPCChannel = struct {
    allocator: Allocator, // memory allocator for dynamic allocations
    config: IPCConfig, // channel configuration parameters
    stats: ChannelStats = .{}, // usage statistics and metrics
    is_connected: bool = false, // whether channel is currently operational
    next_sequence: u64 = 1, // auto-incrementing message sequence number
    read_buffer: []u8 = &[_]u8{}, // buffer for receiving messages

    // File descriptors/handles for I/O
    read_fd: ?std.fs.File = null, // file descriptor for reading
    write_fd: ?std.fs.File = null, // file descriptor for writing

    socket: ?std.net.Stream = null, // TCP socket for network-based IPC

    // stream readers and writers for socket-based communication
    socket_reader: ?std.io.Reader(std.net.Stream, std.net.Stream.ReadError, std.net.Stream.read) = null,
    socket_writer: ?std.io.Writer(std.net.Stream, std.net.Stream.WriteError, std.net.Stream.write) = null,

    // stream readers and writers for file-based communication
    reader: ?std.io.Reader(std.fs.File, std.fs.File.ReadError, std.fs.File.read) = null,
    writer: ?std.io.Writer(std.fs.File, std.fs.File.WriteError, std.fs.File.write) = null,

    /// Initialize a new IPC channel
    ///
    /// Creates and configures a communication channel based on the provided configuration.
    /// Handles platform-specific setup for each channel type and allocates required resources.
    ///
    /// Parameters:
    ///   allocator: Memory allocator for channel resources
    ///   config: IPC channel configuration parameters
    ///
    /// Returns:
    ///   Pointer to initialized IPC channel or error
    pub fn init(allocator: Allocator, config: IPCConfig) !*IPCChannel {
        var channel = try allocator.create(IPCChannel);
        errdefer allocator.destroy(channel);

        channel.* = IPCChannel{
            .allocator = allocator,
            .config = config,
        };

        // allocate read buffer
        channel.read_buffer = try allocator.alloc(u8, config.buffer_size);
        errdefer allocator.free(channel.read_buffer);

        // initialize channel based on the selected type
        switch (config.channel_type) {
            .StdIO => try channel.initStdIO(),
            .NamedPipe => try channel.initNamedPipe(),
            .Socket => try channel.initSocket(),
        }

        // initialize the reader/writer
        if (channel.read_fd != null) {
            channel.reader = channel.read_fd.?.reader();
        }

        if (channel.write_fd != null) {
            channel.writer = channel.write_fd.?.writer();
        }

        if (channel.socket != null) {
            const socket_reader = channel.socket.?.reader();
            const socket_writer = channel.socket.?.writer();

            channel.socket_reader = socket_reader;
            channel.socket_writer = socket_writer;
        }

        channel.is_connected = true;
        channel.stats.last_activity = std.time.timestamp();
        return channel;
    }

    /// Initialize using standard input/output
    ///
    /// Sets up a communication channel using the process stdin/stdout streams.
    /// This is useful for parent-child process communication without extra setup.
    ///
    /// Returns:
    ///   Error if initialization fails
    fn initStdIO(self: *IPCChannel) !void {
        // For StdIO, we'll use the current process's stdin/stdout
        // Child processes will use these to communicate with parent

        if (builtin.os.tag == .windows) {
            // On Windows, we need to open stdin/stdout with appropriate access
            self.read_fd = std.io.getStdIn();
            self.write_fd = std.io.getStdOut();
        } else {
            // On Unix, we can use stdin/stdout directly
            self.read_fd = std.io.getStdIn();
            self.write_fd = std.io.getStdOut();
        }
    }

    /// Initialize using named pipes (Windows) or FIFOs (Unix)
    ///
    /// Creates and configures platform-specific named pipe implementations.
    /// On Windows, uses Win32 named pipe API with message-based mode.
    /// On Unix systems, creates bidirectional FIFOs with non-blocking mode.
    ///
    /// Returns:
    ///   Error if pipe creation or configuration fails
    fn initNamedPipe(self: *IPCChannel) !void {
        if (self.config.path == null) {
            return IPCError.ChannelInitFailed;
        }

        const pipe_path = self.config.path.?;

        if (builtin.os.tag == .windows) {
            // Windows named pipes
            const pipe_name = try std.fmt.allocPrint(self.allocator, "\\\\.\\pipe\\{s}", .{pipe_path});
            defer self.allocator.free(pipe_name);

            const read_pipe_name = try std.fmt.allocPrint(self.allocator, "\\\\.\\pipe\\{s}-read", .{pipe_path});
            defer self.allocator.free(read_pipe_name);

            // Windows-specific pipe constants
            const PIPE_ACCESS_DUPLEX = 0x00000003;
            const PIPE_TYPE_MESSAGE = 0x00000004;
            const PIPE_READMODE_MESSAGE = 0x00000002;
            const PIPE_WAIT = 0x00000000;
            const PIPE_UNLIMITED_INSTANCES = 255;
            const GENERIC_READ = 0x80000000;
            const GENERIC_WRITE = 0x40000000;
            const OPEN_EXISTING = 3;
            const FILE_ATTRIBUTE_NORMAL = 0x00000080;

            // create write pipe (server mode)
            const write_handle = windows.kernel32.CreateNamedPipeW(try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, pipe_name), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, null);

            if (write_handle == windows.INVALID_HANDLE_VALUE) {
                return IPCError.ChannelInitFailed;
            }

            // connect to read pipe (client mode)
            const read_handle = windows.kernel32.CreateFileW(std.unicode.utf8ToUtf16LeAllocZ(self.allocator, read_pipe_name) catch {
                windows.CloseHandle(write_handle);
                return IPCError.ChannelInitFailed;
            }, GENERIC_READ | GENERIC_WRITE, 0, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);

            if (read_handle == windows.INVALID_HANDLE_VALUE) {
                windows.CloseHandle(write_handle);
                return IPCError.ChannelInitFailed;
            }

            // wait for client connection
            if (ConnectNamedPipe(write_handle, null) == 0) {
                const last_error = windows.GetLastError();
                if (@intFromEnum(last_error) != ERROR_PIPE_CONNECTED) {
                    windows.CloseHandle(write_handle);
                    windows.CloseHandle(read_handle);
                    return IPCError.ChannelInitFailed;
                }
            }

            // convert to std.fs.File
            self.write_fd = std.fs.File{ .handle = write_handle };
            self.read_fd = std.fs.File{ .handle = read_handle };

            // set pipe read mode to message
            var pipe_mode: u32 = PIPE_READMODE_MESSAGE;
            if (SetNamedPipeHandleState(read_handle, &pipe_mode, null, null) == 0) {
                return IPCError.ChannelInitFailed;
            }
        } else {
            // Unix FIFO (named pipe) implementation

            const read_path = try std.fmt.allocPrint(self.allocator, "{s}.read", .{pipe_path});
            defer self.allocator.free(read_path);

            const write_path = try std.fmt.allocPrint(self.allocator, "{s}.write", .{pipe_path});
            defer self.allocator.free(write_path);

            // create both read and write FIFOs
            const S_IRUSR = 0o400; // Read permission, owner
            const S_IWUSR = 0o200; // Write permission, owner

            // create read FIFO
            const read_path_z = try self.allocator.dupeZ(u8, read_path);
            defer self.allocator.free(read_path_z);
            mkfifo(read_path_z.ptr, S_IRUSR | S_IWUSR) catch |err| {
                if (err != error.AccessDenied) {
                    std.log.warn("Failed to create read FIFO: {}", .{err});
                }
            };

            // create write FIFO
            const write_path_z = try self.allocator.dupeZ(u8, write_path);
            defer self.allocator.free(write_path_z);
            mkfifo(write_path_z.ptr, S_IRUSR | S_IWUSR) catch |err| {
                if (err != error.AccessDenied) {
                    std.log.warn("Failed to create write FIFO: {}", .{err});
                }
            };

            // open both FIFOs with proper permissions
            self.read_fd = std.fs.openFileAbsolute(read_path, .{
                .mode = .read_only,
            }) catch |err| {
                std.log.err("Failed to open read FIFO: {}", .{err});
                return IPCError.ChannelInitFailed;
            };

            self.write_fd = std.fs.openFileAbsolute(write_path, .{
                .mode = .write_only,
            }) catch |err| {
                std.log.err("Failed to open write FIFO: {}", .{err});
                return IPCError.ChannelInitFailed;
            };

            // set non-blocking mode to avoid deadlocks
            if (builtin.os.tag == .linux) {
                const fd = self.read_fd.?.handle;
                const O_NONBLOCK = 0o4000;
                const current_flags = posix.fcntl(fd, posix.F.GETFL, 0) catch 0;
                _ = posix.fcntl(fd, posix.F.SETFL, current_flags | O_NONBLOCK) catch |err| {
                    std.log.warn("Failed to set non-blocking mode: {}", .{err});
                };
            }
        }
    }

    /// Initialize using TCP socket with proper hostname resolution and IPv6 support
    ///
    /// Creates a TCP socket connection with configurable performance options.
    /// Handles both IPv4 and IPv6 with automatic hostname resolution.
    /// Configures socket for optimal IPC performance (TCP_NODELAY, TCP_KEEPALIVE).
    ///
    /// Returns:
    ///   Error if connection fails or socket configuration fails
    fn initSocket(self: *IPCChannel) !void {
        if (self.config.path == null) {
            return IPCError.ChannelInitFailed;
        }

        // parse the address and port from path
        const addr_str = self.config.path.?;

        // split address:port format
        var split_iter = std.mem.splitScalar(u8, addr_str, ':');
        const hostname = split_iter.next() orelse return IPCError.ChannelInitFailed;
        const port_str = split_iter.next() orelse "8080"; // Default port if not specified

        // parse port
        const port = try std.fmt.parseInt(u16, port_str, 10);

        // connect with full hostname resolution (handles both IPv4 and IPv6)
        const server = try std.net.tcpConnectToHost(self.allocator, hostname, port);

        if (builtin.os.tag == .windows) {
            // Windows socket configuration
            const sock_handle = server.handle;
            const tcp_nodelay: c_int = 1;
            const tcp_keepalive: c_int = 1;
            
            if (@TypeOf(ws2_32) != void) {
                const raw_socket: ws2_32.SOCKET = @intFromPtr(sock_handle);
                _ = ws2_32.setsockopt(
                    raw_socket,
                    ws2_32.SOL_SOCKET,
                    ws2_32.SO_KEEPALIVE,
                    std.mem.asBytes(&tcp_keepalive),
                    @as(c_int, @sizeOf(c_int)),
                );
                _ = ws2_32.setsockopt(
                    raw_socket,
                    ws2_32.IPPROTO_TCP,
                    ws2_32.TCP_NODELAY,
                    std.mem.asBytes(&tcp_nodelay),
                    @as(c_int, @sizeOf(c_int)),
                );
            }
        } else {
            // Unix/Linux socket configuration
            const sock_handle = server.handle;
            const tcp_nodelay: c_int = 1;
            const tcp_keepalive: c_int = 1;
            
            _ = posix.setsockopt(
                sock_handle, 
                posix.SOL.SOCKET, 
                posix.SO.KEEPALIVE, 
                std.mem.asBytes(&tcp_keepalive)
            ) catch |err| {
                std.log.warn("Failed to set SO_KEEPALIVE: {}", .{err});
            };
            
            _ = posix.setsockopt(
                sock_handle, 
                posix.IPPROTO.TCP, 
                posix.TCP.NODELAY, 
                std.mem.asBytes(&tcp_nodelay)
            ) catch |err| {
                std.log.warn("Failed to set TCP_NODELAY: {}", .{err});
            };
        }

        self.socket = server;
    }

    /// Send a message through the IPC channel
    ///
    /// Serializes and transmits a message according to the configured format.
    /// Updates statistics and handles platform-specific transmission details.
    ///
    /// Parameters:
    ///   message: Message to send
    ///
    /// Returns:
    ///   Error if serialization or transmission fails
    pub fn sendMessage(self: *IPCChannel, message: *const Message) !void {
        if (!self.is_connected or self.writer == null) {
            return IPCError.Disconnected;
        }

        const use_socket = self.socket != null and self.socket_writer != null;
        const use_file = self.writer != null;

        if (!use_socket and !use_file) {
            return IPCError.Disconnected;
        }

        // update timestamp to now
        const local_message = Message{
            .header = msg.MessageHeader{
                .version = message.header.version,
                .sequence = message.header.sequence,
                .timestamp = std.time.microTimestamp(),
                .msg_type = message.header.msg_type,
                .payload_size = message.header.payload_size,
            },
            .payload = message.payload,
        };

        // serialize the message based on the configured format
        var bytes: []u8 = undefined;
        defer self.allocator.free(bytes);

        switch (self.config.serialization) {
            .Json => {
                bytes = try msg.toJson(&local_message, self.allocator);

                // for JSON, prepend the message length as a 4-byte integer
                var length_prefix = try self.allocator.alloc(u8, 4 + bytes.len);
                defer self.allocator.free(length_prefix);

                std.mem.writeInt(u32, length_prefix[0..4], @intCast(bytes.len), .little);
                @memcpy(length_prefix[4..][0..bytes.len], bytes);

                // write to the channel
                if (use_socket) {
                    _ = try self.socket_writer.?.writeAll(length_prefix);
                } else {
                    _ = try self.writer.?.writeAll(length_prefix);
                }
            },
            .Binary => {
                bytes = try msg.toBinary(message, self.allocator);

                // write directly to the channel
                if (use_socket) {
                    _ = try self.socket_writer.?.writeAll(bytes);
                } else {
                    _ = try self.writer.?.writeAll(bytes);
                }
            },
        }

        // update statistics
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += bytes.len;
        self.stats.last_activity = std.time.timestamp();
    }

    /// Receive a message from the IPC channel
    ///
    /// Reads and parses an incoming message according to the configured format.
    /// Handles partial reads and platform-specific reception details.
    /// Non-blocking behavior - returns null if no message is available.
    ///
    /// Returns:
    ///   Parsed message if available, null if no message ready, or error
    pub fn receiveMessage(self: *IPCChannel) !?Message {
        if (!self.is_connected or self.reader == null) {
            return IPCError.Disconnected;
        }

        const use_socket = self.socket != null and self.socket_reader != null;
        const use_file = self.reader != null;

        if (!use_socket and !use_file) {
            return IPCError.Disconnected;
        }

        // read based on the configured serialization format
        switch (self.config.serialization) {
            .Json => {
                // first read the 4-byte length prefix
                var length_buf: [4]u8 = undefined;
                const bytes_read = if (use_socket)
                    self.socket_reader.?.read(&length_buf) catch |err| {
                        if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                        return err;
                    }
                else
                    self.reader.?.read(&length_buf) catch |err| {
                        if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                        return err;
                    };

                if (bytes_read == 0) return null; // no data available
                if (bytes_read < 4) {
                    return IPCError.ReceiveFailed;
                }

                // parse the length
                const msg_len = std.mem.readInt(u32, &length_buf, .little);

                // ensure our buffer is large enough
                if (msg_len > self.read_buffer.len) {
                    return IPCError.BufferTooSmall;
                }

                var total_read: usize = 0;
                while (total_read < msg_len) {
                    const n = if (use_socket)
                        self.socket_reader.?.read(self.read_buffer[total_read..msg_len]) catch |err| {
                            if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                            return err;
                        }
                    else
                        self.reader.?.read(self.read_buffer[total_read..msg_len]) catch |err| {
                            if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                            return err;
                        };
                    if (n == 0) return null; // not enough data yet
                    total_read += n;
                }
                const json_bytes_read = total_read;

                if (json_bytes_read < msg_len) {
                    return IPCError.ReceiveFailed;
                }

                // parse the JSON
                const json_data = self.read_buffer[0..json_bytes_read];
                const result = try msg.fromJson(json_data, self.allocator);

                // update statistics
                self.stats.messages_received += 1;
                self.stats.bytes_received += json_bytes_read + 4; // include length prefix
                self.stats.last_activity = std.time.timestamp();

                return result;
            },
            .Binary => {
                // for binary format, we need a fixed-size header first
                const header_size = @sizeOf(msg.MessageHeader);
                const header_bytes_read = if (use_socket)
                    self.socket_reader.?.read(self.read_buffer[0..header_size]) catch |err| {
                        if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                        return err;
                    }
                else
                    self.reader.?.read(self.read_buffer[0..header_size]) catch |err| {
                        if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                        return err;
                    };

                if (header_bytes_read == 0) return null; // no data available
                if (header_bytes_read < header_size) {
                    return IPCError.ReceiveFailed;
                }

                // parse the header
                const header = @as(*const msg.MessageHeader, @ptrCast(@alignCast(&self.read_buffer[0])));

                // calculate total message size based on header
                const total_size = header_size + header.payload_size;

                if (total_size > self.read_buffer.len) {
                    return IPCError.BufferTooSmall;
                }

                // read the rest of the message
                const body_size = total_size - header_size;
                var total_read: usize = 0;
                while (total_read < body_size) {
                    const n = if (use_socket)
                        self.socket_reader.?.read(self.read_buffer[header_size + total_read .. header_size + body_size]) catch |err| {
                            if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                            return err;
                        }
                    else
                        self.reader.?.read(self.read_buffer[header_size + total_read .. header_size + body_size]) catch |err| {
                            if (err == error.WouldBlock or err == error.WouldBlockOrEof) return null;
                            return err;
                        };
                    if (n == 0) return null; // not enough data yet
                    total_read += n;
                }
                const body_bytes_read = total_read;
                if (body_bytes_read < body_size) {
                    return IPCError.ReceiveFailed;
                }

                // parse the binary message
                const message_data = self.read_buffer[0..total_size];
                const result = try msg.fromBinary(message_data, self.allocator);

                // update statistics
                self.stats.messages_received += 1;
                self.stats.bytes_received += total_size;
                self.stats.last_activity = std.time.timestamp();

                return result;
            },
        }
    }

    /// Send a message and wait for a response
    ///
    /// Convenience method for request-response patterns
    ///
    /// Parameters:
    ///   message: Message to send
    ///
    /// Returns:
    ///   Response message or error
    pub fn sendAndReceive(self: *IPCChannel, message: *const Message) !?Message {
        try self.sendMessage(message);
        return try self.receiveMessage();
    }

    /// Create and send a packet event
    ///
    /// Convenience method that handles message creation and sequence numbering
    ///
    /// Parameters:
    ///   event: Packet event data
    ///
    /// Returns:
    ///   Error if message creation or sending fails
    pub fn sendPacketEvent(self: *IPCChannel, event: msg.PacketEvent) !void {
        const message = msg.createPacketEventMsg(self.next_sequence, event);
        self.next_sequence += 1;
        try self.sendMessage(&message);
    }

    /// Create and send a Slig alert
    ///
    /// Convenience method that handles message creation and sequence numbering
    ///
    /// Parameters:
    ///   alert: Alert data
    ///
    /// Returns:
    ///   Error if message creation or sending fails
    pub fn sendSligAlert(self: *IPCChannel, alert: msg.SligAlert) !void {
        const message = msg.createSligAlertMsg(self.next_sequence, alert);
        self.next_sequence += 1;
        try self.sendMessage(&message);
    }

    /// Create and send a flow update
    ///
    /// Convenience method that handles message creation and sequence numbering
    ///
    /// Parameters:
    ///   flow: Flow update data
    ///
    /// Returns:
    ///   Error if message creation or sending fails
    pub fn sendFlowUpdate(self: *IPCChannel, flow: msg.FlowUpdate) !void {
        const message = msg.createFlowUpdateMsg(self.next_sequence, flow);
        self.next_sequence += 1;
        try self.sendMessage(&message);
    }

    /// Close the IPC channel and free resources
    ///
    /// Properly cleans up all resources and handles platform-specific cleanup
    pub fn deinit(self: *IPCChannel) void {
        // close file descriptors if open
        if (self.read_fd) |fd| {
            fd.close();
        }

        if (self.write_fd) |fd| {
            if (self.config.channel_type != .StdIO) {
                fd.close();
            } else if (self.read_fd) |read_fd| {
                if (!std.meta.eql(read_fd, fd)) {
                    fd.close();
                }
            }
        }

        // free the read buffer
        if (self.read_buffer.len > 0) {
            self.allocator.free(self.read_buffer);
        }

        if (self.socket) |socket| {
            socket.close();
        }

        // destroy the channel itself
        self.allocator.destroy(self);
    }

    /// Get the current channel statistics
    ///
    /// Provides metrics about channel usage for monitoring and debugging
    ///
    /// Returns:
    ///   Current statistics snapshot
    pub fn getStats(self: *const IPCChannel) ChannelStats {
        return self.stats;
    }

    /// Check if the channel is connected and active
    ///
    /// A channel is considered inactive if no messages have been
    /// sent or received within the last 30 seconds
    ///
    /// Returns:
    ///   true if channel is connected and recently active
    pub fn isActive(self: *const IPCChannel) bool {
        if (!self.is_connected) {
            return false;
        }

        // consider inactive if no activity for 30 seconds
        const now = std.time.timestamp();
        const inactivity_period = now - self.stats.last_activity;
        const MAX_INACTIVITY_SEC = 30;

        return inactivity_period < MAX_INACTIVITY_SEC;
    }
};

/// High-level IPC server that handles multiple client connections
pub const IPCServer = struct {
    allocator: Allocator, // memory allocator for server resources
    clients: std.ArrayList(*IPCChannel), // list of connected client channels
    is_running: bool = false, // whether server is actively accepting connections
    server_thread: ?Thread = null, // thread handling incoming connections

    /// Initialize a new IPC server
    ///
    /// Creates a server instance that can handle multiple client connections
    ///
    /// Parameters:
    ///   allocator: Memory allocator for server resources
    ///
    /// Returns:
    ///   Pointer to initialized server or error
    pub fn init(allocator: Allocator) !*IPCServer {
        const server = try allocator.create(IPCServer);
        server.* = IPCServer{
            .allocator = allocator,
            .clients = std.ArrayList(*IPCChannel).init(allocator),
        };
        return server;
    }

    /// Add a client connection to the server
    ///
    /// Registers a new client channel with the server for message broadcasting
    ///
    /// Parameters:
    ///   client: Client channel to add
    ///
    /// Returns:
    ///   Error if adding client fails
    pub fn addClient(self: *IPCServer, client: *IPCChannel) !void {
        try self.clients.append(client);
    }

    /// Broadcast a message to all connected clients
    ///
    /// Sends the same message to all active clients, automatically
    /// handling disconnected clients through garbage collection
    ///
    /// Parameters:
    ///   message: Message to broadcast to all clients
    ///
    /// Returns:
    ///   Error if broadcast fails (individual client failures are logged but not fatal)
    pub fn broadcast(self: *IPCServer, message: *const Message) !void {
        // remove disconnected clients first
        var i: usize = 0;
        while (i < self.clients.items.len) {
            if (!self.clients.items[i].isActive()) {
                const client = self.clients.items[i];
                _ = self.clients.swapRemove(i);
                client.deinit(); // clean up the client
            } else {
                i += 1;
            }
        }

        // send to all remaining clients
        for (self.clients.items) |client| {
            client.sendMessage(message) catch |err| {
                std.log.err("Failed to send message to client: {}", .{err});
                // continue sending to other clients
            };
        }
    }

    /// Clean up all resources associated with the server
    ///
    /// Stops the server thread and closes all client connections
    pub fn deinit(self: *IPCServer) void {
        self.is_running = false;

        // wait for server thread to terminate if it exists
        if (self.server_thread) |thread| {
            thread.join();
        }

        // close all client connections
        for (self.clients.items) |client| {
            client.deinit();
        }

        self.clients.deinit();
        self.allocator.destroy(self);
    }
};

/// Create a default IPC configuration suitable for most use cases
///
/// Returns a configuration using StdIO and JSON serialization
///
/// Returns:
///   Default configuration instance
pub fn createDefaultConfig() IPCConfig {
    return IPCConfig{
        .channel_type = .StdIO,
        .serialization = .Json,
        .buffer_size = 65536, // 64KB
    };
}

/// Create a named pipe configuration with custom settings
///
/// Helper function for creating a named pipe configuration
/// with specified path and serialization format
///
/// Parameters:
///   pipe_path: Path or name for the named pipe
///   serialization: Serialization format to use
///
/// Returns:
///   Configured named pipe IPC configuration
pub fn createNamedPipeConfig(pipe_path: []const u8, serialization: SerializationFormat) IPCConfig {
    return IPCConfig{
        .channel_type = .NamedPipe,
        .serialization = serialization,
        .path = pipe_path,
        .buffer_size = 1024 * 1024, // 1MB
    };
}
