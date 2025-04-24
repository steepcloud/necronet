const std = @import("std");
const os = std.os;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const windows = std.os.windows;
const builtin = @import("builtin");

const msg = @import("messages");
const Message = msg.Message;

/// Error types that can occur during IPC operations
pub const IPCError = error{
    ChannelInitFailed,
    SendFailed,
    ReceiveFailed,
    Disconnected,
    InvalidMessage,
    BufferTooSmall,
    OperationTimedOut,
};

/// Message serialization format options
pub const SerializationFormat = enum {
    Json,
    Binary,
};

/// Options for how the IPC channel connects processes
pub const ChannelType = enum {
    StdIO,      // Standard input/output for parent/child processes
    NamedPipe,  // Named pipes (Windows) or FIFOs (Unix)
    Socket,     // TCP socket for network communication
};

/// Configuration for IPC channel
pub const IPCConfig = struct {
    channel_type: ChannelType = .StdIO,
    serialization: SerializationFormat = .Json,
    path: ?[]const u8 = null,         // Path for named pipe, or address for socket
    buffer_size: usize = 65536,       // Default read buffer size (64KB)
    timeout_ms: u32 = 5000,           // Default timeout in milliseconds
    retry_count: u32 = 3,             // Number of retries for failed operations
};

/// Statistics about IPC channel usage
pub const ChannelStats = struct {
    messages_sent: u64 = 0,
    messages_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    send_errors: u32 = 0,
    receive_errors: u32 = 0,
    last_activity: i64 = 0,           // Timestamp of last activity
};

/// IPC Channel for Slig communication
pub const IPCChannel = struct {
    allocator: Allocator,
    config: IPCConfig,
    stats: ChannelStats = .{},
    is_connected: bool = false,
    next_sequence: u64 = 1,
    read_buffer: []u8 = &[_]u8{},
    
    // File descriptors/handles for I/O
    read_fd: ?std.fs.File = null,
    write_fd: ?std.fs.File = null,
    
    // Reader/writer
    reader: ?std.io.Reader(std.fs.File, std.fs.File.ReadError, std.fs.File.read) = null,
    writer: ?std.io.Writer(std.fs.File, std.fs.File.WriteError, std.fs.File.write) = null,
    
    /// Initialize a new IPC channel
    pub fn init(allocator: Allocator, config: IPCConfig) !*IPCChannel {
        var channel = try allocator.create(IPCChannel);
        errdefer allocator.destroy(channel);
        
        channel.* = IPCChannel{
            .allocator = allocator,
            .config = config,
        };
        
        // Allocate read buffer
        channel.read_buffer = try allocator.alloc(u8, config.buffer_size);
        errdefer allocator.free(channel.read_buffer);
        
        // Initialize channel based on the selected type
        switch (config.channel_type) {
            .StdIO => try channel.initStdIO(),
            .NamedPipe => try channel.initNamedPipe(),
            .Socket => try channel.initSocket(),
        }
        
        // Initialize the reader/writer
        if (channel.read_fd != null) {
            channel.reader = channel.read_fd.?.reader();
        }
        
        if (channel.write_fd != null) {
            channel.writer = channel.write_fd.?.writer();
        }
        
        channel.is_connected = true;
        channel.stats.last_activity = std.time.timestamp();
        return channel;
    }
    
    /// Initialize using standard input/output
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
    fn initNamedPipe(self: *IPCChannel) !void {
        if (self.config.path == null) {
            return IPCError.ChannelInitFailed;
        }
        
        const pipe_path = self.config.path.?;
        
        if (builtin.os.tag == .windows) {
            // Windows named pipes with full production robustness
            const pipe_name = try std.fmt.allocPrint(
                self.allocator,
                "\\\\.\\pipe\\{s}",
                .{pipe_path}
            );
            defer self.allocator.free(pipe_name);

            const read_pipe_name = try std.fmt.allocPrint(
                self.allocator, 
                "\\\\.\\pipe\\{s}-read", 
                .{pipe_path}
            );
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

            // Create write pipe (server mode)
            const write_handle = windows.CreateNamedPipeW(
                windows.utf8ToWide(pipe_name) catch return IPCError.ChannelInitFailed,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                null
            );

            if (write_handle == windows.INVALID_HANDLE_VALUE) {
                return IPCError.ChannelInitFailed;
            }

            // Connect to read pipe (client mode)
            const read_handle = windows.CreateFileW(
                windows.utf8ToWide(read_pipe_name) catch {
                    windows.CloseHandle(write_handle);
                    return IPCError.ChannelInitFailed;
                },
                GENERIC_READ | GENERIC_WRITE,
                0,
                null,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null
            );

            if (read_handle == windows.INVALID_HANDLE_VALUE) {
                windows.CloseHandle(write_handle);
                return IPCError.ChannelInitFailed;
            }

            // Wait for client connection
            if (!windows.ConnectNamedPipe(write_handle, null)) {
                const last_error = windows.GetLastError();
                if (last_error != windows.ERROR_PIPE_CONNECTED) {
                    windows.CloseHandle(write_handle);
                    windows.CloseHandle(read_handle);
                    return IPCError.ChannelInitFailed;
                }
            }

            // Convert to std.fs.File
            self.write_fd = std.fs.File{ .handle = write_handle };
            self.read_fd = std.fs.File{ .handle = read_handle };

            // Set pipe read mode to message
            var pipe_mode: u32 = PIPE_READMODE_MESSAGE;
            if (windows.SetNamedPipeHandleState(
                read_handle,
                &pipe_mode,
                null,
                null
            ) == 0) {
                return IPCError.ChannelInitFailed;
            }
        } else {
            // Unix FIFO (named pipe) implementation
            
            const read_path = try std.fmt.allocPrint(
                self.allocator, 
                "{s}.read", 
                .{pipe_path}
            );
            defer self.allocator.free(read_path);

            const write_path = try std.fmt.allocPrint(
                self.allocator, 
                "{s}.write", 
                .{pipe_path}
            );
            defer self.allocator.free(write_path);

            // Create both read and write FIFOs
            const S_IRUSR = 0o400;  // Read permission, owner
            const S_IWUSR = 0o200;  // Write permission, owner

            // Create read FIFO
            _ = os.mkfifo(read_path.ptr, S_IRUSR | S_IWUSR) catch |err| {
                if (err != error.PathAlreadyExists) {
                    return IPCError.ChannelInitFailed;
                }
            };

            // Create write FIFO
            _ = os.mkfifo(write_path.ptr, S_IRUSR | S_IWUSR) catch |err| {
                if (err != error.PathAlreadyExists) {
                    return IPCError.ChannelInitFailed;
                }
            };

            // Open both FIFOs with proper permissions
            self.read_fd = try std.fs.openFileAbsolute(read_path, .{
                .read = true,
                .write = false,
                .mode = .read_only,
            });

            self.write_fd = try std.fs.openFileAbsolute(write_path, .{
                .read = false,
                .write = true, 
                .mode = .write_only,
            });

            // Set non-blocking mode to avoid deadlocks
            try self.read_fd.?.setNonBlocking(true);
        }
    }
    
    /// Initialize using TCP socket with proper hostname resolution and IPv6 support
    fn initSocket(self: *IPCChannel) !void {
        if (self.config.path == null) {
            return IPCError.ChannelInitFailed;
        }
        
        // Parse the address and port from path
        const addr_str = self.config.path.?;
        
        // Split address:port format
        var split_iter = std.mem.split(u8, addr_str, ":");
        const hostname = split_iter.next() orelse return IPCError.ChannelInitFailed;
        const port_str = split_iter.next() orelse "8080"; // Default port if not specified
        
        // Parse port
        const port = try std.fmt.parseInt(u16, port_str, 10);
        
        // Connect with full hostname resolution (handles both IPv4 and IPv6)
        var server = try std.net.tcpConnectToHost(self.allocator, hostname, port);
        
        // Set socket options for better performance
        try server.setNoDelay(true); // Disable Nagle's algorithm
        try server.setTcpKeepAlive(true);
        
        self.read_fd = server;
        self.write_fd = server;
    }
    
    /// Send a message through the IPC channel
    pub fn sendMessage(self: *IPCChannel, message: *const Message) !void {
        if (!self.is_connected or self.writer == null) {
            return IPCError.Disconnected;
        }
        
        // Update timestamp to now
        message.header.timestamp = std.time.microTimestamp();
        
        // Serialize the message based on the configured format
        var bytes: []u8 = undefined;
        defer self.allocator.free(bytes);
        
        switch (self.config.serialization) {
            .Json => {
                bytes = try msg.toJson(message, self.allocator);
                
                // For JSON, prepend the message length as a 4-byte integer
                var length_prefix = try self.allocator.alloc(u8, 4 + bytes.len);
                defer self.allocator.free(length_prefix);
                
                std.mem.writeIntNative(u32, length_prefix[0..4], @intCast(bytes.len));
                std.mem.copy(u8, length_prefix[4..], bytes);
                
                // Write to the channel
                _ = try self.writer.?.writeAll(length_prefix);
            },
            .Binary => {
                bytes = try msg.toBinary(message, self.allocator);
                
                // Write directly to the channel
                _ = try self.writer.?.writeAll(bytes);
            },
        }
        
        // Update statistics
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += bytes.len;
        self.stats.last_activity = std.time.timestamp();
    }
    
    /// Receive a message from the IPC channel
    pub fn receiveMessage(self: *IPCChannel) !?Message {
        if (!self.is_connected or self.reader == null) {
            return IPCError.Disconnected;
        }
        
        // Read based on the configured serialization format
        switch (self.config.serialization) {
            .Json => {
                // First read the 4-byte length prefix
                var length_buf: [4]u8 = undefined;
                const bytes_read = try self.reader.?.readAll(&length_buf);
                
                if (bytes_read < 4) {
                    return IPCError.ReceiveFailed;
                }
                
                // Parse the length
                const msg_len = std.mem.readIntNative(u32, &length_buf);
                
                // Ensure our buffer is large enough
                if (msg_len > self.read_buffer.len) {
                    return IPCError.BufferTooSmall;
                }
                
                // Read the JSON message
                const json_bytes_read = try self.reader.?.readAll(self.read_buffer[0..msg_len]);
                
                if (json_bytes_read < msg_len) {
                    return IPCError.ReceiveFailed;
                }
                
                // Parse the JSON
                const json_data = self.read_buffer[0..json_bytes_read];
                const result = try msg.fromJson(json_data, self.allocator);
                
                // Update statistics
                self.stats.messages_received += 1;
                self.stats.bytes_received += json_bytes_read + 4; // Include length prefix
                self.stats.last_activity = std.time.timestamp();
                
                return result;
            },
            .Binary => {
                // For binary format, we need a fixed-size header first
                const header_size = @sizeOf(msg.MessageHeader);
                const header_bytes_read = try self.reader.?.readAll(self.read_buffer[0..header_size]);
                
                if (header_bytes_read < header_size) {
                    return IPCError.ReceiveFailed;
                }
                
                // Parse the header
                const header = @as(*const msg.MessageHeader, @ptrCast(&self.read_buffer[0]));
                
                // Calculate total message size based on header
                const total_size = header_size + header.payload_size;
                
                if (total_size > self.read_buffer.len) {
                    return IPCError.BufferTooSmall;
                }
                
                // Read the rest of the message
                const body_size = total_size - header_size;
                const body_bytes_read = try self.reader.?.readAll(
                    self.read_buffer[header_size..total_size]
                );
                
                if (body_bytes_read < body_size) {
                    return IPCError.ReceiveFailed;
                }
                
                // Parse the binary message
                const message_data = self.read_buffer[0..total_size];
                const result = try msg.fromBinary(message_data, self.allocator);
                
                // Update statistics
                self.stats.messages_received += 1;
                self.stats.bytes_received += total_size;
                self.stats.last_activity = std.time.timestamp();
                
                return result;
            }
        }
    }
    
    /// Send a message and wait for a response
    pub fn sendAndReceive(self: *IPCChannel, message: *const Message) !?Message {
        try self.sendMessage(message);
        return try self.receiveMessage();
    }
    
    /// Create and send a packet event
    pub fn sendPacketEvent(self: *IPCChannel, event: msg.PacketEvent) !void {
        const message = msg.createPacketEventMsg(self.next_sequence, event);
        self.next_sequence += 1;
        try self.sendMessage(&message);
    }
    
    /// Create and send a Slig alert
    pub fn sendSligAlert(self: *IPCChannel, alert: msg.SligAlert) !void {
        const message = msg.createSligAlertMsg(self.next_sequence, alert);
        self.next_sequence += 1;
        try self.sendMessage(&message);
    }
    
    /// Create and send a flow update
    pub fn sendFlowUpdate(self: *IPCChannel, flow: msg.FlowUpdate) !void {
        const message = msg.createFlowUpdateMsg(self.next_sequence, flow);
        self.next_sequence += 1;
        try self.sendMessage(&message);
    }
    
    /// Close the IPC channel and free resources
    pub fn deinit(self: *IPCChannel) void {
        // Close file descriptors if open
        if (self.read_fd) |fd| {
            fd.close();
        }
        
        if (self.write_fd) |fd| {
            if (self.config.channel_type != .StdIO or self.read_fd != self.write_fd) {
                fd.close();
            }
        }
        
        // Free the read buffer
        if (self.read_buffer.len > 0) {
            self.allocator.free(self.read_buffer);
        }
        
        // Destroy the channel itself
        self.allocator.destroy(self);
    }
    
    /// Get the current channel statistics
    pub fn getStats(self: *const IPCChannel) ChannelStats {
        return self.stats;
    }
    
    /// Check if the channel is connected and active
    pub fn isActive(self: *const IPCChannel) bool {
        if (!self.is_connected) {
            return false;
        }
        
        // Consider inactive if no activity for 30 seconds
        const now = std.time.timestamp();
        const inactivity_period = now - self.stats.last_activity;
        const MAX_INACTIVITY_SEC = 30;
        
        return inactivity_period < MAX_INACTIVITY_SEC;
    }
};

/// High-level IPC server that handles multiple client connections
pub const IPCServer = struct {
    allocator: Allocator,
    clients: std.ArrayList(*IPCChannel),
    is_running: bool = false,
    server_thread: ?Thread = null,
    
    /// Initialize a new IPC server
    pub fn init(allocator: Allocator) !*IPCServer {
        const server = try allocator.create(IPCServer);
        server.* = IPCServer{
            .allocator = allocator,
            .clients = std.ArrayList(*IPCChannel).init(allocator),
        };
        return server;
    }
    
    /// Add a client connection to the server
    pub fn addClient(self: *IPCServer, client: *IPCChannel) !void {
        try self.clients.append(client);
    }
    
    /// Broadcast a message to all connected clients
    pub fn broadcast(self: *IPCServer, message: *const Message) !void {
        // Remove disconnected clients first
        var i: usize = 0;
        while (i < self.clients.items.len) {
            if (!self.clients.items[i].isActive()) {
                const client = self.clients.items[i];
                _ = self.clients.swapRemove(i);
                client.deinit(); // Clean up the client
            } else {
                i += 1;
            }
        }
        
        // Send to all remaining clients
        for (self.clients.items) |client| {
            client.sendMessage(message) catch |err| {
                std.log.err("Failed to send message to client: {}", .{err});
                // Continue sending to other clients
            };
        }
    }
    
    /// Clean up all resources associated with the server
    pub fn deinit(self: *IPCServer) void {
        self.is_running = false;
        
        // Wait for server thread to terminate if it exists
        if (self.server_thread) |thread| {
            thread.join();
        }
        
        // Close all client connections
        for (self.clients.items) |client| {
            client.deinit();
        }
        
        self.clients.deinit();
        self.allocator.destroy(self);
    }
};

/// Create a default IPC configuration suitable for most use cases
pub fn createDefaultConfig() IPCConfig {
    return IPCConfig{
        .channel_type = .StdIO,
        .serialization = .Json,
        .buffer_size = 65536, // 64KB
    };
}

/// Create a named pipe configuration with custom settings
pub fn createNamedPipeConfig(pipe_path: []const u8, serialization: SerializationFormat) IPCConfig {
    return IPCConfig{
        .channel_type = .NamedPipe,
        .serialization = serialization,
        .path = pipe_path,
        .buffer_size = 1024 * 1024, // 1MB
    };
}