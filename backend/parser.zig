const std = @import("std");
const capture = @import("capture.zig");
const common = @import("common");
const Allocator = std.mem.Allocator;

pub const ParseError = error{
    InvalidFormat,
    UnsupportedProtocol,
    InsufficientData,
    MalformedPacket,
};

/// Base protocol parser interface
pub const ProtocolParser = struct {
    // Function pointers for virtual methods
    parseFn: *const fn(self: *ProtocolParser, data: []const u8) ParseError!void,
    resetFn: *const fn(self: *ProtocolParser) void,
    deinitFn: *const fn(self: *ProtocolParser, allocator: Allocator) void,
    
    // Parse incoming data
    pub fn parse(self: *ProtocolParser, data: []const u8) ParseError!void {
        return self.parseFn(self, data);
    }
    
    // Reset parser state
    pub fn reset(self: *ProtocolParser) void {
        return self.resetFn(self);
    }
    
    // Free resources
    pub fn deinit(self: *ProtocolParser, allocator: Allocator) void {
        return self.deinitFn(self, allocator);
    }
};

/// HTTP protocol parser
pub const HttpParser = struct {
    base: ProtocolParser,
    allocator: Allocator,
    state: HttpParseState,
    method: []u8,
    uri: []u8,
    headers: std.StringHashMap([]u8),
    header_count: usize,
    body_length: usize,
    is_request: bool,
    
    pub const HttpParseState = enum {
        StartLine,
        Headers,
        Body,
        Complete,
        Error,
    };
    
    pub fn init(allocator: Allocator) !*HttpParser {
        const parser = try allocator.create(HttpParser);
        parser.* = HttpParser{
            .base = ProtocolParser{
                .parseFn = parse,
                .resetFn = reset,
                .deinitFn = deinit,
            },
            .allocator = allocator,
            .state = .StartLine,
            .method = &[_]u8{},
            .uri = &[_]u8{},
            .headers = std.StringHashMap([]u8).init(allocator),
            .header_count = 0,
            .body_length = 0,
            .is_request = true,
        };
        return parser;
    }
    
    fn parse(base: *ProtocolParser, data: []const u8) ParseError!void {
        const self: *HttpParser = @fieldParentPtr("base", base);
        
        // Basic HTTP parsing logic
        var i: usize = 0;
        while (i < data.len) {
            switch (self.state) {
                .StartLine => {
                    // Find end of start line (request or response)
                    const line_end = std.mem.indexOfScalarPos(u8, data, i, '\n') orelse {
                        return ParseError.InsufficientData;
                    };
                    
                    // Parse the start line (GET /path HTTP/1.1 or HTTP/1.1 200 OK)
                    const line = data[i..line_end];
                    if (line.len > 0) {
                        if (std.mem.startsWith(u8, line, "HTTP/")) {
                            self.is_request = false;
                            // Response parsing logic would go here
                        } else {
                            self.is_request = true;
                            // Request parsing logic - extract method and URI
                            const space1 = std.mem.indexOfScalar(u8, line, ' ') orelse {
                                return ParseError.MalformedPacket;
                            };
                            const method = line[0..space1];
                            self.method = try self.allocator.dupe(u8, method);
                            
                            const remaining = line[space1 + 1 ..];
                            const space2 = std.mem.indexOfScalar(u8, remaining, ' ') orelse {
                                return ParseError.MalformedPacket;
                            };
                            const uri = remaining[0..space2];
                            self.uri = try self.allocator.dupe(u8, uri);
                        }
                    }
                    
                    i = line_end + 1;
                    self.state = .Headers;
                },
                
                .Headers => {
                    // Header parsing logic
                    const line_end = std.mem.indexOfScalarPos(u8, data, i, '\n') orelse {
                        return ParseError.InsufficientData;
                    };
                    
                    const line = data[i..line_end];
                    if (line.len == 0 or (line.len == 1 and line[0] == '\r')) {
                        // Empty line - end of headers
                        i = line_end + 1;
                        self.state = .Body;
                    } else {
                        // Parse header
                        const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
                            return ParseError.MalformedPacket;
                        };
                        
                        var name = line[0..colon];
                        if (name.len > 0 and name[name.len - 1] == '\r') {
                            name = name[0 .. name.len - 1];
                        }
                        
                        var value = line[colon + 1 ..];
                        if (value.len > 0 and value[0] == ' ') {
                            value = value[1..];
                        }
                        if (value.len > 0 and value[value.len - 1] == '\r') {
                            value = value[0 .. value.len - 1];
                        }
                        
                        const name_owned = try self.allocator.dupe(u8, name);
                        const value_owned = try self.allocator.dupe(u8, value);
                        try self.headers.put(name_owned, value_owned);
                        self.header_count += 1;
                        
                        // Check for Content-Length
                        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                            self.body_length = std.fmt.parseInt(usize, value, 10) catch 0;
                        }
                        
                        i = line_end + 1;
                    }
                },
                
                .Body => {
                    // Body processing would go here
                    // For now, just move to complete state
                    self.state = .Complete;
                    break;
                },
                
                .Complete, .Error => {
                    break;
                },
            }
        }
    }
    
    fn reset(base: *ProtocolParser) void {
        const self: *HttpParser = @fieldParentPtr( "base", base);
        self.state = .StartLine;
        
        // Free old data
        if (self.method.len > 0) {
            self.allocator.free(self.method);
            self.method = &[_]u8{};
        }
        
        if (self.uri.len > 0) {
            self.allocator.free(self.uri);
            self.uri = &[_]u8{};
        }
        
        // Free headers
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.clearRetainingCapacity();
        self.header_count = 0;
        self.body_length = 0;
    }
    
    fn deinit(base: *ProtocolParser, allocator: Allocator) void {
        const self: *HttpParser = @fieldParentPtr("base", base);
        self.reset(&self.base);
        self.headers.deinit();
        allocator.destroy(self);
    }
};

/// DNS protocol parser
pub const DnsParser = struct {
    base: ProtocolParser,
    allocator: Allocator,
    transaction_id: u16,
    is_query: bool,
    query_count: u16,
    answer_count: u16,
    questions: std.ArrayList(DnsQuestion),
    answers: std.ArrayList(DnsAnswer),
    
    pub const DnsQuestion = struct {
        name: []u8,
        type: u16,
        class: u16,
    };
    
    pub const DnsAnswer = struct {
        name: []u8,
        type: u16,
        class: u16,
        ttl: u32,
        data: []u8,
    };
    
    pub fn init(allocator: Allocator) !*DnsParser {
        const parser = try allocator.create(DnsParser);
        parser.* = DnsParser{
            .base = ProtocolParser{
                .parseFn = parse,
                .resetFn = reset,
                .deinitFn = deinit,
            },
            .allocator = allocator,
            .transaction_id = 0,
            .is_query = false,
            .query_count = 0,
            .answer_count = 0,
            .questions = std.ArrayList(DnsQuestion).init(allocator),
            .answers = std.ArrayList(DnsAnswer).init(allocator),
        };
        return parser;
    }
    
    fn parse(base: *ProtocolParser, data: []const u8) ParseError!void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        
        // DNS requires at least 12 bytes for header
        if (data.len < 12) {
            return ParseError.InsufficientData;
        }
        
        // Parse DNS header
        self.transaction_id = ((@as(u16, data[0]) << 8) | @as(u16, data[1]));
        const flags = ((@as(u16, data[2]) << 8) | @as(u16, data[3]));
        self.is_query = (flags & 0x8000) == 0;
        self.query_count = ((@as(u16, data[4]) << 8) | @as(u16, data[5]));
        self.answer_count = ((@as(u16, data[6]) << 8) | @as(u16, data[7]));
        
        // DNS parsing would continue here...
        // For now this is just a basic demonstration
    }
    
    fn reset(base: *ProtocolParser) void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        
        // Clear questions
        for (self.questions.items) |question| {
            self.allocator.free(question.name);
        }
        self.questions.clearRetainingCapacity();
        
        // Clear answers
        for (self.answers.items) |answer| {
            self.allocator.free(answer.name);
            self.allocator.free(answer.data);
        }
        self.answers.clearRetainingCapacity();
        
        self.transaction_id = 0;
        self.is_query = false;
        self.query_count = 0;
        self.answer_count = 0;
    }
    
    fn deinit(base: *ProtocolParser, allocator: Allocator) void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        self.reset(&self.base);
        self.questions.deinit();
        self.answers.deinit();
        allocator.destroy(self);
    }
};

/// Creates a parser appropriate for the given protocol
pub fn createParser(allocator: Allocator, protocol: common.Protocol, dest_port: u16) !?*ProtocolParser {
    switch (protocol) {
        .TCP => {
            // Choose parser based on port number
            switch (dest_port) {
                80, 8080 => {
                    const http_parser = try HttpParser.init(allocator);
                    return &http_parser.base;
                },
                53 => {
                    const dns_parser = try DnsParser.init(allocator);
                    return &dns_parser.base;
                },
                else => return null,
            }
        },
        .UDP => {
            if (dest_port == 53) {
                const dns_parser = try DnsParser.init(allocator);
                return &dns_parser.base;
            }
            return null;
        },
        else => return null,
    }
}

/// Parses a packet and returns the appropriate parser with parsed data
pub fn parsePacket(allocator: Allocator, packet: capture.PacketInfo, data: []const u8) !?*ProtocolParser {
    // Create appropriate parser for the protocol/port
    var parser = try createParser(allocator, packet.protocol, packet.dest_port);
    if (parser == null) {
        return null;
    }
    
    // If we have payload data, try to parse it
    if (packet.payload) |payload| {
        try parser.?.parse(payload);
    } else if (data.len > 0) {
        try parser.?.parse(data);
    }
    
    return parser;
}