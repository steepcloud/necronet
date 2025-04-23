const std = @import("std");
const capture = @import("backend");
const common = @import("common");
const Allocator = std.mem.Allocator;

pub const ParseError = error{
    InvalidFormat,
    UnsupportedProtocol,
    InsufficientData,
    MalformedPacket,
    OutOfMemory,
};

/// Base protocol parser interface
pub const ProtocolParser = struct {
    parseFn: *const fn(self: *ProtocolParser, data: []const u8) ParseError!void,
    resetFn: *const fn(self: *ProtocolParser) void,
    deinitFn: *const fn(self: *ProtocolParser, allocator: Allocator) void,

    pub fn parse(self: *ProtocolParser, data: []const u8) ParseError!void {
        return self.parseFn(self, data);
    }
    pub fn reset(self: *ProtocolParser) void {
        return self.resetFn(self);
    }
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
    version: []u8,
    status_code: []u8,
    reason_phrase: []u8,
    headers: std.StringHashMap([]u8),
    header_count: usize,
    body_length: usize,
    is_request: bool,
    body: []u8,

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
            .version = &[_]u8{},
            .status_code = &[_]u8{},
            .reason_phrase = &[_]u8{},
            .headers = std.StringHashMap([]u8).init(allocator),
            .header_count = 0,
            .body_length = 0,
            .is_request = true,
            .body = &[_]u8{},
        };
        return parser;
    }

    fn parse(base: *ProtocolParser, data: []const u8) ParseError!void {
        const self: *HttpParser = @fieldParentPtr("base", base);
        var i: usize = 0;
        while (i < data.len) {
            switch (self.state) {
                .StartLine => {
                    const line_end = std.mem.indexOfScalarPos(u8, data, i, '\n') orelse return ParseError.InsufficientData;
                    const line = data[i..line_end];
                    if (line.len > 0) {
                        if (std.mem.startsWith(u8, line, "HTTP/")) {
                            // Parse HTTP response: HTTP/1.1 200 OK
                            self.is_request = false;
                            var parts = std.mem.splitScalar(u8, line, ' ');
                            const version = parts.next() orelse return ParseError.MalformedPacket;
                            const status_code = parts.next() orelse return ParseError.MalformedPacket;
                            const reason_phrase = parts.next() orelse return ParseError.MalformedPacket;
                            self.version = try self.allocator.dupe(u8, version);
                            self.status_code = try self.allocator.dupe(u8, status_code);
                            self.reason_phrase = try self.allocator.dupe(u8, reason_phrase);
                            self.method = &[_]u8{};
                            self.uri = &[_]u8{};
                        } else {
                            // Parse HTTP request: GET /path HTTP/1.1
                            self.is_request = true;
                            var parts = std.mem.splitScalar(u8, line, ' ');
                            const method = parts.next() orelse return ParseError.MalformedPacket;
                            const uri = parts.next() orelse return ParseError.MalformedPacket;
                            const version = parts.next() orelse return ParseError.MalformedPacket;
                            self.method = try self.allocator.dupe(u8, method);
                            self.uri = try self.allocator.dupe(u8, uri);
                            self.version = try self.allocator.dupe(u8, version);
                            self.status_code = &[_]u8{};
                            self.reason_phrase = &[_]u8{};
                        }
                    }
                    i = line_end + 1;
                    self.state = .Headers;
                },
                .Headers => {
                    const line_end = std.mem.indexOfScalarPos(u8, data, i, '\n') orelse return ParseError.InsufficientData;
                    const line = data[i..line_end];
                    if (line.len == 0 or (line.len == 1 and line[0] == '\r')) {
                        i = line_end + 1;
                        self.state = .Body;
                    } else {
                        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return ParseError.MalformedPacket;
                        var name = line[0..colon];
                        if (name.len > 0 and name[name.len - 1] == '\r') name = name[0 .. name.len - 1];
                        var value = line[colon + 1 ..];
                        if (value.len > 0 and value[0] == ' ') value = value[1..];
                        if (value.len > 0 and value[value.len - 1] == '\r') value = value[0 .. value.len - 1];
                        const name_owned = try self.allocator.dupe(u8, name);
                        const value_owned = try self.allocator.dupe(u8, value);
                        try self.headers.put(name_owned, value_owned);
                        self.header_count += 1;
                        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                            self.body_length = std.fmt.parseInt(usize, value, 10) catch 0;
                        }
                        i = line_end + 1;
                    }
                },
                .Body => {
                    if (self.body_length > 0 and (data.len - i) >= self.body_length) {
                        self.body = try self.allocator.dupe(u8, data[i .. i + self.body_length]);
                        self.state = .Complete;
                        i += self.body_length;
                    } else {
                        self.state = .Complete;
                        break;
                    }
                },
                .Complete, .Error => break,
            }
        }
    }

    fn reset(base: *ProtocolParser) void {
        const self: *HttpParser = @fieldParentPtr("base", base);
        self.state = .StartLine;
        if (self.method.len > 0) self.allocator.free(self.method);
        if (self.uri.len > 0) self.allocator.free(self.uri);
        if (self.version.len > 0) self.allocator.free(self.version);
        if (self.body.len > 0) self.allocator.free(self.body);
        self.method = &[_]u8{};
        self.uri = &[_]u8{};
        self.version = &[_]u8{};
        self.status_code = &[_]u8{};
        self.reason_phrase = &[_]u8{};
        self.body = &[_]u8{};
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
        reset(&self.base);
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

    fn parseName(self: *DnsParser, data: []const u8, offset_ptr: *usize, depth: usize) ParseError![]u8 {
        if (depth > 10) return ParseError.MalformedPacket; // Prevent infinite loops
        var name_buf = std.ArrayList(u8).init(self.allocator);
        defer name_buf.deinit();

        var offset = offset_ptr.*;
        var jumped = false;
        var jump_offset: usize = 0;

        while (offset < data.len) {
            const len = data[offset];
            if (len == 0) {
                offset += 1;
                break;
            } else if ((len & 0xC0) == 0xC0) {
                // Pointer: next byte + lower 6 bits of this byte
                if (offset + 1 >= data.len) return ParseError.MalformedPacket;
                const ptr = ((@as(u16, len & 0x3F) << 8) | @as(u16, data[offset + 1]));
                if (!jumped) {
                    jump_offset = offset + 2;
                    jumped = true;
                }
                offset = ptr;
                // Recursively parse at pointer location
                const pointed = try self.parseName(data, &offset, depth + 1);
                try name_buf.appendSlice(pointed);
                break;
            } else {
                offset += 1;
                if (offset + len > data.len) return ParseError.MalformedPacket;
                if (name_buf.items.len > 0) try name_buf.append('.');
                try name_buf.appendSlice(data[offset .. offset + len]);
                offset += len;
            }
        }
        if (jumped) {
            offset_ptr.* = jump_offset;
        } else {
            offset_ptr.* = offset;
        }
        return try self.allocator.dupe(u8, name_buf.items);
    }

    fn parse(base: *ProtocolParser, data: []const u8) ParseError!void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        if (data.len < 12) return ParseError.InsufficientData;
        self.transaction_id = ((@as(u16, data[0]) << 8) | @as(u16, data[1]));
        const flags = ((@as(u16, data[2]) << 8) | @as(u16, data[3]));
        self.is_query = (flags & 0x8000) == 0;
        self.query_count = ((@as(u16, data[4]) << 8) | @as(u16, data[5]));
        self.answer_count = ((@as(u16, data[6]) << 8) | @as(u16, data[7]));

        var offset: usize = 12;

        // Parse questions
        for (0..self.query_count) |_| {
            var name_offset = offset;
            const name = try self.parseName(data, &name_offset, 0);
            offset = name_offset;

            if (offset + 4 > data.len) return ParseError.MalformedPacket;
            const qtype = (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
            const qclass = (@as(u16, data[offset + 2]) << 8) | @as(u16, data[offset + 3]);
            offset += 4;

            try self.questions.append(DnsQuestion{
                .name = name,
                .type = qtype,
                .class = qclass,
            });
        }

        // Parse answers
        for (0..self.answer_count) |_| {
            var name_offset = offset;
            const name = try self.parseName(data, &name_offset, 0);
            offset = name_offset;

            if (offset + 10 > data.len) return ParseError.MalformedPacket;
            const atype = (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
            const aclass = (@as(u16, data[offset + 2]) << 8) | @as(u16, data[offset + 3]);
            const ttl = (@as(u32, data[offset + 4]) << 24) | (@as(u32, data[offset + 5]) << 16) |
                        (@as(u32, data[offset + 6]) << 8) | @as(u32, data[offset + 7]);
            const rdlength = (@as(u16, data[offset + 8]) << 8) | @as(u16, data[offset + 9]);
            offset += 10;

            if (offset + rdlength > data.len) return ParseError.MalformedPacket;
            const rdata = try self.allocator.dupe(u8, data[offset .. offset + rdlength]);
            offset += rdlength;

            try self.answers.append(DnsAnswer{
                .name = name,
                .type = atype,
                .class = aclass,
                .ttl = ttl,
                .data = rdata,
            });
        }
    }

    fn reset(base: *ProtocolParser) void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        for (self.questions.items) |question| {
            self.allocator.free(question.name);
        }
        self.questions.clearRetainingCapacity();
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
        reset(&self.base);
        self.questions.deinit();
        self.answers.deinit();
        allocator.destroy(self);
    }
};

/// Factory: Creates a parser appropriate for the given protocol/port
pub fn createParser(allocator: Allocator, protocol: common.Protocol, dest_port: u16) !?*ProtocolParser {
    switch (protocol) {
        .TCP => switch (dest_port) {
            80, 8080 => {
                const http_parser = try HttpParser.init(allocator);
                return &http_parser.base;
            },
            53 => {
                const dns_parser = try DnsParser.init(allocator);
                return &dns_parser.base;
            },
            else => return null,
        },
        .UDP => if (dest_port == 53) {
            const dns_parser = try DnsParser.init(allocator);
            return &dns_parser.base;
        } else return null,
        else => return null,
    }
}

/// Parses a packet and returns the appropriate parser with parsed data
pub fn parsePacket(allocator: Allocator, packet: capture.PacketInfo, data: []const u8) !?*ProtocolParser {
    var parser = try createParser(allocator, packet.protocol, packet.dest_port);
    if (parser == null) return null;
    if (packet.payload) |payload| {
        try parser.?.parse(payload);
    } else if (data.len > 0) {
        try parser.?.parse(data);
    }
    return parser;
}