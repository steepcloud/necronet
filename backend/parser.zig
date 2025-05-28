///////////////////////////////////////////////////////////////////////////////
// Network Protocol Parser Module
//
// This module provides parsers for common network application protocols,
// extracting structured information from raw packet payloads. The design uses
// an object-oriented approach with a common parser interface and protocol-
// specific implementations.
//
// The parsers handle the complexities of binary protocols including byte order
// conversion, pointer resolution, and header parsing. Memory management is
// carefully handled with proper allocation and cleanup for all dynamic data.
///////////////////////////////////////////////////////////////////////////////

const std = @import("std");
const capture = @import("backend");
const common = @import("common");
const Allocator = std.mem.Allocator;

/// Error types that can occur during packet parsing operations
pub const ParseError = error{
    InvalidFormat, // the packet data doesn't match expected protocol format
    UnsupportedProtocol, // the specified protocol is not supported by any parser
    InsufficientData, // the packet is truncated or contains insufficient data
    MalformedPacket, // the packet structure violates protocol specifications
    OutOfMemory, // memory allocation failure during parsing
};

/// Base protocol parser interface
/// Defines the common interface for all protocol parsers using vtable pattern
pub const ProtocolParser = struct {
    /// Function pointer for parsing protocol-specific data
    parseFn: *const fn(self: *ProtocolParser, data: []const u8) ParseError!void,
    /// Function pointer for resetting parser state
    resetFn: *const fn(self: *ProtocolParser) void,
    /// Function pointer for releasing allocated resources
    deinitFn: *const fn(self: *ProtocolParser, allocator: Allocator) void,

    /// Parse protocol-specific data from a raw byte slice
    /// Returns error if parsing fails or data is malformed
    pub fn parse(self: *ProtocolParser, data: []const u8) ParseError!void {
        return self.parseFn(self, data);
    }

    /// Reset parser state to prepare for new packet data
    /// Clears any internal state but maintains allocated memory
    pub fn reset(self: *ProtocolParser) void {
        return self.resetFn(self);
    }

    /// Free all resources allocated by this parser
    /// Must be called when the parser is no longer needed
    pub fn deinit(self: *ProtocolParser, allocator: Allocator) void {
        return self.deinitFn(self, allocator);
    }
};

/// HTTP protocol parser
/// Parses both HTTP requests and responses using a state machine approach
pub const HttpParser = struct {
    base: ProtocolParser, // base protocol parser interface
    allocator: Allocator, // memory allocator for this parser
    state: HttpParseState, // current parsing state
    method: []u8, // HTTP method (GET, POST, etc.)
    uri: []u8, // request URI/path
    version: []u8, // HTTP version (e.g., "HTTP/1.1")
    status_code: []u8, // response status code (e.g., "200")
    reason_phrase: []u8, // response reason pharse (e.g., "OK")
    headers: std.StringHashMap([]u8), // HTTP headers map (name -> value)
    header_count: usize, // number of headers parsed
    body_length: usize, // content length from headers or 0
    is_request: bool, // whether this is a request or response
    body: []u8, // HTTP message body
    previous_header_name: []const u8, // used for header folding

    /// HTTP parsing state machine states
    pub const HttpParseState = enum {
        StartLine, // parsing request/status line
        Headers, // parsing HTTP headers
        Body, // parsing message body
        Complete, // parsing complete
        Error, // error occurred during parsing
    };

    /// Initialize a new HTTP parser
    ///
    /// Parameters:
    ///   allocator: Memory allocator for parser resources
    ///
    /// Returns:
    ///   Allocated and initialized HTTP parser or error
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
            .previous_header_name = &[_]u8{},
        };
        return parser;
    }

    /// Parse HTTP protocol data using a state machine
    /// Handles both request and response messages
    ///
    /// Parameters:
    ///   base: Base protocol parser interface
    ///   data: Raw HTTP data to parse
    ///
    /// Returns:
    ///   Error if parsing fails or data is malformed
    fn parse(base: *ProtocolParser, data: []const u8) ParseError!void {
        const self: *HttpParser = @fieldParentPtr("base", base);
        var i: usize = 0;
        while (i < data.len) {
            switch (self.state) {
                .StartLine => {
                    // find the end of the first lien (request line or status line)
                    const line_end = std.mem.indexOfScalarPos(u8, data, i, '\n') orelse return ParseError.InsufficientData;
                    const line = data[i..line_end];
                    if (line.len > 0) {
                        if (std.mem.startsWith(u8, line, "HTTP/")) {
                            // Parse HTTP response: HTTP/1.1 200 OK
                            self.is_request = false;
                            var parts = std.mem.splitScalar(u8, line, ' ');
                            const version = parts.next() orelse return ParseError.MalformedPacket;
                            const status_code = parts.next() orelse return ParseError.MalformedPacket;
                            var reason_builder = std.ArrayList(u8).init(self.allocator);
                            defer reason_builder.deinit();
                            var first = true;
                            while (parts.next()) |part| {
                                if (!first) {
                                    try reason_builder.append(' ');
                                }
                                try reason_builder.appendSlice(part);
                                first = false;
                            }
                            self.version = try self.allocator.dupe(u8, std.mem.trimRight(u8, version, "\r"));
                            self.status_code = try self.allocator.dupe(u8, status_code);
                            self.reason_phrase = try self.allocator.dupe(u8, std.mem.trim(u8, reason_builder.items, "\r\n"));
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
                            self.version = try self.allocator.dupe(u8, std.mem.trimRight(u8, version, "\r"));
                            self.status_code = &[_]u8{};
                            self.reason_phrase = &[_]u8{};
                        }
                    }
                    i = line_end + 1;
                    self.state = .Headers;
                },
                .Headers => {
                    // find the end of the current header line
                    const line_end = std.mem.indexOfScalarPos(u8, data, i, '\n') orelse return ParseError.InsufficientData;
                    const line = data[i..line_end];

                    // empty line indicates end of headers
                    if (line.len == 0 or (line.len == 1 and line[0] == '\r')) {
                        i = line_end + 1;
                        self.state = .Body;
                    } else if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                        // handle header line folding (continuation of previous header)
                        if (self.previous_header_name.len == 0) return ParseError.MalformedPacket;
                        if (self.headers.get(self.previous_header_name)) |prev_value| {
                            const folded_content = std.mem.trim(u8, line, " \t\r");
                            const new_value = try std.fmt.allocPrint(
                                self.allocator,
                                "{s} {s}",
                                .{ prev_value, folded_content }
                            );

                            errdefer self.allocator.free(new_value);

                            self.allocator.free(prev_value);
                            
                            try self.headers.put(self.previous_header_name, new_value);
                        } else {
                            return ParseError.MalformedPacket;
                        }

                        i = line_end + 1;
                    } else {
                        // parse standard header -> Name: Value
                        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return ParseError.MalformedPacket;
                        
                        var name = line[0..colon];
                        var value = line[colon + 1 ..];
                        
                        // trim whitespace and CR
                        if (name.len > 0 and name[name.len - 1] == '\r') name = name[0 .. name.len - 1];
                        if (value.len > 0 and value[0] == ' ') value = value[1..];
                        if (value.len > 0 and value[value.len - 1] == '\r') value = value[0 .. value.len - 1];
                        
                        // allocate memory for header name and value
                        const name_owned = try self.allocator.dupe(u8, name);
                        errdefer self.allocator.free(name_owned);
                        
                        const value_owned = try self.allocator.dupe(u8, value);
                        errdefer self.allocator.free(value_owned);
                        
                        // store header in hash map, managing memory correctly for overwrites
                        const fetch_put_result = try self.headers.fetchPut(name_owned, value_owned);
                        if (fetch_put_result) |result_kv| {
                            self.allocator.free(result_kv.value);
                            self.allocator.free(name_owned);
                            self.previous_header_name = result_kv.key;
                        } else {
                            self.previous_header_name = name_owned;
                        }

                        self.header_count += 1;
                        
                        // special handling for Content-Length header
                        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                            self.body_length = std.fmt.parseInt(usize, value, 10) catch 0;
                        }
                        i = line_end + 1;
                    }
                },
                .Body => {
                    // extract body content if Content-Length is provided
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

    /// Reset the HTTP parser to its initial state
    /// Frees all allocated memory for parsed data but maintains the parser itself
    ///
    /// Parameters:
    ///   base: Base protocol parser interface
    fn reset(base: *ProtocolParser) void {
        const self: *HttpParser = @fieldParentPtr("base", base);
        self.state = .StartLine;

        // free all allocated string memory
        if (self.method.len > 0) self.allocator.free(self.method);
        if (self.uri.len > 0) self.allocator.free(self.uri);
        if (self.version.len > 0) self.allocator.free(self.version);
        if (self.body.len > 0) self.allocator.free(self.body);
        if (self.status_code.len > 0) self.allocator.free(self.status_code);
        if (self.reason_phrase.len > 0) self.allocator.free(self.reason_phrase);
        
        // reset fields to empty
        self.method = &[_]u8{};
        self.uri = &[_]u8{};
        self.version = &[_]u8{};
        self.status_code = &[_]u8{};
        self.reason_phrase = &[_]u8{};
        self.body = &[_]u8{};
        self.previous_header_name = &[_]u8{};

        // free all header memory
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.clearRetainingCapacity();
        self.header_count = 0;
        self.body_length = 0;
    }

    /// Completely deallocate the HTTP parser and all its resources
    ///
    /// Parameters:
    ///   base: Base protocol parser interface
    ///   allocator: Memory allocator to free resources
    pub fn deinit(base: *ProtocolParser, allocator: Allocator) void {
        const self: *HttpParser = @fieldParentPtr("base", base);
        reset(&self.base);
        self.headers.deinit();
        allocator.destroy(self);
    }
};

/// DNS protocol parser
/// Parses DNS queries and responses including domain names and records
pub const DnsParser = struct {
    base: ProtocolParser, // base protocol parser interface
    allocator: Allocator, // memory allocator for this parser
    transaction_id: u16, // DNS transaction identifier
    is_query: bool, // whether this is a query (not a response)
    query_count: u16, // number of queries in the DNS message
    answer_count: u16, // number of answers in the DNS message
    questions: std.ArrayList(DnsQuestion), // list of parsed query sections
    answers: std.ArrayList(DnsAnswer), // list of parsed answer sections

    /// DNS query section structure
    pub const DnsQuestion = struct {
        name: []u8, // domain name being queried
        type: u16, // query type (e.g., A=1, AAAA=28, etc.)
        class: u16, // query class (typically IN=1)
    };

    /// DNS answer section structure
    pub const DnsAnswer = struct {
        name: []u8, // domain name this answer refers to
        type: u16, // record type (e.g., A=1, AAAA=28, etc.)
        class: u16, // record class (typically IN=1)
        ttl: u32, // time-to-live in seconds
        data: []u8, // record data (parsed according to type)
    };

    /// Initialize a new DNS parser
    ///
    /// Parameters:
    ///   allocator: Memory allocator for parser resources
    ///
    /// Returns:
    ///   Allocated and initialized DNS parser or error
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

    /// Parse a DNS domain name with compression pointer support
    /// Handles DNS name compression (RFC 1035) by resolving pointers
    ///
    /// Parameters:
    ///   self: Pointer to DnsParser
    ///   data: Complete DNS message data
    ///   offset_ptr: Pointer to current offset, updated with new position
    ///   depth: Recursion depth counter for pointer loop prevention
    ///
    /// Returns:
    ///   Allocated string with parsed domain name
    ///   Error if name parsing fails or message is malformed
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
                // end of name
                offset += 1;
                break;
            } else if ((len & 0xC0) == 0xC0) {
                // Pointer (compression - top 2 bits are set): next byte + lower 6 bits of this byte
                // format: 11xxxxxx xxxxxxxx (14 bits for offset into message)
                if (offset + 1 >= data.len) return ParseError.MalformedPacket;
                const ptr = ((@as(u16, len & 0x3F) << 8) | @as(u16, data[offset + 1]));
                if (!jumped) {
                    jump_offset = offset + 2;
                    jumped = true;
                }
                offset = ptr;
                // recursively parse at pointer location
                const pointed = try self.parseName(data, &offset, depth + 1);
                defer self.allocator.free(pointed);
                try name_buf.appendSlice(pointed);
                break;
            } else {
                // this is a label (part of domain name)
                offset += 1;
                if (offset + len > data.len) return ParseError.MalformedPacket;
                if (name_buf.items.len > 0) try name_buf.append('.');
                try name_buf.appendSlice(data[offset .. offset + len]);
                offset += len;
            }
        }

        // update position based on whether we followed pointers
        if (jumped) {
            offset_ptr.* = jump_offset;
        } else {
            offset_ptr.* = offset;
        }
        return try self.allocator.dupe(u8, name_buf.items);
    }

    /// Parse DNS protocol message data
    /// Handles both queries and responses with all supported record types
    ///
    /// Parameters:
    ///   base: Base protocol parser interface
    ///   data: Raw DNS message data to parse
    ///
    /// Returns:
    ///   Error if parsing fails or message is malformed
    fn parse(base: *ProtocolParser, data: []const u8) ParseError!void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        
        // validate minimum DNS header size
        if (data.len < 12) return ParseError.InsufficientData;
        
        // parse DNS header fields (all big-endian)
            //self.transaction_id = ((@as(u16, data[0]) << 8) | @as(u16, data[1]));
            //const flags = ((@as(u16, data[2]) << 8) | @as(u16, data[3]));
            //self.is_query = (flags & 0x8000) == 0;
            //self.query_count = ((@as(u16, data[4]) << 8) | @as(u16, data[5]));
            //self.answer_count = ((@as(u16, data[6]) << 8) | @as(u16, data[7]));
        self.transaction_id = std.mem.readInt(u16, data[0..2], .big);
        const flags = std.mem.readInt(u16, data[2..4], .big);
        self.is_query = (flags & 0x8000) == 0;
        self.query_count = std.mem.readInt(u16, data[4..6], .big);
        self.answer_count = std.mem.readInt(u16, data[6..8], .big);

        var offset: usize = 12;

        // parse questions
        for (0..self.query_count) |_| {
            var name_offset = offset;
            const name = try self.parseName(data, &name_offset, 0);
            offset = name_offset;

            // parse QTYPE and QCLASS fields
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

        // parse answers
        for (0..self.answer_count) |_| {
            var name_offset = offset;
            const name = try self.parseName(data, &name_offset, 0);
            offset = name_offset;

            // parse answer record fields
            if (offset + 10 > data.len) return ParseError.MalformedPacket;
            const atype = (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
            const aclass = (@as(u16, data[offset + 2]) << 8) | @as(u16, data[offset + 3]);
            const ttl = (@as(u32, data[offset + 4]) << 24) | (@as(u32, data[offset + 5]) << 16) |
                        (@as(u32, data[offset + 6]) << 8) | @as(u32, data[offset + 7]);
            const rdlength = (@as(u16, data[offset + 8]) << 8) | @as(u16, data[offset + 9]);
            offset += 10;

            // validate RDATA length
            if (offset + rdlength > data.len) return ParseError.MalformedPacket;
            
            // parse RDATA according to record type
            var rdata_str: []u8 = &[_]u8{};
            switch(atype) {
                1 => { // A record - IPv4 address
                    if (rdlength == 4) {
                        // format IPv4 address as dotted decimal
                        rdata_str = try std.fmt.allocPrint(self.allocator, "{d}.{d}.{d}.{d}",
                            .{ data[offset], data[offset+1], data[offset+2], data[offset+3] });
                    }
                },
                28 => { // AAAA record - IPv6 address
                    if (rdlength == 16) {
                        // format IPv6 address as colon-separated hex
                        rdata_str = try std.fmt.allocPrint(self.allocator,
                        "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}",
                        .{ data[offset], data[offset+1], data[offset+2], data[offset+3],
                           data[offset+4], data[offset+5], data[offset+6], data[offset+7],
                           data[offset+8], data[offset+9], data[offset+10], data[offset+11],
                           data[offset+12], data[offset+13], data[offset+14], data[offset+15] }
                        );
                    }
                },
                5 => { // CNAME record - canonical name pointer
                    var cname_offset = offset;
                    rdata_str = try self.parseName(data, &cname_offset, 0);
                },
                else => {
                    // default: just copy raw RDATA
                    rdata_str = try self.allocator.dupe(u8, data[offset .. offset + rdlength]);
                }
            }

            offset += rdlength;

            // add the parsed answer to our list
            try self.answers.append(DnsAnswer{
                .name = name,
                .type = atype,
                .class = aclass,
                .ttl = ttl,
                .data = rdata_str,
            });
        }
    }

    /// Reset the DNS parser to its initial state
    /// Frees all allocated memory for parsed data but maintains the parser itself
    ///
    /// Parameters:
    ///   base: Base protocol parser interface
    fn reset(base: *ProtocolParser) void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        for (self.questions.items) |question| {
            self.allocator.free(question.name);
        }
        self.questions.clearRetainingCapacity();
        for (self.answers.items) |answer| {
            self.allocator.free(answer.name);
            if (answer.data.len > 0) {
                self.allocator.free(answer.data);
            }
        }
        self.answers.clearRetainingCapacity();

        // reset state fields
        self.transaction_id = 0;
        self.is_query = false;
        self.query_count = 0;
        self.answer_count = 0;
    }

    /// Completely deallocate the DNS parser and all its resources
    ///
    /// Parameters:
    ///   base: Base protocol parser interface
    ///   allocator: Memory allocator to free resources
    pub fn deinit(base: *ProtocolParser, allocator: Allocator) void {
        const self: *DnsParser = @fieldParentPtr("base", base);
        reset(&self.base);
        self.questions.deinit();
        self.answers.deinit();
        allocator.destroy(self);
    }
};

/// Factory: Creates a parser appropriate for the given protocol/port
///
/// Uses protocol and port number to determine which specialized parser to use.
/// This factory method implements the strategy pattern, selecting the appropriate
/// parser implementation based on the protocol characteristics.
///
/// Parameters:
///   allocator: Memory allocator for the parser
///   protocol: Transport layer protocol (TCP, UDP, etc.)
///   dest_port: Destination port number
///
/// Returns:
///   An initialized protocol parser or null if no matching parser is available
///   May return error on allocation failure
pub fn createParser(allocator: Allocator, protocol: common.Protocol, dest_port: u16, source_port: u16) !?*ProtocolParser {
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
        .UDP => if (dest_port == 53 or source_port == 53) {
            const dns_parser = try DnsParser.init(allocator);
            return &dns_parser.base;
        } else return null,
        else => return null,
    }
}

/// Parses a packet and returns the appropriate parser with parsed data
///
/// This high-level function creates the right parser for the packet, 
/// runs the parsing operation, and returns the populated parser object.
///
/// Parameters:
///   allocator: Memory allocator for the parser and parsed data
///   packet: Packet information from the capture system
///   data: Raw packet data (optional, used if packet.payload is null)
///
/// Returns:
///   Populated parser with parsed protocol data or null if no parser was found
///   May return error if parsing fails
pub fn parsePacket(allocator: Allocator, packet: capture.PacketInfo, data: []const u8) !?*ProtocolParser {
    var parser = try createParser(allocator, packet.protocol, packet.dest_port, packet.source_port);
    if (parser == null) return null;
    if (packet.payload) |payload| {
        try parser.?.parse(payload);
    } else if (data.len > 0) {
        try parser.?.parse(data);
    }
    return parser;
}