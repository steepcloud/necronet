const std = @import("std");
const parser = @import("parser");

test "HTTP parser: minimal valid request and response" {
    const allocator = std.testing.allocator;
    const req = "GET / HTTP/1.0\r\n\r\n";
    var http_parser = try parser.HttpParser.init(allocator);
    defer http_parser.base.deinit(allocator);
    try http_parser.base.parse(req);
    try std.testing.expect(http_parser.is_request);
    try std.testing.expectEqualStrings("GET", http_parser.method);
    try std.testing.expectEqualStrings("/", http_parser.uri);
    try std.testing.expectEqualStrings("HTTP/1.0", http_parser.version);

    const resp = "HTTP/1.1 200 OK\r\n\r\n";
    http_parser.base.reset();
    try http_parser.base.parse(resp);
    try std.testing.expect(!http_parser.is_request);
    try std.testing.expectEqualStrings("HTTP/1.1", http_parser.version);
    try std.testing.expectEqualStrings("200", http_parser.status_code);
    try std.testing.expectEqualStrings("OK", http_parser.reason_phrase);
}

test "HTTP parser: malformed request line" {
    const allocator = std.testing.allocator;
    const bad_req = "GET /missing_version\r\n\r\n";
    var http_parser = try parser.HttpParser.init(allocator);
    defer http_parser.base.deinit(allocator);
    try std.testing.expectError(parser.ParseError.MalformedPacket, http_parser.base.parse(bad_req));
}

test "HTTP parser: folded headers and duplicate headers" {
    const allocator = std.testing.allocator;
    var http_parser = try parser.HttpParser.init(allocator);
    defer http_parser.base.deinit(allocator);

    const req = "GET / HTTP/1.1\r\n"
          ++ "Host: example.com\r\n"
          ++ "X-Test: value1\r\n"
          ++ "X-Test: value2\r\n"
          ++ " Folded\r\n"
          ++ "\r\n";

    try http_parser.base.parse(req);

    try std.testing.expectEqualStrings("example.com", http_parser.headers.get("Host").?);
    try std.testing.expectEqualStrings("value2 Folded", http_parser.headers.get("X-Test").?);
}

test "DNS parser: truncated packet" {
    const allocator = std.testing.allocator;
    // Truncated after header
    const dns_packet = [_]u8{0x12,0x34, 0x81,0x80, 0x00,0x01, 0x00,0x01};
    var dns_parser = try parser.DnsParser.init(allocator);
    defer dns_parser.base.deinit(allocator);
    try std.testing.expectError(parser.ParseError.InsufficientData, dns_parser.base.parse(&dns_packet));
}

test "DNS parser: unsupported type" {
    const allocator = std.testing.allocator;
    // DNS response for query "a.com" type 99 (unknown), answer: 4 bytes
    const dns_packet = [_]u8{
        0x12,0x34, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x01,0x61,0x03,0x63,0x6f,0x6d,0x00,
        0x00,0x63, 0x00,0x01,
        0xc0,0x0c,
        0x00,0x63, 0x00,0x01, 0x00,0x00,0x00,0x3c, 0x00,0x04,
        0xde,0xad,0xbe,0xef
    };
    var dns_parser = try parser.DnsParser.init(allocator);
    defer dns_parser.base.deinit(allocator);
    try dns_parser.base.parse(&dns_packet);
    try std.testing.expectEqual(@as(u16, 1), dns_parser.answer_count);
    try std.testing.expectEqualStrings("a.com", dns_parser.answers.items[0].name);
    try std.testing.expectEqual(@as(u16, 99), dns_parser.answers.items[0].type);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xde,0xad,0xbe,0xef}, dns_parser.answers.items[0].data);
}

test "DNS parser: multiple questions and answers" {
    const allocator = std.testing.allocator;
    // DNS response for two questions, two answers (A and AAAA)
    const dns_packet = [_]u8{
        // Header: ID=0x1234, QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
        // QDCOUNT=2, ANCOUNT=2, NSCOUNT=0, ARCOUNT=0
        0x12,0x34, 0x81,0x80, 0x00,0x02, 0x00,0x02, 0x00,0x00, 0x00,0x00,
        
        // Question 1: a.com, type A, class IN
        0x01,0x61, 0x03,0x63,0x6f,0x6d, 0x00, // a.com
        0x00,0x01, // type A
        0x00,0x01, // class IN
        
        // Question 2: b.com, type AAAA, class IN
        0x01,0x62, 0x03,0x63,0x6f,0x6d, 0x00, // b.com
        0x00,0x1c, // type AAAA
        0x00,0x01, // class IN
        
        // Answer 1: a.com, type A, class IN, TTL=60, RDLENGTH=4, RDATA=1.2.3.4
        0xc0,0x0c, // pointer to a.com
        0x00,0x01, // type A
        0x00,0x01, // class IN
        0x00,0x00,0x00,0x3c, // TTL=60
        0x00,0x04, // RDLENGTH=4
        0x01,0x02,0x03,0x04, // 1.2.3.4
        
        // Answer 2: b.com, type AAAA, class IN, TTL=60, RDLENGTH=16, RDATA=2001:db8::1
        0xc0,0x17, // pointer to b.com (offset 33)
        0x00,0x1c, // type AAAA
        0x00,0x01, // class IN
        0x00,0x00,0x00,0x3c, // TTL=60
        0x00,0x10, // RDLENGTH=16
        0x20,0x01,0x0d,0xb8, // 2001:db8:
        0x00,0x00,0x00,0x00, // ::
        0x00,0x00,0x00,0x00, // ::
        0x00,0x00,0x00,0x01 // ::1
    };
    var dns_parser = try parser.DnsParser.init(allocator);
    defer dns_parser.base.deinit(allocator);
    try dns_parser.base.parse(&dns_packet);
    try std.testing.expectEqual(@as(u16, 2), dns_parser.query_count);
    try std.testing.expectEqual(@as(u16, 2), dns_parser.answer_count);
    try std.testing.expectEqualStrings("a.com", dns_parser.questions.items[0].name);
    try std.testing.expectEqualStrings("b.com", dns_parser.questions.items[1].name);
    try std.testing.expectEqualStrings("a.com", dns_parser.answers.items[0].name);
    try std.testing.expectEqualStrings("b.com", dns_parser.answers.items[1].name);
    try std.testing.expectEqualStrings("1.2.3.4", dns_parser.answers.items[0].data);
    try std.testing.expectEqualStrings("2001:0db8:0000:0000:0000:0000:0000:0001", dns_parser.answers.items[1].data);
}

test "DNS parser: reset and reuse" {
    const allocator = std.testing.allocator;
    // First parse A record
    const dns_packet1 = [_]u8{
        0x12,0x34, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x01,0x61,0x03,0x63,0x6f,0x6d,0x00, 0x00,0x01, 0x00,0x01,
        0xc0,0x0c, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0x3c, 0x00,0x04, 0x01,0x02,0x03,0x04
    };
    // Then parse AAAA record
    const dns_packet2 = [_]u8{
        0x12,0x34, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x01,0x61,0x03,0x63,0x6f,0x6d,0x00, 0x00,0x1c, 0x00,0x01,
        0xc0,0x0c, 0x00,0x1c, 0x00,0x01, 0x00,0x00,0x00,0x3c, 0x00,0x10,
        0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    var dns_parser = try parser.DnsParser.init(allocator);
    defer dns_parser.base.deinit(allocator);

    try dns_parser.base.parse(&dns_packet1);
    try std.testing.expectEqualStrings("1.2.3.4", dns_parser.answers.items[0].data);

    dns_parser.base.reset();
    try dns_parser.base.parse(&dns_packet2);
    try std.testing.expectEqualStrings("2001:0db8:0000:0000:0000:0000:0000:0001", dns_parser.answers.items[0].data);
}