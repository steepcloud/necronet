///////////////////////////////////////////////////////////////////////////////
// Common Type Definitions
//
// This module provides shared type definitions used throughout the Necronet
// application. These types establish a common vocabulary for networking
// concepts and ensure type consistency across modules.
///////////////////////////////////////////////////////////////////////////////

/// Network protocol identifiers
///
/// Used for classifying network traffic by protocol type and determining
/// appropriate parsing and analysis strategies. This enum supports both
/// transport layer protocols (TCP, UDP) and application layer protocols
/// (HTTP, DNS).
pub const Protocol = enum {
    /// Transmission Control Protocol (Layer 4)
    /// Connection-oriented protocol that guarantees delivery and ordering
    TCP,
    
    /// User Datagram Protocol (Layer 4)
    /// Connectionless protocol with no delivery guarantees
    UDP,
    
    /// Internet Control Message Protocol (Layer 3)
    /// Used for network diagnostics and error reporting
    ICMP,
    
    /// Hypertext Transfer Protocol (Layer 7)
    /// Application protocol for distributed hypermedia systems
    HTTP,
    
    /// Domain Name System Protocol (Layer 7)
    /// Application protocol for translating domain names to IP addresses
    DNS,
    
    /// Unidentified or unsupported protocol
    Unknown,
};