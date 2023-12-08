pub struct DNSHeader {
    // Packet Identifier (ID) - 16 bits
    // A random ID assigned to query packets. Response packets must reply with the same ID.
    id: u16,
    // Query/Response Indicator (QR) - 1 bit
    // 1 for a response packet, 0 for a query packet.
    qr: u8,
    // Operation Code (OPCODE) - 4 bits
    // 0 for a standard query, 1 for an inverse query, 2 for a server status request, 3-15 reserved for future use.
    opcode: u8,
    // Authoritative Answer (AA) - 1 bit
    // 1 if the responding server is an authority for the domain name in question, 0 otherwise.
    aa: u8,
    // Truncation (TC) - 1 bit
    // 1 if the response was truncated due to the packet being too large for the transport protocol, 0 otherwise.
    // For DNS over UDP, this is always 0.
    tc: u8,
    // Recursion Desired (RD) - 1 bit
    // 1 if the client wants the server to recursively resolve the domain name in question, 0 otherwise.
    rd: u8,
    // Recursion Available (RA) - 1 bit
    // 1 if the server supports recursive resolution, 0 otherwise.
    ra: u8,
    // Reserved (Z) - 3 bits
    // Used by DNSSEC, always 0 otherwise.
    z: u8,
    // Response Code (RCODE) - 4 bits
    // - 0 for no error
    // - 1 for a format error
    // - 2 for a server failure
    // - 3 for a name error
    // - 4 for a not implemented error
    // - 5 for a refused error
    // - 6-15 reserved for future use.
    rcode: u8,
    // Question Count (QDCOUNT) - 16 bits
    // The number of questions in the question section of the packet.
    qdcount: u16,
    // Answer Record Count (ANCOUNT) - 16 bits
    // The number of resource records in the answer section of the packet.
    ancount: u16,
    // Authority Record Count (NSCOUNT) - 16 bits
    // The number of resource records in the authority section of the packet.
    nscount: u16,
    // Additional Record Count (ARCOUNT) - 16 bits
    // The number of resource records in the additional section of the packet.
    arcount: u16,
}

impl DNSHeader {
    pub fn new(id: u16, response: bool) -> DNSHeader {
        DNSHeader {
            id,
            qr: if response { 1 } else { 0 },
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2] = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        bytes[3] = (self.ra << 7) | (self.z << 4) | self.rcode;
        bytes[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        bytes
    }
}
