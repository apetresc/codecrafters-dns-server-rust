use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct ProtocolError;

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ProtocolError")
    }
}

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

    pub fn from_bytes(bytes: &[u8]) -> Result<DNSHeader, ProtocolError> {
        if bytes.len() < 12 {
            Err(ProtocolError)
        } else {
            let bytes = &bytes[0..12];
            Ok(DNSHeader {
                id: u16::from_be_bytes([bytes[0], bytes[1]]),
                qr: bytes[2] >> 7,
                opcode: (bytes[2] >> 3) & 0b1111,
                aa: (bytes[2] >> 2) & 0b1,
                tc: (bytes[2] >> 1) & 0b1,
                rd: bytes[2] & 0b1,
                ra: bytes[3] >> 7,
                z: (bytes[3] >> 4) & 0b111,
                rcode: bytes[3] & 0b1111,
                qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
                ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
                nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
                arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
            })
        }
    }
}

pub struct DNSQuestion {
    // A domain name represented as a sequence of labels, where each label consists of a length
    // octet followed by that number of octets.
    domain_name: Vec<String>,
    // The type of the query.
    query_type: u16,
    // The class of the query.
    query_class: u16,
}

impl DNSQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in &self.domain_name {
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.push(0x0);
        bytes.extend(&self.query_type.to_be_bytes());
        bytes.extend(&self.query_class.to_be_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> DNSQuestion {
        let mut domain_name = Vec::new();
        let mut i = 0;
        while bytes[i] != 0x0 {
            let label_length = bytes[i] as usize;
            let label = String::from_utf8_lossy(&bytes[i + 1..i + 1 + label_length]);
            domain_name.push(label.to_string());
            i += 1 + label_length;
        }
        let query_type = u16::from_be_bytes([bytes[i + 1], bytes[i + 2]]);
        let query_class = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]);
        DNSQuestion {
            domain_name,
            query_type,
            query_class,
        }
    }
}

pub struct DNSAnswer {
    // A domain name represented as a sequence of labels, where each label consists of a length
    // octet followed by that number of octets.
    domain_name: Vec<String>,
    // The type of the query.
    query_type: u16,
    // The class of the query.
    query_class: u16,
    // The time to live of the resource record in seconds.
    ttl: u32,
    // The length of the resource record data in octets.
    rdlength: u16,
    // The resource record data.
    rdata: Ipv4Addr,
}

impl DNSAnswer {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in &self.domain_name {
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.push(0x0);
        bytes.extend(&self.query_type.to_be_bytes());
        bytes.extend(&self.query_class.to_be_bytes());
        bytes.extend(&self.ttl.to_be_bytes());
        bytes.extend(&self.rdlength.to_be_bytes());
        bytes.extend(&self.rdata.octets());
        bytes
    }
}

pub struct DNSQuery {
    header: DNSHeader,
    question_section: DNSQuestion,
}

impl DNSQuery {
    pub fn new(id: u16, question: DNSQuestion) -> DNSQuery {
        DNSQuery {
            header: DNSHeader::new(id, false),
            question_section: question,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DNSQuery, ProtocolError> {
        let header = DNSHeader::from_bytes(bytes)?;
        let question_section = DNSQuestion::from_bytes(&bytes[12..]);
        Ok(DNSQuery::new(header.id, question_section))
    }

    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes().to_vec();
        bytes.extend(self.question_section.to_bytes());
        bytes
    }
}

pub struct DNSResponse {
    header: DNSHeader,
    question_section: DNSQuestion,
    answer_section: DNSAnswer,
}

impl DNSResponse {
    pub fn for_request(query: DNSQuery) -> DNSResponse {
        let mut header = DNSHeader::new(query.header.id, true);
        header.qdcount = 1;
        // TODO: Actually compute these values
        let answer = DNSAnswer {
            domain_name: query.question_section.domain_name.clone(),
            query_type: query.question_section.query_type,
            query_class: query.question_section.query_class,
            ttl: 60,
            rdlength: 4,
            rdata: Ipv4Addr::new(8, 8, 8, 8),
        };
        header.ancount = 1;
        DNSResponse {
            header,
            question_section: query.question_section,
            answer_section: answer,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes().to_vec();
        bytes.extend(self.question_section.to_bytes());
        bytes.extend(self.answer_section.to_bytes());
        bytes
    }
}
