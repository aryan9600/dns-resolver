use crate::domain_name::{DomainName, LabelSequenceParser};
use crate::error::{map_decode_err, map_encode_err, DNSResolverError, Result};
use crate::rr_types::RRType;
use crate::utils::{self, get_bit, set_bit};

// DNSHeader represents a DNS header.
#[derive(Debug)]
pub struct DNSHeader {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

// DNSQuestion represents a DNS question.
#[derive(Debug)]
pub struct DNSQuestion {
    name: DomainName,
    q_type: RRType,
    class: u16,
}

pub enum QR {
    Query = 0,
    Response,
}

impl DNSQuestion {
    pub fn new(name: DomainName, q_type: RRType, class: u16) -> DNSQuestion {
        DNSQuestion {
            name,
            q_type,
            class,
        }
    }

    pub fn name(&self) -> &DomainName {
        &self.name
    }

    pub fn q_type(&self) -> &RRType {
        &self.q_type
    }

    // Encode the question into the provided vector in its wire format.
    pub fn encode(&self, encoded: &mut Vec<u8>) -> Result<()> {
        self.name
            .encode(encoded)
            .map_err(|e| map_encode_err("question", &e))?;

        let rr_type = self.q_type.clone() as u16;
        encoded.extend(rr_type.to_be_bytes());
        encoded.extend(self.class.to_be_bytes());
        Ok(())
    }

    // Decode the question from its wire format into our representation.
    pub fn decode<'a, T>(iter: &mut T) -> Result<DNSQuestion>
    where
        T: Iterator<Item = &'a u8> + Clone,
    {
        let mut label_parser = LabelSequenceParser::new();
        let name = label_parser.construct_domain_name(iter, None)?;

        let parts = utils::u8_bytes_to_u16_vec(iter, 2)?;
        if parts.len() < 2 {
            return Err(DNSResolverError::Decode(
                String::from("question"),
                String::from("failed to convert bytes"),
            ));
        }
        let q_type: RRType = parts[0].try_into()?;
        Ok(DNSQuestion {
            name,
            q_type,
            class: parts[1],
        })
    }
}

impl DNSHeader {
    pub fn new(
        id: u16,
        flags: u16,
        qd_count: u16,
        an_count: u16,
        ns_count: u16,
        ar_count: u16,
    ) -> DNSHeader {
        DNSHeader {
            id,
            flags,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        }
    }

    pub fn set_qr(&mut self, qr: QR) {
        self.flags = set_bit(self.flags, qr as u8, 0);
    }

    pub fn set_opcode_std_query(&mut self) {
        for i in 1..5 {
            self.flags = set_bit(self.flags, 0, i);
        }
    }

    pub fn set_recursion_desired(&mut self, rd: bool) {
        self.flags = set_bit(self.flags, rd as u8, 7);
    }

    pub fn set_recursion_available(&mut self, ra: bool) {
        self.flags = set_bit(self.flags, ra as u8, 8);
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn recursion_desired(&self) -> bool {
        let rd = get_bit(self.flags, 7);
        if rd == 1 {
            true
        } else {
            false
        }
    }

    pub fn num_questions(&self) -> u16 {
        return self.qd_count;
    }

    pub fn num_answers(&self) -> u16 {
        return self.an_count;
    }

    pub fn num_authorities(&self) -> u16 {
        return self.ns_count;
    }
    pub fn num_additionals(&self) -> u16 {
        return self.ar_count;
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id
    }

    // Encode the header into the provided vector in its wire format.
    pub fn encode(&self, encoded: &mut Vec<u8>) {
        encoded.extend(self.id.to_be_bytes());
        encoded.extend(self.flags.to_be_bytes());
        encoded.extend(self.qd_count.to_be_bytes());
        encoded.extend(self.an_count.to_be_bytes());
        encoded.extend(self.ns_count.to_be_bytes());
        encoded.extend(self.ar_count.to_be_bytes());
    }

    // Decode the header from its wire format into our representation.
    pub fn decode<'a, T>(header_bytes: &mut T) -> Result<DNSHeader>
    where
        T: Iterator<Item = &'a u8>,
    {
        let parts = utils::u8_bytes_to_u16_vec(header_bytes, 6)
            .map_err(|e| map_decode_err("header", &e))?;
        if parts.len() < 6 {
            return Err(DNSResolverError::Decode(
                String::from("header"),
                String::from("failed to convert bytes"),
            ));
        }

        Ok(DNSHeader {
            id: parts[0],
            flags: parts[1],
            qd_count: parts[2],
            an_count: parts[3],
            ns_count: parts[4],
            ar_count: parts[5],
        })
    }
}

// Build a DNS query (in the wire format) using the provided domain
// name and the record type.
pub fn build_query(domain_name: String, record_type: RRType) -> Result<Vec<u8>> {
    let header = DNSHeader::new(45232, 0, 1, 0, 0, 0);
    let question = DNSQuestion::new(DomainName::new(domain_name), record_type, 1);
    let mut query: Vec<u8> = vec![];
    header.encode(&mut query);
    question.encode(&mut query)?;
    Ok(query)
}
