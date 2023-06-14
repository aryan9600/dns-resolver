use crate::domain_name::{DomainName, LabelSequenceParser};
use crate::error::{DNSResolverError, Result, map_decode_err, map_encode_err};
use crate::rr_types::RRType;
use crate::utils;
use tokio::net::UdpSocket;

#[derive(Debug)]
pub struct DNSHeader {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

#[derive(Debug)]
pub struct DNSQuestion {
    name: DomainName,
    q_type: RRType,
    class: u16,
}

impl DNSQuestion {
    pub fn new(name: DomainName, q_type: RRType, class: u16) -> DNSQuestion {
        DNSQuestion { name, q_type, class }
    }

    pub fn encode(&self, encoded: &mut Vec<u8>) -> Result<()> {
        self.name.encode(encoded)
            .map_err(|e| map_encode_err("question", &e))?;
        let rr_type = self.q_type.clone() as u16;
        encoded.extend(rr_type.to_be_bytes());
        encoded.extend(self.class.to_be_bytes());
        Ok(())
    }

    pub fn decode<'a, T>(iter: &mut T) -> Result<DNSQuestion>
    where T: Iterator<Item = &'a u8> + Clone {
        let mut label_parser = LabelSequenceParser::new();
        let name = label_parser.construct_domain_name(iter, None)?;

        let parts = utils::u8_bytes_to_u16_vec(iter, 2)?;
        if parts.len() < 2 {
            return Err(DNSResolverError::Decode(String::from("question"), String::from("failed to convert bytes")));
        }
        let q_type: RRType = parts[0].try_into()?;
        Ok(DNSQuestion{
            name,
            q_type,
            class: parts[1]
        })
    }
}

impl DNSHeader {
    pub fn new(id: u16, flags: u16, qd_count: u16, an_count: u16, ns_count: u16, ar_count: u16) -> DNSHeader {
        DNSHeader{
            id, flags, qd_count, an_count, ns_count, ar_count
        }
    }

    pub fn num_questions (&self) -> u16 {
        return self.qd_count
    }

    pub fn num_answers (&self) -> u16 {
        return self.an_count
    }

    pub fn num_authorities (&self) -> u16 {
        return self.ns_count
    }
    pub fn num_additionals (&self) -> u16 {
        return self.ar_count
    }

    pub fn encode(&self, encoded: &mut Vec<u8>) {
        encoded.extend(self.id.to_be_bytes());
        encoded.extend(self.flags.to_be_bytes());
        encoded.extend(self.qd_count.to_be_bytes());
        encoded.extend(self.an_count.to_be_bytes());
        encoded.extend(self.ns_count.to_be_bytes());
        encoded.extend(self.ar_count.to_be_bytes());
    }
 
    pub fn decode<'a, T>(header_bytes: &mut T) -> Result<DNSHeader> 
    where T: Iterator<Item = &'a u8> {
        let parts = utils::u8_bytes_to_u16_vec(header_bytes, 6)
            .map_err(|e| map_decode_err("header", &e))?;
        if parts.len() < 6 {
            return Err(DNSResolverError::Decode(String::from("header"), String::from("failed to convert bytes")));
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

pub fn build_query(domain_name: String, record_type: RRType) -> Result<Vec<u8>> {
    let header = DNSHeader::new(45232, 0, 1, 0, 0, 0);
    let question = DNSQuestion::new(DomainName::new(domain_name), record_type, 1);
    let mut query: Vec<u8> = vec![];
    header.encode(&mut query);
    question.encode(&mut query)?;
    Ok(query)
}
