use std::fmt::Debug;
use std::time::Duration;

use itertools::Itertools;

use crate::domain_name::{DomainName, LabelSequenceParser};
use crate::query;
use crate::error::{DNSResolverError, Result, map_decode_err, map_encode_err};
use crate::rr_types::RRType;
use crate::utils;

#[derive(Debug)]
pub struct DNSRecord {
    name: DomainName,
    r_type: RRType,
    class: u16,
    ttl: Duration,
    rd_len: u16,
    data: Data
}

#[derive(Clone, Debug)]
struct Data {
    raw: Vec<u8>,
    parsed: Option<String>
}

impl DNSRecord {
    pub fn r_type(&self) -> &RRType {
        &self.r_type
    }

    pub fn parsed_data(&self) -> &Option<String> {
        &self.data.parsed
    }

    pub fn decode<'a, T>(iter: &mut T, response: &mut T) -> Result<DNSRecord>
    where T: Iterator<Item = &'a u8> + Clone {
        // construct domain name
        let mut label_parser = LabelSequenceParser::new();
        let name = label_parser.construct_domain_name(iter, Some(&mut response.clone()))?;

        // get r_type and class
        let parts = utils::u8_bytes_to_u16_vec(iter, 2)?;
        if parts.len() < 2 {
            return Err(DNSResolverError::Decode(String::from("rr"), String::from("failed to convert bytes")));
        }
        let r_type: RRType = parts[0].try_into()?;
        let class = parts[1];

        // get ttl
        let mut ttl_bytes: [u8; 4] = [0, 0, 0,0];
        for i in 0..ttl_bytes.len() {
            ttl_bytes[i] = *iter.next().
                ok_or(DNSResolverError::Decode(String::from("rr"), String::from("could not parse bytes")))?;
        }
        let ttl_u32 = u32::from_be_bytes(ttl_bytes);
        let ttl = Duration::from_secs(u64::from(ttl_u32));

        // get rd_len
        let rd_len_bytes = utils::u8_bytes_to_u16_vec(iter, 1)?;
        if rd_len_bytes.len() < 1 {
            return Err(DNSResolverError::Decode(String::from("rr"), String::from("failed to convert bytes")));
        }
        let rd_len = rd_len_bytes[0];
        let rd_size = usize::try_from(rd_len)
            .map_err(|e| map_decode_err("rr", &e))?;

        // get data in its raw format
        let data = iter.take(rd_size).map(|x| *x).collect_vec();

        let mut record = DNSRecord{
            name,
            r_type,
            class,
            ttl,
            rd_len,
            data: Data { raw: data, parsed: None },
        };

        // parse data into a human readable format
        record.data.parsed = record.parse_raw_data(response).ok();
        Ok(record)
    }

    // pub fn encode(&self, encoded: &mut Vec<u8>) -> Result<()> {
        // self.name.encode_with_compression(encoded)?;
// 
        // let rr_type = self.r_type as u16;
        // encoded.extend(rr_type.to_be_bytes());
        // encoded.extend(self.class.to_be_bytes());
// 
        // let ttl = u32::try_from(self.ttl.as_secs())
            // .map_err(|e| map_encode_err("rr", &e))?;
        // encoded.extend(ttl.to_be_bytes());
// 
        // encoded.extend(self.rd_len.to_be_bytes());
        // 
    // }

    fn parse_raw_data<'a, T>(&self, response: &mut T) -> Result<String>
    where T: Iterator<Item = &'a u8> + Clone {
        // if it's an A record, then each byte represents an octect, so just join them
        // with a '.' as a separator.
        if self.r_type == RRType::A {
            let data = self.data.raw.iter().map(|x| x.to_string()).join(".");
            return Ok(data);
        // if it's a TXT record, then the bytes are utf8 bytes so convert them into a string.
        } else if self.r_type == RRType::TXT {
            let data = String::from_utf8_lossy(&self.data.raw[1..]).to_string();
            return Ok(data);
        // if it's a NS or CNAME record, then the bytes are label sequences which may or may
        // not be compressed.
        } else if self.r_type == RRType::NS || self.r_type == RRType::CNAME {
            let raw = &self.data.raw;
            let pp = raw[raw.len()-2];
            let name: DomainName;
            let mut label_parser = LabelSequenceParser::new();
            if pp.leading_ones() == 2 {
                let val = response.map(|x| *x).collect_vec();
                name = label_parser.construct_domain_name(&mut raw.iter(), Some(&mut val.iter()))?;
            } else {
                name = label_parser.construct_domain_name(&mut raw.iter(), None)?;
            }
            return Ok(name.0);
        } else {
            return Err(DNSResolverError::Parse);
        }
    }
}
