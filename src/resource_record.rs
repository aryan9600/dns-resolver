use std::fmt::Debug;

use itertools::Itertools;

use crate::domain_name::DomainName;
use crate::query;
use crate::error::{DNSResolverError, Result, map_decode_err};
use crate::utils;

#[derive(Debug)]
pub struct DNSRecord {
    name: DomainName,
    r_type: u16,
    class: u16,
    ttl: u32,
    rd_len: u16,
    data: Data
}

#[derive(Clone, Debug)]
struct Data {
    raw: Vec<u8>,
    parsed: Option<String>
}

impl DNSRecord {
    pub fn r_type(&self) -> u16 {
        self.r_type
    }

    pub fn parsed_data(&self) -> Option<String> {
        self.data.parsed.clone()
    }

    pub fn decode<'a, T>(iter: &mut T, response: &mut T) -> Result<DNSRecord>
    where T: Iterator<Item = &'a u8> + Clone {
        let mut name = DomainName::new(String::from(""));
        name.decode(iter, Some(&mut response.clone()))?;

        let parts = utils::u8_bytes_to_u16_vec(iter, 2)?;
        if parts.len() < 2 {
            return Err(DNSResolverError::Decode(String::from("rr"), String::from("failed to convert bytes")));
        }
        let r_type = parts[0];
        let class = parts[1];

        let mut ttl_bytes: [u8; 4] = [0, 0, 0,0];
        for i in 0..ttl_bytes.len() {
            ttl_bytes[i] = *iter.next().
                ok_or(DNSResolverError::Decode(String::from("rr"), String::from("could not parse bytes")))?;
        }
        let ttl = u32::from_be_bytes(ttl_bytes);

        let rd_len_bytes = utils::u8_bytes_to_u16_vec(iter, 1)?;
        if rd_len_bytes.len() < 1 {
            return Err(DNSResolverError::Decode(String::from("rr"), String::from("failed to convert bytes")));
        }
        let rd_len = rd_len_bytes[0];
        let rd_size = usize::try_from(rd_len)
            .map_err(|e| map_decode_err("rr", &e))?;

        let data = iter.take(rd_size).map(|x| *x).collect_vec();

        let mut record = DNSRecord{
            name,
            r_type,
            class,
            ttl,
            rd_len,
            data: Data { raw: data, parsed: None },
        };
        record.data.parsed = record.parse_raw_data(response).ok();
        Ok(record)
    }

    fn parse_raw_data<'a, T>(&self, response: &mut T) -> Result<String>
    where T: Iterator<Item = &'a u8> + Clone {
        if self.r_type == 1 {
            let data = self.data.raw.iter().map(|x| x.to_string()).join(".");
            return Ok(data);
        } else if self.r_type == 16 {
            let data = String::from_utf8_lossy(&self.data.raw[1..]).to_string();
            return Ok(data);
        } else if self.r_type == 2 {
            let raw = &self.data.raw;
            let pp = raw[raw.len()-2];
            let data: String;
            let mut domain_name = DomainName::new(String::from(""));
            if pp.leading_ones() == 2 {
                let len = usize::try_from(raw[0])
                    .map_err(|e| map_decode_err("rr", &e))?;
                let label_bytes = &raw[1..len+1];
                let label = String::from_utf8_lossy(label_bytes).into_owned();

                let val = response.map(|x| *x).collect_vec();
                let pointer = [pp, raw[raw.len()-1]];

                domain_name.decode(&mut pointer.iter(), Some(&mut val.iter()))?;
                data = format!("{}.{}", label, domain_name.0)
            } else {
                domain_name.decode(&mut raw.iter(), None)?;
                data = domain_name.0;
            }
            return Ok(data);
        } else {
            return Err(DNSResolverError::Parse);
        }
    }
}
