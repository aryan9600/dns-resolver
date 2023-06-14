use itertools::Itertools;
use crate::error::{DNSResolverError, Result, map_decode_err, map_encode_err};
use crate::utils;

#[derive(Debug)]
pub struct DomainName(pub String);

pub struct LabelSequenceParser(Option<Vec<String>>);

impl LabelSequenceParser {
    pub fn new() -> LabelSequenceParser {
        LabelSequenceParser(None)
    }

    pub fn construct_domain_name<'a, T>(&mut self, iter: &mut T, response: Option<&mut T>) -> Result<DomainName> 
    where T: Iterator<Item = &'a u8> + Clone {
        if self.0 == None {
            self.0 = Some(vec![]);
        }
        let parts = self.0.as_mut().expect("");

        loop {
            if let Some(len) = iter.next() {
                if *len == 0 {
                    break
                }
                // check if the length is actually a pointer
                if len.leading_ones() == 2 {
                    if let Some(val) = response {
                        let domain_name = self.construct_compressed_domain_name(*len, iter, val)?;
                        return Ok(domain_name);
                    }
                }
                let len_usize = usize::try_from(*len)
                    .map_err(|e| map_decode_err("name", &e))?;

                // check if the data ends with a pointer
                let mut pp_iter = iter.clone();
                // if length is less than 2, then it can't be a pointer.
                if len_usize >= 2 {
                    for _ in 0..len_usize-2 {
                        pp_iter.next();
                    }
                    if let Some(pp) = pp_iter.next() {
                        if pp.leading_ones() == 2 {
                            if let Some(val) = response {
                                let domain_name = self.construct_compressed_domain_name(*pp, &mut pp_iter, val)?;
                                return Ok(domain_name)
                            }
                        }
                    }
                }

                let data_bytes = iter.take(len_usize);
                let labels = data_bytes.map(|x| *x).collect_vec();
                let label_str = String::from_utf8_lossy(&labels).into_owned();
                parts.push(label_str);
            } else {
                break
            }
        }

        let name = parts.join(".");
        Ok(DomainName(name))
    }

    fn construct_compressed_domain_name<'a, T>(&mut self, length: u8, iter: &mut T, response: &mut T) -> Result<DomainName>
    where T: Iterator<Item = &'a u8> + Clone {
        let next = iter.next().ok_or(
            DNSResolverError::Decode(String::from("compressed_name"),
            String::from("could not parse bytes"))
        )?;
        let offset_bytes = u16::from_be_bytes([length&0b0011_1111, *next]);
        let offset = usize::try_from(offset_bytes)
            .map_err(|e| map_decode_err("compressed_name", &e))?;

        // sad but necessary
        let mut og = response.clone();

        response.nth(offset-1);
        let domain_name = self.construct_domain_name(response, Some(&mut og))?;
        Ok(domain_name)
    }
}

impl DomainName {
    pub fn new(domain: String) -> DomainName {
        DomainName(domain)
    }

    pub fn encode(&self, encoded: &mut Vec<u8>) -> Result<()> {
        let name = &self.0;
        let parts: Vec<&str> = name.split('.').collect();
        for part in parts {
            let len = u8::try_from(part.len())
                .map_err(|e| map_encode_err("name", &e))?
                .to_be_bytes();
            let content = part.as_bytes();
            encoded.extend(len);
            encoded.extend(content);
        }
        encoded.extend(0_u8.to_be_bytes());
        Ok(())
    }

    // pub fn encode_with_compression(&self, encoded: &mut Vec<u8>) -> Result<()> {
        // let mut non_compressed = vec![];
        // self.encode(&mut non_compressed)?;
        // Last element is a 0 that we don't care about.
        // non_compressed.pop();
        // let mut iter = non_compressed.iter();
// 
        // let mut parts = vec![];
        // loop {
            // if let Some(len) = iter.next() {
                // let len_usize = usize::try_from(*len)
                    // .map_err(|e| map_encode_err("name", &e))?;
// 
                // let data_bytes = iter.take(len_usize);
                // let labels = data_bytes.map(|x| *x).collect_vec();
                // parts.push((len_usize, labels));
            // } else {
                // break
            // }
        // }
        // parts.reverse();
// 
        // let mut offset = None;
        // for i in 0..parts.len() {
            // if let Some(idx) = find_subset_index(&encoded, &parts[i]) {
                // TODO: validation
                // offset = Some(idx);
                // parts.pop();
            // } else {
                // break
            // }
        // }
// 
        // if let Some(offset_idx) = offset {
            // for part in parts {
                // encoded.push(part.0 as u8);
                // encoded.extend(part.1)
            // }
            // let offset_u16 = offset_idx as u16;
            // let mut offset_bytes = offset_u16.to_be_bytes();
            // offset_bytes[0] |= 0b1100_0000;
            // encoded.extend(offset_bytes);
        // } else {
            // encoded.extend(non_compressed);
        // }
// 
        // Ok(())
    // }
}

// fn find_subset_index<>(superset: &Vec<u8>, subset: &Vec<u8>) -> Option<usize> {
    // if subset.is_empty() {
        // return None;
    // }
// 
    // if subset.len() > superset.len() {
        // return None;
    // }
// 
    // for i in 0..=(superset.len() - subset.len()) {
        // if superset[i..(i + subset.len())] == *subset {
            // return Some(i);
        // }
    // }
// 
    // None
// }
