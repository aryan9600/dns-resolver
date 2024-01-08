use crate::error::{map_decode_err, map_encode_err, DNSResolverError, Result};
use itertools::Itertools;

// DomainName represents a fully form domain name.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct DomainName(pub String);

// LabelSequenceParser is a parser that knows how to construct
// domain names where a domain name is represented as:
// 1. a sequence of labels ending in a zero octet
// 2. a pointer
// 3. a sequence of labels ending with a pointer
pub struct LabelSequenceParser(Option<Vec<String>>);

impl LabelSequenceParser {
    pub fn new() -> LabelSequenceParser {
        LabelSequenceParser(None)
    }

    // Constructs the domain name from its wire format.
    // response is supposed to be the entire DNS message required
    // to go back to where a pointer is pointing.
    pub fn construct_domain_name<'a, T>(
        &mut self,
        iter: &mut T,
        response: Option<&mut T>,
    ) -> Result<DomainName>
    where
        T: Iterator<Item = &'a u8> + Clone,
    {
        if self.0 == None {
            self.0 = Some(vec![]);
        }
        let parts = self.0.as_mut().expect("");

        loop {
            if let Some(len) = iter.next() {
                // If length is 0, then there are no more labels.
                if *len == 0 {
                    break;
                }
                // check if the length is actually a pointer
                if len.leading_ones() == 2 {
                    if let Some(val) = response {
                        let domain_name = self.construct_compressed_domain_name(*len, iter, val)?;
                        return Ok(domain_name);
                    }
                }
                let len_usize = usize::try_from(*len).map_err(|e| map_decode_err("name", &e))?;

                // to check if the data ends with a pointer
                let mut pp_iter = iter.clone();
                // if length is less than 2, then it can't be a pointer.
                if len_usize >= 2 {
                    // Advance the iterator till the (potential) pointer.
                    for _ in 0..len_usize - 2 {
                        pp_iter.next();
                    }
                    if let Some(pp) = pp_iter.next() {
                        // check if it is indeed a pointer
                        if pp.leading_ones() == 2 {
                            if let Some(val) = response {
                                let domain_name =
                                    self.construct_compressed_domain_name(*pp, &mut pp_iter, val)?;
                                return Ok(domain_name);
                            }
                        }
                    }
                }

                let data_bytes = iter.take(len_usize);
                let labels = data_bytes.map(|x| *x).collect_vec();
                let label_str = String::from_utf8_lossy(&labels).into_owned();
                parts.push(label_str);
            } else {
                break;
            }
        }

        let name = parts.join(".");
        Ok(DomainName(name))
    }

    fn construct_compressed_domain_name<'a, T>(
        &mut self,
        length: u8,
        iter: &mut T,
        response: &mut T,
    ) -> Result<DomainName>
    where
        T: Iterator<Item = &'a u8> + Clone,
    {
        let next = iter.next().ok_or(DNSResolverError::Decode(
            String::from("compressed_name"),
            String::from("could not parse bytes"),
        ))?;
        // get offset; the place we need to go to
        let offset_bytes = u16::from_be_bytes([length & 0b0011_1111, *next]);
        let offset =
            usize::try_from(offset_bytes).map_err(|e| map_decode_err("compressed_name", &e))?;

        // sad but necessary
        let mut og = response.clone();

        // move iterator to the offset
        response.nth(offset - 1);
        let domain_name = self.construct_domain_name(response, Some(&mut og))?;
        Ok(domain_name)
    }
}

impl DomainName {
    pub fn new(domain: String) -> DomainName {
        DomainName(domain)
    }

    // Encodes the domain name into a sequence of labels ending in a zero octect.
    pub fn encode(&self, encoded: &mut Vec<u8>) -> Result<()> {
        let name = &self.0;
        let parts: Vec<&str> = name.split('.').collect();
        for part in parts {
            let len = u8::try_from(part.len()).map_err(|e| map_encode_err("name", &e))?;
            let content = part.as_bytes();
            encoded.push(len);
            encoded.extend(content);
        }
        encoded.extend(0_u8.to_be_bytes());
        Ok(())
    }

    // Encodes the domain name into either a pointer or a sequence of labels ending in a pointer.
    pub fn encode_with_compression(&self, encoded: &mut Vec<u8>) -> Result<()> {
        let mut non_compressed = vec![];
        self.encode(&mut non_compressed)?;
        // Last element is a 0 that we don't care about.
        non_compressed.pop();
        let mut iter = non_compressed.iter();

        // a vector where each element is a tuple consisting of the label size and the
        // label itself.
        let mut parts = vec![];
        loop {
            if let Some(len) = iter.next() {
                let len_usize = usize::try_from(*len).map_err(|e| map_encode_err("name", &e))?;

                let mut label = vec![];
                for _ in 0..len_usize {
                    let next = iter.next().ok_or(DNSResolverError::Encode(
                        String::from("compressed_name"),
                        String::from("could not parse bytes"),
                    ))?;
                    label.push(*next);
                }

                parts.push((len_usize, label));
            } else {
                break;
            }
        }
        // reverse the vector, since we want to search for occurences from the
        // last label onwards.
        parts.reverse();

        // offset is the position where the pointer in our answer points to.
        let mut offset = None;
        let mut parts_iter = parts.iter();
        loop {
            if let Some(part) = parts_iter.next() {
                // check if the label is already present somewhere in the encoded message.
                if let Some(idx) = find_subset_index(&encoded, &part.1) {
                    // subtract 1 here since we need to include the length octect that appears
                    // before the start of label.
                    offset = Some(idx - 1);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if let Some(offset_idx) = offset {
            // push the non-compressable labels first.
            parts_iter.for_each(|part| {
                encoded.push(part.0 as u8);
                encoded.extend(part.1.clone());
            });

            let offset_u16 = offset_idx as u16;
            let mut offset_bytes = offset_u16.to_be_bytes();
            // this bitwise operation makes it clear that this is a pointer.
            offset_bytes[0] |= 0b1100_0000;
            encoded.extend(offset_bytes);
        } else {
            encoded.extend(non_compressed);
        }

        Ok(())
    }
}

fn find_subset_index(superset: &Vec<u8>, subset: &Vec<u8>) -> Option<usize> {
    if subset.is_empty() {
        return None;
    }

    if subset.len() > superset.len() {
        return None;
    }

    for i in 0..=(superset.len() - subset.len()) {
        if superset[i..(i + subset.len())] == *subset {
            return Some(i);
        }
    }

    None
}
