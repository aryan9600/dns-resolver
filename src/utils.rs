use crate::error::{DNSResolverError, Result};

pub fn u8_bytes_to_u16_vec<'a, T>(u8_bytes: &mut T, n: i32) -> Result<Vec<u16>>
where T: Iterator<Item = &'a u8> {
    let mut parts = vec![];
    for _ in 0..n {
        let mut u8s: [u8; 2] = [0, 0];
        for i in 0..u8s.len() {
            u8s[i] = *u8_bytes.next().ok_or(DNSResolverError::Parse)?;
        }
        parts.push(u16::from_be_bytes(u8s));
    }
    Ok(parts)
}
