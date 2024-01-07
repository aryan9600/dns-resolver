use crate::error::{DNSResolverError, Result};

pub fn u8_bytes_to_u16_vec<'a, T>(u8_bytes: &mut T, n: i32) -> Result<Vec<u16>>
where
    T: Iterator<Item = &'a u8>,
{
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

pub fn set_bit(number: u16, bit: u8, position: u16) -> u16 {
    if position < 16 {
        let mask: u16 = 1 << 15 - position;
        let bit_value = if bit == 0 { 0 } else { 1 };
        if bit_value == 1 {
            number | mask
        } else {
            number & !mask
        }
    } else {
        number
    }
}

pub fn get_bit(number: u16, position: u16) -> u8 {
    if position < 16 {
        if (number >> 15 - position) & 1 == 1 {
            1
        } else {
            0
        }
    } else {
        0
    }
}
