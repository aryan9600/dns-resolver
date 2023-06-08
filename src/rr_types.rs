use std::str::FromStr;

use strum_macros::EnumString;
use crate::error::{DNSResolverError, Result};

macro_rules! rr_type {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($variant:ident$( = $val:literal)?),*
    }) => {
        $(#[$meta])*
        $vis enum $name {
            $($variant$( = $val)?),*
        }

        impl TryFrom<u16> for $name {
            type Error = DNSResolverError;

            fn try_from(v: u16) -> Result<Self> {
                match v {
                    $(x if x == $name::$variant as u16 => Ok($name::$variant),)*
                    _ => Err(DNSResolverError::InvalidRecordType(v.to_string())),
                }
            }
        }
    };
}

rr_type!(
    #[derive(Debug, EnumString, Clone, PartialEq)]
    pub enum RRType {
        A = 1,
        NS,
        MD,
        MF,
        CNAME,
        SOA,
        MB,
        MG,
        MR,
        NULl,
        WKS,
        PTR,
        HINFO,
        MINFO,
        MX,
        TXT,
        AAAA = 28
    }
);

pub fn str_to_record_type(val: &str) -> Result<RRType> {
    RRType::from_str(val).map_err(|_| DNSResolverError::InvalidRecordType(val.to_owned()))
}
