use crate::error::{DNSResolverError, Result};
use crate::packet::DNSPacket;
use crate::query::{self};
use crate::rr_types::RRType;
use std::future::Future;
use std::pin::Pin;
use tokio::net::UdpSocket;

// Resolver is a DNS resolver.
pub struct Resolver {
    pub socket: UdpSocket,
}

impl Resolver {
    pub async fn new(addr: &str) -> Result<Resolver> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| DNSResolverError::ConnectionFailure(addr.to_string(), e.to_string()))?;
        Ok(Resolver { socket })
    }

    // Constructs a DNS query out of the provided domain and record type, resolves
    // the same and returns the resolved DNS packet.
    pub async fn resolve(&self, domain: String, record_type: &RRType) -> Result<DNSPacket> {
        match record_type {
            &RRType::A => self.resolve_a_record(domain).await,
            &RRType::CNAME => self.resolve_cname_record(domain).await,
            &RRType::TXT => self.resolve_txt_record(domain).await,
            &RRType::NS => self.resolve_ns_record(domain).await,
            _ => {
                return Err(DNSResolverError::InvalidRecordType(
                    record_type.as_ref().to_string(),
                ))
            }
        }
    }

    async fn resolve_ns_record(&self, domain: String) -> Result<DNSPacket> {
        let mut nameserver = String::from("198.41.0.4");
        let record_type = RRType::NS;

        loop {
            println!(
                "Querying {} for {} about {:?} type",
                nameserver, domain, record_type
            );
            let response = self
                .send_query(nameserver, domain.clone(), record_type.clone())
                .await?;
            let packet = DNSPacket::decode(&response)?;

            if packet.answers_data(&record_type).len() > 0 {
                return Ok(packet);
            } else if packet.answers_data(&RRType::CNAME).len() > 0 {
                let cname = packet.answers_data(&RRType::CNAME)[0].clone();
                let resolved_cname = self.resolve_a_record(cname).await?;
                return Ok(resolved_cname);
            } else if let Some(ns_ip) = packet.ns_ip() {
                nameserver = ns_ip.to_owned();
            } else if let Some(ns) = packet.nameserver() {
                let resolved_ns = self.resolve_a_record(ns.to_owned()).await?;
                nameserver = resolved_ns.answers_data(&RRType::A)[0].clone();
            } else {
                return Err(DNSResolverError::LookupFailure(String::from("NS"), domain));
            }
        }
    }

    async fn resolve_cname_record(&self, domain: String) -> Result<DNSPacket> {
        let mut nameserver = String::from("198.41.0.4");
        let record_type = RRType::CNAME;

        loop {
            println!(
                "Querying {} for {} about {:?} type",
                nameserver, domain, record_type
            );
            let response = self
                .send_query(nameserver, domain.clone(), record_type.clone())
                .await?;
            let packet = DNSPacket::decode(&response)?;

            if packet.answers_data(&record_type).len() > 0 {
                return Ok(packet);
            } else if let Some(ns_ip) = packet.ns_ip() {
                nameserver = ns_ip.to_owned();
            } else if let Some(ns) = packet.nameserver() {
                let resolved_ns = self.resolve_a_record(ns.to_owned()).await?;
                nameserver = resolved_ns.answers_data(&RRType::A)[0].clone();
            } else {
                return Err(DNSResolverError::LookupFailure(
                    String::from("CNAME"),
                    domain,
                ));
            }
        }
    }

    async fn resolve_txt_record(&self, domain: String) -> Result<DNSPacket> {
        let mut nameserver = String::from("198.41.0.4");
        let record_type = RRType::TXT;

        loop {
            println!(
                "Querying {} for {} about {:?} type",
                nameserver, domain, record_type
            );
            let response = self
                .send_query(nameserver, domain.clone(), record_type.clone())
                .await?;
            let packet = DNSPacket::decode(&response)?;

            if packet.answers_data(&record_type).len() > 0 {
                return Ok(packet);
            } else if let Some(ns_ip) = packet.ns_ip() {
                nameserver = ns_ip.to_owned();
            } else if let Some(ns) = packet.nameserver() {
                let resolved_ns = self.resolve_a_record(ns.to_owned()).await?;
                nameserver = resolved_ns.answers_data(&RRType::A)[0].clone();
            } else {
                return Err(DNSResolverError::LookupFailure(String::from("TXT"), domain));
            }
        }
    }

    fn resolve_a_record(
        &self,
        domain: String,
    ) -> Pin<Box<dyn Future<Output = Result<DNSPacket>> + '_>> {
        Box::pin(async move {
            let mut nameserver = String::from("198.41.0.4");
            let record_type = RRType::A;

            loop {
                println!(
                    "Querying {} for {} about {:?} type",
                    nameserver, domain, record_type
                );
                let response = self
                    .send_query(nameserver, domain.clone(), record_type.clone())
                    .await?;
                let packet = DNSPacket::decode(&response)?;

                if packet.answers_data(&record_type).len() > 0 {
                    return Ok(packet);
                } else if packet.answers_data(&RRType::CNAME).len() > 0 {
                    let cname = packet.answers_data(&RRType::CNAME)[0].clone();
                    let resolved_cname = self.resolve_a_record(cname).await?;
                    return Ok(resolved_cname);
                } else if let Some(ns_ip) = packet.ns_ip() {
                    nameserver = ns_ip.to_owned();
                } else if let Some(ns) = packet.nameserver() {
                    let resolved_ns = self.resolve_a_record(ns.to_owned()).await?;
                    nameserver = resolved_ns.answers_data(&RRType::A)[0].clone();
                } else {
                    return Err(DNSResolverError::LookupFailure(String::from("A"), domain));
                }
            }
        })
    }

    async fn send_query(
        &self,
        mut nameserver: String,
        domain: String,
        record_type: RRType,
    ) -> Result<Vec<u8>> {
        nameserver.push_str(":53");
        self.socket
            .connect(&nameserver)
            .await
            .map_err(|e| DNSResolverError::ConnectionFailure(nameserver, e.to_string()))?;

        let q = query::build_query(domain, record_type)?;
        let query = q.as_slice();
        self.socket
            .send(query)
            .await
            .map_err(|e| DNSResolverError::IOFailure(String::from("send"), e.to_string()))?;

        let mut buf = [0; 1024];
        let no = self
            .socket
            .recv(&mut buf)
            .await
            .map_err(|e| DNSResolverError::IOFailure(String::from("receive"), e.to_string()))?;

        let reply = buf[..no].to_vec();
        Ok(reply)
    }
}
