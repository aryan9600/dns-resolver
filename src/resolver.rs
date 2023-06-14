use crate::error::{DNSResolverError, Result};
use crate::packet::DNSPacket;
use crate::query::{self, DNSHeader, DNSQuestion};
use crate::rr_types::RRType;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::net::UdpSocket;

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

    pub async fn resolve(
        &self,
        domain: String,
        record_type: &RRType,
    ) -> Result<(Vec<String>, Vec<u8>)> {
        if record_type == &RRType::A {
            return self.resolve_a_record(domain).await;
        } else if record_type == &RRType::CNAME {
            return self.resolve_cname_record(domain).await;
        } else if record_type == &RRType::TXT {
            return self.resolve_txt_record(domain).await;
        } else if record_type == &RRType::NS {
            return self.resolve_ns_record(domain).await;
        } else {
            return Err(DNSResolverError::InvalidRecordType(
                record_type.as_ref().to_string(),
            ));
        }
    }

    async fn resolve_ns_record(&self, domain: String) -> Result<(Vec<String>, Vec<u8>)> {
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
            let packet = DNSPacket::decode(response.clone())?;

            if packet.answers(&record_type).len() > 0 {
                return Ok((packet.answers(&record_type), response));
            } else if packet.answers(&RRType::CNAME).len() > 0 {
                let cname = packet.answers(&RRType::CNAME)[0].clone();
                let (resolved_cname, response) = self.resolve_a_record(cname).await?;
                return Ok((resolved_cname, response));
            } else if let Some(ns_ip) = packet.ns_ip() {
                nameserver = ns_ip.to_owned();
            } else if let Some(ns) = packet.nameserver() {
                let (ips, _) = self.resolve_a_record(ns.to_owned()).await?;
                nameserver = ips[0].clone();
            } else {
                return Err(DNSResolverError::LookupFailure(String::from("NS"), domain));
            }
        }
    }

    async fn resolve_cname_record(&self, domain: String) -> Result<(Vec<String>, Vec<u8>)> {
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
            let packet = DNSPacket::decode(response.clone())?;

            if packet.answers(&record_type).len() > 0 {
                return Ok((packet.answers(&record_type), response));
            } else if let Some(ns_ip) = packet.ns_ip() {
                nameserver = ns_ip.to_owned();
            } else if let Some(ns) = packet.nameserver() {
                let (ips, _) = self.resolve_a_record(ns.to_owned()).await?;
                nameserver = ips[0].clone();
            } else {
                return Err(DNSResolverError::LookupFailure(
                    String::from("CNAME"),
                    domain,
                ));
            }
        }
    }

    async fn resolve_txt_record(&self, domain: String) -> Result<(Vec<String>, Vec<u8>)> {
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
            let packet = DNSPacket::decode(response.clone())?;

            if packet.answers(&record_type).len() > 0 {
                return Ok((packet.answers(&record_type), response));
            } else if let Some(ns_ip) = packet.ns_ip() {
                nameserver = ns_ip.to_owned();
            } else if let Some(ns) = packet.nameserver() {
                let (ips, _) = self.resolve_a_record(ns.to_owned()).await?;
                nameserver = ips[0].clone();
            } else {
                return Err(DNSResolverError::LookupFailure(String::from("TXT"), domain));
            }
        }
    }

    pub async fn txt_record(&self, domain: String) -> Result<Vec<u8>> {
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
            let packet = DNSPacket::decode(response.clone())?;

            if packet.answers(&record_type).len() > 0 {
                println!("{:?}", packet.answers(&record_type));
                return Ok(response);
            } else if let Some(ns_ip) = packet.ns_ip() {
                nameserver = ns_ip.to_owned();
            } else if let Some(ns) = packet.nameserver() {
                let (ips, _) = self.resolve_a_record(ns.to_owned()).await?;
                nameserver = ips[0].clone();
            } else {
                return Err(DNSResolverError::LookupFailure(String::from("TXT"), domain));
            }
        }
    }

    fn resolve_a_record(
        &self,
        domain: String,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<String>, Vec<u8>)>> + '_>> {
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
                let packet = DNSPacket::decode(response.clone())?;

                if packet.answers(&record_type).len() > 0 {
                    return Ok((packet.answers(&record_type), response));
                } else if packet.answers(&RRType::CNAME).len() > 0 {
                    let cname = packet.answers(&RRType::CNAME)[0].clone();
                    let (resolved_cname, response) = self.resolve_a_record(cname).await?;
                    return Ok((resolved_cname, response));
                } else if let Some(ns_ip) = packet.ns_ip() {
                    nameserver = ns_ip.to_owned();
                } else if let Some(ns) = packet.nameserver() {
                    let (ips, _) = self.resolve_a_record(ns.to_owned()).await?;
                    nameserver = ips[0].clone();
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
            .connect(nameserver.clone())
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

    pub async fn get_question(&self) -> Result<(SocketAddr, DNSQuestion)> {
        let mut buf = [0; 1024];
        let (no, addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| DNSResolverError::IOFailure(String::from("receive"), e.to_string()))?;
        let query = buf[..no].to_vec();
        let mut query_iter = query.iter();

        let _header = DNSHeader::decode(&mut query_iter)?;
        let question = DNSQuestion::decode(&mut query_iter)?;
        Ok((addr, question))
    }
}
