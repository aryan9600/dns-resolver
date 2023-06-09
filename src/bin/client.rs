use dns_resolver::{query::self, packet::DNSPacket, rr_types::{RRType, str_to_record_type}};
use std::{net::UdpSocket, env, process};
use anyhow::{Result, Ok, Error};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("expected two arguments; specifying the domain name and record_type");
        process::exit(1);
    }

    let domain = args[1].clone();
    let record_type = args[2].clone();
    let rr_type = str_to_record_type(&record_type)?;
    let ip = resolve(domain, rr_type)?;
    println!("answer(s): {:?}", ip);
    Ok(())
}

fn resolve(domain: String, record_type: RRType) -> Result<Vec<String>> {
    if record_type == RRType::A {
        let record = resolve_a_record(domain)?;
        return Ok(record);
    } else if record_type == RRType::CNAME {
        let record = resolve_cname_record(domain)?;
        return Ok(record);
    } else if record_type == RRType::TXT {
        let record = resolve_txt_record(domain)?;
        return Ok(record);
    } else if record_type == RRType::NS {
        let record = resolve_ns_record(domain)?;
        return Ok(record);
    } else {
        return Err(Error::msg(format!("unsupported record type: {:?}", record_type)))
    }
}

fn resolve_ns_record(domain: String) -> Result<Vec<String>> {
    let mut nameserver = String::from("198.41.0.4");
    let record_type = RRType::NS;

    loop {
        println!("Querying {} for {} about {:?} type", nameserver, domain, record_type);
        let response = send_query(nameserver, domain.clone(), record_type.clone())?;
        let packet = DNSPacket::decode(response)?;

        if packet.answers(&record_type).len() > 0 {
            return Ok(packet.answers(&record_type));
        } else if packet.answers(&RRType::CNAME).len() > 0 {
            let cname = packet.answers(&RRType::CNAME)[0].clone();
            let resolved_cname = resolve_a_record(cname);
            return resolved_cname;
        } else if let Some(ns_ip) = packet.ns_ip() {
            nameserver = ns_ip.to_owned();
        } else if let Some(ns) = packet.nameserver() {
            nameserver = resolve_a_record(ns.to_owned())?[0].clone();
        } else {
            return Err(Error::msg(format!("could not lookup A record of {domain}")))
        }
    }
}

fn resolve_cname_record(domain: String) -> Result<Vec<String>> {
    let mut nameserver = String::from("198.41.0.4");
    let record_type = RRType::CNAME;

    loop {
        println!("Querying {} for {} about {:?} type", nameserver, domain, record_type);
        let response = send_query(nameserver, domain.clone(), record_type.clone())?;
        let packet = DNSPacket::decode(response)?;

        if packet.answers(&record_type).len() > 0 {
            return Ok(packet.answers(&record_type));
        }  else if let Some(ns_ip) = packet.ns_ip() {
            nameserver = ns_ip.to_owned();
        } else if let Some(ns) = packet.nameserver() {
            nameserver = resolve_a_record(ns.to_owned())?[0].clone();
        } else {
            return Err(Error::msg(format!("could not lookup A record of {domain}")))
        }
    }
}

fn resolve_txt_record(domain: String) -> Result<Vec<String>> {
    let mut nameserver = String::from("198.41.0.4");
    let record_type = RRType::TXT;

    loop {
        println!("Querying {} for {} about {:?} type", nameserver, domain, record_type);
        let response = send_query(nameserver, domain.clone(), record_type.clone())?;
        let packet = DNSPacket::decode(response)?;

        if packet.answers(&record_type).len() > 0 {
            return Ok(packet.answers(&record_type));
        }  else if let Some(ns_ip) = packet.ns_ip() {
            nameserver = ns_ip.to_owned();
        } else if let Some(ns) = packet.nameserver() {
            nameserver = resolve_a_record(ns.to_owned())?[0].clone();
        } else {
            return Err(Error::msg(format!("could not lookup A record of {domain}")))
        }
    }
}

fn resolve_a_record(domain: String) -> Result<Vec<String>> {
    let mut nameserver = String::from("198.41.0.4");
    let record_type = RRType::A;

    loop {
        println!("Querying {} for {} about {:?} type", nameserver, domain, record_type);
        let response = send_query(nameserver, domain.clone(), record_type.clone())?;
        let packet = DNSPacket::decode(response)?;

        if packet.answers(&record_type).len() > 0 {
            return Ok(packet.answers(&record_type));
        } else if packet.answers(&RRType::CNAME).len() > 0 {
            let cname = packet.answers(&RRType::CNAME)[0].clone();
            let resolved_cname = resolve_a_record(cname);
            return resolved_cname;
        } else if let Some(ns_ip) = packet.ns_ip() {
            nameserver = ns_ip.to_owned();
        } else if let Some(ns) = packet.nameserver() {
            nameserver = resolve_a_record(ns.to_owned())?[0].clone();
        } else {
            return Err(Error::msg(format!("could not lookup A record of {domain}")))
        }
    }
}

fn send_query(mut nameserver: String, domain: String, record_type: RRType) -> Result<Vec<u8>> {
    let q = query::build_query(domain, record_type)?;
    let question = q.as_slice();

    nameserver.push_str(":53");
    let socket = UdpSocket::bind("0.0.0.0:3400")?;
    socket.send_to(question, nameserver)?;
    let mut buf = [0; 1024];
    let (no, _) = socket.recv_from(&mut buf)?;

    let reply = buf[..no].to_vec();
    Ok(reply)
}
