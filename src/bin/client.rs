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
    println!("ip: {}", ip);
    Ok(())
}

fn resolve(domain: String, record_type: RRType) -> Result<String> {
    if record_type == RRType::A {
        let record = resolve_a_record(domain)?;
        return Ok(record);
    } else if record_type == RRType::CNAME {
        let record = resolve_cname_record(domain)?;
        return Ok(record);
    }
    let s = String::from("");
    Ok(s)
}

fn resolve_cname_record(domain: String) -> Result<String> {
    let mut nameserver = String::from("198.41.0.4");

    loop {
        println!("Querying {} for {} about {:?} type", nameserver, domain, RRType::CNAME);
        let response = send_query(nameserver, domain.clone(), RRType::CNAME)?;
        let packet = DNSPacket::decode(response)?;

        if let Some(ip) = packet.cname() {
            return Ok(ip.to_owned());
        }  else if let Some(ns_ip) = packet.ns_ip() {
            nameserver = ns_ip.to_owned();
        } else if let Some(ns) = packet.nameserver() {
            nameserver = resolve_a_record(ns.to_owned())?;
        } else {
            return Err(Error::msg(format!("could not lookup A record of {domain}")))
        }
    }
}

fn resolve_a_record(domain: String) -> Result<String> {
    let mut nameserver = String::from("198.41.0.4");

    loop {
        println!("Querying {} for {} about {:?} type", nameserver, domain, RRType::A);
        let response = send_query(nameserver, domain.clone(), RRType::A)?;
        let packet = DNSPacket::decode(response)?;

        if let Some(ip) = packet.answer() {
            return Ok(ip.to_owned());
        } else if let Some(cname) = packet.cname() {
            println!("{:?}", packet);
            nameserver = resolve_a_record(cname.to_owned())?;
            return Ok(nameserver);
        } else if let Some(ns_ip) = packet.ns_ip() {
            nameserver = ns_ip.to_owned();
        } else if let Some(ns) = packet.nameserver() {
            nameserver = resolve_a_record(ns.to_owned())?;
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
