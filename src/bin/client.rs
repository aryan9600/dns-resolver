use dns_resolver::{query::self, packet::DNSPacket};
use std::{net::UdpSocket, env, process};
use anyhow::{Result, Ok, Error};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("expected two arguments; specifying the domain name and record_type");
        process::exit(1);
    }

    let domain = args[1].clone();
    let r_type = args[2].clone().parse::<u16>()?;
    let ip = resolve(domain, r_type)?;
    println!("ip: {}", ip);
    Ok(())
}

fn resolve(domain: String, record_type: u16) -> Result<String> {
    let mut nameserver = String::from("198.41.0.4");

    loop {
        println!("Querying {} for {}", nameserver, domain);
        let response = send_query(nameserver, domain.clone(), record_type)?;
        let packet = DNSPacket::decode(response)?;
        if let Some(ip) = packet.answer() {
            return Ok(ip);
        } else if let Some(ns_ip) = packet.ns_ip() {
            nameserver = ns_ip;
        } else if let Some(ns) = packet.nameserver() {
            nameserver = resolve(ns, 1)?;
        } else {
            break
        }
    }
    Err(Error::msg("problem"))
}

fn send_query(mut nameserver: String, domain: String, record_type: u16) -> Result<Vec<u8>> {
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
