use anyhow::Result;
use dns_resolver::query::{DNSHeader, DNSQuestion};
use dns_resolver::resolver::Resolver;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:3500").await?;
    loop {
        let mut buf = [0; 1024];
        let (no, addr) = socket.recv_from(&mut buf).await?;
        let query = buf[..no].to_vec();
        let mut query_iter = query.iter();

        let header = DNSHeader::decode(&mut query_iter)?;
        let question = DNSQuestion::decode(&mut query_iter)?;

        let resolver = Resolver::new("0.0.0.0:3400").await?;
        let domain = question.name().0.clone();
        let (_, mut packet) = resolver.resolve(domain, question.q_type()).await?;
        let id = header.id().to_be_bytes();
        packet[0] = id[0];
        packet[1] = id[1];
        socket.send_to(&packet, addr).await?;
    }
}
