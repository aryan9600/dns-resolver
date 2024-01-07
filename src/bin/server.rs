use anyhow::Result;
use dns_resolver::cache::DNSCache;
use dns_resolver::packet::DNSPacket;
use dns_resolver::query::{DNSHeader, DNSQuestion, QR};
use dns_resolver::resolver::Resolver;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:3500").await?;
    let mut cache = DNSCache::new(100);
    loop {
        let mut buf = [0; 1024];
        let (no, addr) = socket.recv_from(&mut buf).await?;
        let query = buf[..no].to_vec();
        let mut query_iter = query.iter();

        let header = DNSHeader::decode(&mut query_iter)?;
        let question = DNSQuestion::decode(&mut query_iter)?;
        let mut packet: DNSPacket;
        if let Some(answer) = cache.get(question.name(), question.q_type()) {
            let mut new_header = DNSHeader::new(
                header.id(),
                0,
                1,
                answer.data().len().try_into().unwrap(),
                0,
                0,
            );
            new_header.set_qr(QR::Response);
            new_header.set_recursion_desired(header.recursion_desired());
            new_header.set_recursion_available(true);
            let questions = vec![question];
            let answers = answer.data();
            packet = DNSPacket::new(new_header, questions, answers, vec![], vec![]);
        } else {
            let resolver = Resolver::new("0.0.0.0:3400").await?;
            let domain = question.name().0.clone();
            packet = resolver.resolve(domain, question.q_type()).await?;
            packet.set_id(header.id());
            cache.insert(question.name(), question.q_type(), packet.answers().clone());
        }

        let encoded = packet.encode()?;
        socket.send_to(&encoded, addr).await?;
    }
}
