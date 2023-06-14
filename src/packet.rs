use crate::{query::{DNSHeader, DNSQuestion}, resource_record::DNSRecord, rr_types::RRType};
use crate::error::Result;

#[derive(Debug)]
pub struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>
}

impl DNSPacket {
    pub fn decode(packet: Vec<u8>) -> Result<DNSPacket> {
        let mut packet_iter = packet.iter();
        let mut questions = vec![];
        let mut answers = vec![];
        let mut authorities = vec![];
        let mut additionals = vec![];

        let header = DNSHeader::decode(&mut packet_iter)?;
        for _ in 0..header.num_questions() {
            let question = DNSQuestion::decode(&mut packet_iter)?;
            questions.push(question);
        }
        for _ in 0..header.num_answers() {
            let answer = DNSRecord::decode(&mut packet_iter, &mut packet.iter())?;
            answers.push(answer);
        }
        for _ in 0..header.num_authorities() {
            let rr = DNSRecord::decode(&mut packet_iter, &mut packet.iter())?;
            authorities.push(rr);
        }
        for _ in 0..header.num_additionals() {
            let rr = DNSRecord::decode(&mut packet_iter, &mut packet.iter())?;
            additionals.push(rr);
        }
        
        Ok(DNSPacket { header, questions, answers, authorities, additionals })
    }

    // pub fn encode(&self) -> Result<Vec<u8>> {
        // let buf: Vec<u8> = vec![];
        // self.header.encode(&mut buf);
        // for q in self.questions {
            // q.encode(&mut buf);
        // }
        // Ok(buf);
    // }

    pub fn answers(&self, record_type: &RRType) -> Vec<String> {
        let mut answers = vec![];
        for ans in &self.answers {
            if ans.r_type() == record_type {
                if let Some(data) = ans.parsed_data() {
                    answers.push(data.to_owned());
                }
            }
        }
        answers
    }

    pub fn ns_ip(&self) -> &Option<String> {
        for additional in &self.additionals {
            if additional.r_type() == &RRType::A  {
                return additional.parsed_data();
            }
        }
        &None
    }

    pub fn nameserver(&self) -> &Option<String> {
        for ns in &self.authorities {
            if ns.r_type() == &RRType::NS {
                return ns.parsed_data();
            }
        }
        &None
    }
}
