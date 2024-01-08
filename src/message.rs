use crate::error::Result;
use crate::{
    query::{DNSHeader, DNSQuestion},
    resource_record::DNSRecord,
    rr_types::RRType,
};

// DNSMessage represents a DNS message.
#[derive(Debug)]
pub struct DNSMessage {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl DNSMessage {
    pub fn new(
        header: DNSHeader,
        questions: Vec<DNSQuestion>,
        answers: Vec<DNSRecord>,
        authorities: Vec<DNSRecord>,
        additionals: Vec<DNSRecord>,
    ) -> DNSMessage {
        DNSMessage {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    // Decode the message from its wire format into our representation.
    pub fn decode(message: &Vec<u8>) -> Result<DNSMessage> {
        let mut message_iter = message.iter();
        let mut questions = vec![];
        let mut answers = vec![];
        let mut authorities = vec![];
        let mut additionals = vec![];

        let header = DNSHeader::decode(&mut message_iter)?;
        for _ in 0..header.num_questions() {
            let question = DNSQuestion::decode(&mut message_iter)?;
            questions.push(question);
        }
        for _ in 0..header.num_answers() {
            let answer = DNSRecord::decode(&mut message_iter, &mut message.iter())?;
            answers.push(answer);
        }
        for _ in 0..header.num_authorities() {
            let rr = DNSRecord::decode(&mut message_iter, &mut message.iter())?;
            authorities.push(rr);
        }
        for _ in 0..header.num_additionals() {
            let rr = DNSRecord::decode(&mut message_iter, &mut message.iter())?;
            additionals.push(rr);
        }

        Ok(DNSMessage {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    // Encode the message into the wire format.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        self.header.encode(&mut encoded);
        for question in &self.questions {
            question.encode(&mut encoded)?;
        }
        for answer in &self.answers {
            answer.encode(&mut encoded)?;
        }
        for authority in &self.authorities {
            authority.encode(&mut encoded)?;
        }
        for additional in &self.additionals {
            additional.encode(&mut encoded)?;
        }
        Ok(encoded)
    }

    pub fn set_id(&mut self, id: u16) {
        self.header.set_id(id);
    }

    // Returns the entire answers section.
    pub fn answers(&mut self) -> &Vec<DNSRecord> {
        &self.answers
    }

    // Returns the data of a particular record type from the answers section.
    pub fn answers_data(&self, record_type: &RRType) -> Vec<String> {
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

    // Returns the data of the first A record in the additionals section.
    pub fn ns_ip(&self) -> &Option<String> {
        for additional in &self.additionals {
            if additional.r_type() == &RRType::A {
                return additional.parsed_data();
            }
        }
        &None
    }

    // Returns the data of the first NS record in the authorities section.
    pub fn nameserver(&self) -> &Option<String> {
        for ns in &self.authorities {
            if ns.r_type() == &RRType::NS {
                return ns.parsed_data();
            }
        }
        &None
    }
}
