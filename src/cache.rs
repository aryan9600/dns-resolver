use std::{cmp::Reverse, collections::HashMap, time::Instant};

use priority_queue::PriorityQueue;

use crate::{domain_name::DomainName, resource_record::DNSRecord, rr_types::RRType};

// A LRU cache with a fixed capacity that stores DNS answer records indexed by the
// domain name and record type.
#[derive(Debug, Clone)]
pub struct DNSCache {
    cache: HashMap<CachedAnswerKey, CachedAnswer>,
    // Helps track the least recently used key in the above cache.
    lru_priority: PriorityQueue<CachedAnswerKey, Reverse<Instant>>,
    max_size: usize,
}

// The key that is used to store DNS answer records.
#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct CachedAnswerKey {
    domain_name: DomainName,
    q_type: RRType,
}

// The answer thats stored in the cache.
#[derive(Debug, Clone)]
pub struct CachedAnswer {
    records: Vec<DNSRecord>,
    last_read: Instant,
    inserted_at: Instant,
}

impl CachedAnswer {
    // If the answer has expired. Returns true, if any record has expired.
    pub fn expired(&self) -> bool {
        let elapsed = self.inserted_at.elapsed().as_secs();
        for record in &self.records {
            if elapsed > record.ttl().as_secs() {
                return true;
            }
        }
        false
    }

    pub fn data(&self) -> Vec<DNSRecord> {
        self.records.clone()
    }
}

impl DNSCache {
    pub fn new(max_size: usize) -> DNSCache {
        let records = HashMap::new();
        let lru_priority = PriorityQueue::new();
        DNSCache {
            cache: records,
            lru_priority,
            max_size,
        }
    }

    // Gets the cached answer for the provided domain name and record type. Returns None if
    // the answer does not exist or it has expired.
    pub fn get(&mut self, domain_name: &DomainName, q_type: &RRType) -> Option<CachedAnswer> {
        let key = CachedAnswerKey {
            domain_name: domain_name.clone(),
            q_type: q_type.clone(),
        };

        let mut expired = false;
        if let Some(record) = self.cache.get_mut(&key) {
            record.last_read = Instant::now();

            expired = record.expired();
            if !expired {
                self.lru_priority
                    .change_priority(&key, Reverse(record.last_read));
                return Some(record.clone());
            }
        }

        if expired {
            self.cache.remove(&key);
            self.lru_priority.remove(&key);
        }

        None
    }

    // Insert the answer records mapped to the provided domain name and record type. If a fresh
    // record already exists for the provided key in the cache, then its a no-op.
    pub fn insert(&mut self, domain_name: &DomainName, q_type: &RRType, records: Vec<DNSRecord>) {
        let key = CachedAnswerKey {
            domain_name: domain_name.clone(),
            q_type: q_type.clone(),
        };
        let now = Instant::now();
        let answer = CachedAnswer {
            records,
            last_read: now,
            inserted_at: now,
        };

        if let Some(old_answer) = self.cache.get_mut(&key) {
            if old_answer.expired() {
                self.cache.insert(key.clone(), answer.clone());
                self.lru_priority.change_priority(&key, Reverse(now));
            }
        } else {
            // Make sure we have room in our cache for the new entry.
            self.evict();

            self.cache.insert(key.clone(), answer);
            self.lru_priority.push(key, Reverse(now));
        }
    }

    // Evict removes all expired records and then removes the least recently used element until the
    // size of the cache is less than the configured capacity.
    pub fn evict(&mut self) {
        // First, try to remove all expired records.
        self.cache.retain(|_, record| !record.expired());

        // If we still don't have room, i.e. there are no expired records at the moment,
        // then remove the least recently read record until we have space for a new entry.
        while self.cache.len() >= self.max_size {
            self.remove_least_recently_used();
        }
    }

    pub fn remove_least_recently_used(&mut self) {
        if let Some((key, _)) = self.lru_priority.pop() {
            self.cache.remove(&key);
        }
    }
}
