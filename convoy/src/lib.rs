use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;

use ipnet::Ipv4Net;
use regex::Regex;

#[derive(Clone, PartialEq)]
pub struct Metadata {
    pub ip: u32,
    pub port: u16,
}

impl Metadata {
    pub fn to_bytes(&self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        let (l, r) = bytes.split_at_mut(4);
        l.copy_from_slice(&self.ip.to_be_bytes());
        r.copy_from_slice(&self.port.to_be_bytes());
        bytes
    }

    pub fn from_bytes(b: [u8; 6]) -> Self {
        let (l, r) = b.split_at(4);
        let l_deref: [u8; 4] = l.try_into().unwrap();
        let r_deref: [u8; 2] = r.try_into().unwrap();
        Self {
            ip: u32::from_be_bytes(l_deref),
            port: u16::from_be_bytes(r_deref),
        }
    }

    pub fn file_append(&self, file: &str) {
        let mut on_disk = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file)
            .unwrap();
        on_disk.write_all(&self.to_bytes()).unwrap();
    }
}

pub struct Dedupe<T, const N: usize> {
    buffer: [Option<T>; N],
    cursor: usize,
}

impl<T: PartialEq + Clone, const N: usize> Dedupe<T, N> {
    pub fn new() -> Self {
        Self {
            buffer: std::array::from_fn(|_| None),
            cursor: 0,
        }
    }

    pub fn check(&mut self, item: &T) -> bool {
        for slot in self.buffer.iter() {
            if let Some(existing) = slot {
                if existing == item {
                    return true;
                }
            }
        }

        self.buffer[self.cursor] = Some(item.clone());

        self.cursor = (self.cursor + 1) % N;

        false
    }
}

pub fn read_exclude(list: &str) -> Vec<Ipv4Net> {
    let re = Regex::new(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))?$").unwrap();
    let mut excl: Vec<Ipv4Net> = Vec::new();
    let file = File::open(list).unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let content = line.unwrap();
        if re.is_match(&content) {
            let cidr: Ipv4Net;
            if content.contains("/") {
                cidr = Ipv4Net::from_str(&content).unwrap();
            } else {
                cidr = Ipv4Net::from_str(&(content + "/32")).unwrap();
            }
            excl.push(cidr);
        }
    }
    excl
}
