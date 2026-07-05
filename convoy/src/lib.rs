use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

use ipnet::Ipv4Net;
use regex::Regex;

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
