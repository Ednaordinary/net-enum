use std::fs::File;
use std::io::{BufReader, Read};
use std::net::Ipv4Addr;

use clap::Parser;

mod lib;

use lib::*;

/// Reader for the convoy save format
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// File to read from
    #[arg(short, long)]
    file: String,
}

fn main() {
    let args = Args::parse();
    let file = File::open(args.file).unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 6];
    let mut meta: Metadata;
    loop {
        match reader.read_exact(&mut buffer) {
            Ok(()) => {
                meta = Metadata::from_bytes(buffer);
                println!("{}:{}", Ipv4Addr::from_bits(meta.ip), meta.port.to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // eprintln!("{}", e);
                // eprintln!(
                // "File bytes were not a multiple of 6. Are you sure this is a convoy scan file?"
                // );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }
}
