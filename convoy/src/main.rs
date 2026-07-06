extern crate pnet;

use aya::maps::{MapData, MapError};
use ipnet::Ipv4Net;
use iprange::IpRange;
use pnet::datalink::{NetworkInterface, interfaces};
use pnet::packet::tcp::TcpOption;
use pnet::packet::{
    MutablePacket, Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags::SYN, TcpPacket},
};
use pnet::util::MacAddr;
use pnet_macros_support::types::u16be;

use xsk_rs::config::{FrameSize, LibxdpFlags, QueueSize, SocketConfig, UmemConfig, XdpFlags};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use std::env;
use std::fmt::Debug;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, XskMap},
    programs::{Xdp, XdpMode},
};
use aya_log::EbpfLogger;

use anyhow::Result;
use clap::Parser;
use itertools::Itertools;
use rand::seq::IteratorRandom;

mod lib;

use lib::*;

//
/// A speedy af_xdp port scanner
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// CIDR range of IPs to scan
    #[arg(short, long)]
    range: String,

    /// TX queues to use
    #[arg(long, default_value_t = 1)]
    tx: u8,

    /// Port range start
    #[arg(short)]
    b: u16,

    /// Port range end
    #[arg(short, default_value_t = 0)]
    e: u16,

    /// Interface to use
    #[arg(short, long, default_value = "")]
    net: String,

    /// Umem buffer size exponent
    #[arg(short, default_value_t = 7, value_parser = clap::value_parser!(u8).range(7..))]
    u: u8,

    /// Queue size exponent
    #[arg(short, default_value_t = 20)]
    q: u8,

    /// Exclude list
    #[arg(long, default_value = "")]
    exclude: String,

    /// Write to file
    #[arg(short, long, default_value = "")]
    file: String,

    /// Do not print received packets;
    #[arg(long)]
    quiet: bool,
}

fn toggle_capture_port(
    ebpf: &mut Ebpf,
    port: u16,
    enabled: bool,
) -> Result<(), aya::maps::MapError> {
    let mut bitmap = Array::try_from(ebpf.map_mut("CAPTURE_PORTS_BITMAP").unwrap())?;

    let value: u8 = if enabled { 1 } else { 0 };
    bitmap.set(port as u32, value, 0)?;

    Ok(())
}

fn handle_recv(
    packet: &[u8],
    range: &Ipv4Net,
    dedupe: &mut Dedupe<Metadata, 4096>,
    file: Option<&str>,
    quiet: &bool,
) {
    let eth = EthernetPacket::new(packet).unwrap();
    let packet_vec = eth.payload().to_vec();
    let ip_packet = Ipv4Packet::new(&packet_vec).unwrap();
    let source = ip_packet.get_source();
    let in_range = range.contains(&source);
    if in_range {
        match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet: TcpPacket = TcpPacket::new(ip_packet.payload()).unwrap();
                let meta = Metadata {
                    ip: ip_packet.get_source().to_bits(),
                    port: tcp_packet.get_source(),
                };
                let dupe = dedupe.check(&meta);
                if !dupe {
                    if !*quiet {
                        println!(
                            "Tcp {0}:{1} -> {2}:{3} - {4}",
                            ip_packet.get_source(),
                            tcp_packet.get_source().to_string(),
                            ip_packet.get_destination().to_string(),
                            tcp_packet.get_destination().to_string(),
                            tcp_packet.get_flags().to_string(),
                        );
                    }
                    if file.is_some() {
                        meta.file_append(file.unwrap())
                    }
                }
            }
            _ => {}
        }
    }
}

fn recv(
    mut rx_q: RxQueue,
    mut fq: FillQueue,
    descs: &mut [FrameDesc],
    umem: &Umem,
    range: &Ipv4Net,
    file: Option<&str>,
    quiet: bool,
) {
    let mut dedupe: Dedupe<Metadata, 4096> = Dedupe::new();
    loop {
        unsafe {
            fq.produce(descs);
            let packets = rx_q.poll_and_consume(descs, 100).unwrap();
            for packet in descs.iter().take(packets) {
                let data = umem.data(packet);
                handle_recv(data.contents(), range, &mut dedupe, file, &quiet);
            }
        }
    }
}

fn craft_eth_packet<'a>(
    source: MacAddr,
    dest: MacAddr,
    buffer: &'a mut [u8],
) -> MutableEthernetPacket<'a> {
    let mut eth_packet = MutableEthernetPacket::new(buffer).unwrap();
    eth_packet.set_source(source);
    eth_packet.set_destination(dest);
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet
}

fn craft_ip_packet<'a>(source_ip: Ipv4Addr, buffer: &'a mut [u8]) -> MutableIpv4Packet<'a> {
    let mut ip_packet = MutableIpv4Packet::new(buffer).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_source(source_ip);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_identification(1);
    ip_packet.set_flags(0b010);
    ip_packet.set_dscp(0);
    ip_packet.set_ecn(0);
    ip_packet
}

// Copied from pnet::utils
fn ipv4_word_sum(ip: &Ipv4Addr) -> u32 {
    let octets = ip.octets();
    ((octets[0] as u32) << 8 | octets[1] as u32) + ((octets[2] as u32) << 8 | octets[3] as u32)
}

// Copied from pnet::utils
fn finalize_checksum(mut sum: u32) -> u16be {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

// Copied from pnet::utils
fn sum_be_words(data: &[u8], skipword: usize) -> u32 {
    if data.len() == 0 {
        return 0;
    }
    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;
    while cur_data.len() >= 2 {
        if i != skipword {
            // It's safe to unwrap because we verified there are at least 2 bytes
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    // If the length is odd, make sure to checksum the final byte
    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    sum
}

fn craft_tcp_packet_inplace(mut ipv4_packet: MutableIpv4Packet, ip: Ipv4Addr, partial_sum: u32) {
    ipv4_packet.set_destination(ip.to_owned());
    ipv4_packet.set_checksum(pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable()));
    let mut part_sum = partial_sum;
    part_sum += ipv4_word_sum(&ip);
    let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
    part_sum += sum_be_words(tcp_packet.packet(), 8);
    tcp_packet.set_checksum(finalize_checksum(part_sum));
}

fn write_tcp_packet(packet: &[u8], umem: &Umem, desc: &mut FrameDesc) {
    unsafe {
        let mut mut_frame = umem.data_mut(desc);
        let mut cursor = mut_frame.cursor();
        cursor.set_pos(0);
        let write_res = cursor.write_all(packet).err();
        if write_res.is_some() {
            println!("{:?} Frame len: {:?}", write_res, desc.lengths());
        }
    }
}

fn fill_descs(
    descs: &mut [FrameDesc],
    umem: &Umem,
    ips: &Vec<Ipv4Addr>,
    partial_sum: u32,
    ipv4_packet: &[u8],
    eth_packet: &[u8],
) {
    descs.iter_mut().zip(ips).for_each(|(desc, ip)| {
        let mut vec_packet = ipv4_packet.to_vec();
        let packet = MutableIpv4Packet::new(&mut vec_packet).unwrap();
        craft_tcp_packet_inplace(packet, *ip, partial_sum);
        vec_packet = [eth_packet, &vec_packet].concat().to_vec();
        write_tcp_packet(&mut vec_packet, &umem, desc);
    });
}

fn send_packets(
    source_ip: &Ipv4Addr,
    remote_ips: &Vec<Ipv4Net>,
    source_port: u16,
    remote_ports: Vec<u16>,
    gate_mac: MacAddr,
    mac: MacAddr,
    umem: &Umem,
    mut tx_q: TxQueue,
    cq: &mut CompQueue,
    descs: &mut [FrameDesc],
    send_mul: u32,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let mut part_sum = ipv4_word_sum(source_ip);
    let IpNextHeaderProtocol(protocol) = IpNextHeaderProtocols::Tcp;
    part_sum += protocol as u32;
    part_sum += 20; // data len
    let mut eth_buffer = [0; 14];
    craft_eth_packet(mac, gate_mac, &mut eth_buffer);
    let mut ip_buffer = [0; 40];
    let mut ip_packet = craft_ip_packet(*source_ip, &mut ip_buffer);
    let tcp_seq = rand::random::<u32>();
    {
        let mut base_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        base_packet.set_source(source_port);
        base_packet.set_sequence(tcp_seq);
        base_packet.set_window(64240);
        base_packet.set_flags(SYN);
        base_packet.set_data_offset(5);
        base_packet.set_reserved(0);
        base_packet.set_urgent_ptr(0);
        // if you wanna slopify your packets for some reason
        // let mut opts = vec![
        //     TcpOption::mss(1460),
        //     TcpOption::nop(),
        //     TcpOption::wscale(7),
        //     TcpOption::sack_perm(),
        //     TcpOption::timestamp(12345678, 0),
        // ];
        // opts.extend(std::iter::repeat(TcpOption::nop()).take(16));
        // base_packet.set_options(&opts);
    }
    let req = remote_ips
        .iter()
        .map(|x| 2u32.pow(32 - x.prefix_len() as u32))
        .sum::<u32>();
    let mut available = descs.len();
    let mut all_sent: u64 = 0;
    let mut consumed: usize;
    let mut percent: u64;
    let mut last_percent: u64 = 0;
    for port in remote_ports.iter() {
        println!("Port {}", port);
        let mut sent: u32 = 0;
        {
            let mut base_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
            base_packet.set_destination(*port);
        }
        let mut hosts = remote_ips.into_iter().map(|x| x.hosts()).flatten();
        unsafe {
            loop {
                while available == 0 {
                    let consumed = cq.consume(&mut descs[..]);
                    if consumed > 0 {
                        sent += consumed as u32;
                        available += consumed;
                    } else if tx_q.needs_wakeup() {
                        tx_q.wakeup().unwrap();
                    }
                }
                let ip_chunk: Vec<Ipv4Addr> = hosts.by_ref().take(available).collect();
                if ip_chunk.len() == 0 {
                    break;
                }
                fill_descs(
                    &mut descs[..ip_chunk.len()],
                    umem,
                    &ip_chunk,
                    part_sum,
                    &ip_packet.packet(),
                    &eth_buffer,
                );
                let mut submit = 0;
                while submit < ip_chunk.len() {
                    let n = tx_q
                        .produce_and_wakeup(&descs[submit..ip_chunk.len()])
                        .unwrap();
                    if n > 0 {
                        submit += n;
                        available -= n;
                    } else {
                        let consumed = cq.consume(&mut descs[..]);
                        sent += consumed as u32;
                        available += consumed;
                    }
                }
                let consumed = cq.consume(&mut descs[..]);
                sent += consumed as u32;
                available += consumed;
                percent = sent as u64 * 100 / req as u64;
                if percent != last_percent {
                    print!("{}%      \r", sent * 100 / req);
                    std::io::stdout().flush().unwrap();
                }
                last_percent = percent;
            }
        }
        let total_descs = descs.len();
        while available < total_descs {
            let consumed = unsafe { cq.consume(&mut descs[..]) };
            if consumed > 0 {
                sent += consumed as u32;
                available += consumed;
            } else if tx_q.needs_wakeup() {
                tx_q.wakeup().unwrap();
            }
        }
        print!("\r          \r");
        all_sent += sent as u64;
    }
    Ok((all_sent, remote_ports.len() as u64 * req as u64))
}

fn calculate_ips(range: String) -> Ipv4Net {
    let ips: Ipv4Net = Ipv4Net::from_str(&range).expect(&format!("Could not parse {}", range));
    ips
}

fn inject_ebpf(interface: &str) -> Ebpf {
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../convoy-ebpf/target/bpfel-unknown-none/release/convoy-ebpf"
    ))
    .unwrap();
    let program: &mut Xdp = bpf.program_mut("xsk_def_prog").unwrap().try_into().unwrap();
    program.load().unwrap();
    program.attach(interface, XdpMode::Default).unwrap();
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        eprintln!("Failed to initialize eBPF logger: {}", e);
    }
    bpf
}

fn make_socket(
    interface: &NetworkInterface,
    umem_size: u32,
    in_queue_size: u32,
    out_queue_size: u32,
    q_id: u32,
    ebpf: &mut Ebpf,
) -> (
    (TxQueue, RxQueue, Option<(FillQueue, CompQueue)>),
    Umem,
    Vec<FrameDesc>,
) {
    let (umem, descs) = Umem::new(
        UmemConfig::builder()
            .comp_queue_size(QueueSize::new(in_queue_size).unwrap())
            .fill_queue_size(QueueSize::new(in_queue_size).unwrap())
            .frame_size(FrameSize::new(2048).unwrap())
            .build()
            .unwrap(),
        umem_size.try_into().unwrap(),
        false,
    )
    .unwrap();
    let socket = unsafe {
        Socket::new(
            SocketConfig::builder()
                .tx_queue_size(QueueSize::new(out_queue_size).unwrap())
                .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
                .build(),
            &umem,
            &interface.name.parse().unwrap(),
            q_id,
        )
    }
    .unwrap();
    let xsks_map_obj = ebpf.map_mut("XSKS_MAP").unwrap();
    let mut xsks_map = XskMap::try_from(xsks_map_obj).unwrap();
    xsks_map.set(q_id, socket.0.fd().as_raw_fd(), 0).unwrap();
    (socket, umem, descs)
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main());
}

async fn async_main() {
    let args = Args::parse();
    let range = args.range;
    let mut ports: Vec<u16> = Vec::new();
    if args.e != 0 {
        println!("Scanning ports {}..{}", args.b, args.e + 1);
        (args.b..args.e + 1).for_each(|x| ports.push(x));
    } else {
        println!("Scanning port {}", args.b);
        ports.push(args.b);
    }
    let ips = calculate_ips(range);
    let excl: Vec<Ipv4Net> = if args.exclude != "" {
        read_exclude(&args.exclude)
    } else {
        Vec::new()
    };
    // Below does not include exclude list, so it is an overshoot estimation
    //let packets: u64 = ports.len() as u64 * 2u64.pow(32 - ips.prefix_len() as u32) as u64;
    // println!("Sending: {}", packets);
    // println!("Total size (bytes): {}", packets * 54);
    let ifs = interfaces();
    let if_default: String = if args.net != "" {
        args.net
    } else {
        default_net::get_default_interface().unwrap().name
    };
    let interface = ifs.into_iter().find(|x| x.name == if_default).unwrap();
    let mac: MacAddr = interface.mac.unwrap();
    let gate_mac: MacAddr = MacAddr::from(
        default_net::get_default_gateway()
            .unwrap()
            .mac_addr
            .octets(),
    );
    let chunk_prefix = std::cmp::min(32, ips.prefix_len() + args.tx.ilog2() as u8);
    let chunk_amt = 2_i32.pow((chunk_prefix - ips.prefix_len()) as u32);
    let ip_chunks = ips.subnets(chunk_prefix).unwrap();
    let ip_chunks: Vec<Vec<Ipv4Net>> = ip_chunks
        .map(|x| {
            let mut range: IpRange<Ipv4Net> = IpRange::new();
            range.add(x);
            excl.iter().for_each(|y| {
                let mut yrange = IpRange::new();
                yrange.add(*y);
                range = range.exclude(&yrange);
            });
            range.into_iter().collect()
        })
        .collect();
    let ip = interface.ips.first().unwrap().ip();
    println!("if: {}", interface.name);
    let mut q_id: u32 = 0;
    let mut ebpf = inject_ebpf(&interface.name);
    ports
        .iter()
        .for_each(|x| toggle_capture_port(&mut ebpf, *x, true).unwrap());
    match ip {
        IpAddr::V4(v4_addr) => {
            println!("{}", v4_addr);
            for ip_chunk in ip_chunks {
                if q_id == (chunk_amt - 1) as u32 {
                    let ((tx_q, rx_q, fq_cq), umem, mut descs) = make_socket(
                        &interface,
                        2u32.pow(args.u as u32),
                        2u32.pow(args.q as u32),
                        2u32.pow(args.q as u32),
                        q_id,
                        &mut ebpf,
                    );
                    let desc_len = descs.len();
                    let (mut rx_desc, mut tx_desc) = descs.split_at_mut(desc_len / 2);
                    let (fq, mut cq) = fq_cq.unwrap();
                    let ips_clone = ips.clone();
                    std::thread::scope(|s| {
                        let umem_ref = &umem;
                        s.spawn(move || {
                            recv(
                                rx_q,
                                fq,
                                &mut rx_desc,
                                umem_ref,
                                &ips_clone,
                                if args.file != "" {
                                    Some(&args.file)
                                } else {
                                    None
                                },
                                args.quiet,
                            );
                        });
                        let ip_ref = ip_chunk;
                        let ports_clone = ports.clone();
                        let start = Instant::now();
                        let (packets, req) = send_packets(
                            &v4_addr,
                            &ip_ref,
                            34567,
                            ports_clone,
                            gate_mac,
                            mac,
                            &umem,
                            tx_q,
                            &mut cq,
                            &mut tx_desc,
                            args.tx as u32,
                        )
                        .unwrap();
                        let elapsed = start.elapsed().as_secs_f64();
                        std::thread::sleep(Duration::from_secs(2));
                        println!("Packets requested: {}", req);
                        println!("Packets sent: {}", packets);
                        println!("Total real size (bytes): {}", packets * 54);
                        println!("Elapsed: {:.2}", elapsed);
                        // This is safe. packets will never exceed 2^48 so it fits in f64 mantissa
                        println!("Final pps {:.2}", packets as f64 / elapsed);
                        std::process::exit(0);
                    });
                } else {
                    let ((tx_q, _rx_q, fq_cq), umem, mut descs) = make_socket(
                        &interface,
                        2u32.pow(args.u as u32),
                        2u32.pow(args.q as u32),
                        2u32.pow(args.q as u32),
                        q_id,
                        &mut ebpf,
                    );
                    let (_fq, mut cq) = fq_cq.unwrap();
                    let ip_ref = ip_chunk;
                    let ports_clone = ports.clone();
                    tokio::task::spawn_blocking(move || {
                        send_packets(
                            &v4_addr,
                            &ip_ref,
                            34567,
                            ports_clone,
                            gate_mac,
                            mac,
                            &umem,
                            tx_q,
                            &mut cq,
                            &mut descs,
                            0,
                        )
                        .unwrap();
                    });
                }
                q_id += 1;
            }
        }
        IpAddr::V6(_) => {
            println!("Source is v6! Not implemented");
        }
    }
}
