extern crate pnet;

use default_net::{Interface, interface};
use pnet::datalink::{NetworkInterface, interfaces};
use pnet::packet::{
    MutablePacket, Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags::SYN, TcpPacket},
};
use pnet::util::MacAddr;
use pnet_macros_support::types::u16be;

use ipnet::Ipv4Net;
use tokio::task::JoinSet;
use xsk_rs::config::{QueueSize, SocketConfig, UmemConfig, XdpFlags};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use std::env;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_scoped::TokioScope;

fn handle_recv(packet: &[u8], range: &Ipv4Net) {
    let eth = EthernetPacket::new(packet).unwrap();
    let packet_vec = eth.payload().to_vec();
    let ip_packet = Ipv4Packet::new(&packet_vec).unwrap();
    let source = ip_packet.get_source();
    let in_range = range.contains(&source);
    if in_range {
        match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet: TcpPacket = TcpPacket::new(ip_packet.payload()).unwrap();
                println!(
                    "Tcp {0}:{1} -> {2}:{3} - {4}",
                    ip_packet.get_source(),
                    tcp_packet.get_source().to_string(),
                    ip_packet.get_destination().to_string(),
                    tcp_packet.get_destination().to_string(),
                    tcp_packet.get_flags().to_string(),
                );
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
) {
    loop {
        unsafe {
            fq.produce(descs);
            let packets = rx_q.poll_and_consume(descs, 100).unwrap();
            for packet in descs.iter().take(packets) {
                let data = umem.data(packet);
                handle_recv(data.contents(), range);
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
        let write_res = cursor.write_all(packet).err();
        if write_res.is_some() {
            println!("Failed to write full frame buffer");
        }
    }
}

fn fill_descs(
    descs: &mut [FrameDesc],
    umem: &Umem,
    ips: Vec<Ipv4Addr>,
    partial_sum: u32,
    ipv4_packet: &[u8],
    eth_packet: &[u8],
) {
    for (desc, ip) in descs.iter_mut().zip(ips) {
        let mut vec_packet = ipv4_packet.to_vec();
        let packet = MutableIpv4Packet::new(&mut vec_packet).unwrap();
        craft_tcp_packet_inplace(packet, ip, partial_sum);
        vec_packet = [eth_packet, &vec_packet].concat().to_vec();
        write_tcp_packet(&mut vec_packet, &umem, desc);
    }
}

fn send_loop(
    descs: &mut [FrameDesc],
    umem: &Umem,
    ips: &Ipv4Net,
    partial_sum: u32,
    ipv4_packet: &MutableIpv4Packet,
    eth_packet: &[u8],
    tx_q: &mut TxQueue,
    cq: &mut CompQueue,
    mut fill_amt: usize,
    send_mul: u32,
) -> usize {
    let mut sent: usize = 0;
    let mut count: u32 = 0;
    let mut start = Instant::now();
    loop {
        count += 1;
        let ip_chunk: Vec<Ipv4Addr> = ips.hosts().take(fill_amt).collect();
        let chunk_len = ip_chunk.len();
        if chunk_len == 0 {
            break;
        }
        if send_mul != 0 && count.rem_euclid(1000) == 0 {
            print!(
                "pps {}   \r",
                sent * send_mul as usize * 1000 / start.elapsed().as_millis() as usize
            );
            std::io::stdout().flush().unwrap();
            count = 0;
            sent = 0;
            start = Instant::now();
        }
        fill_descs(
            &mut descs[..chunk_len],
            umem,
            ip_chunk,
            partial_sum,
            ipv4_packet.packet(),
            eth_packet,
        );
        unsafe {
            //while !tx_q.poll(100).unwrap() {
            //    println!("poll failed");
            //}
            while { tx_q.produce_and_wakeup(&mut descs[..chunk_len]).unwrap() } < 1 {}
            fill_amt = 0;
            while fill_amt == 0 {
                fill_amt = cq.consume(&mut descs[..])
            }
            sent += fill_amt;
        }
    }
    if send_mul != 0 {
        print!("\r          \r");
    }
    fill_amt
}

fn send_packets(
    source_ip: &Ipv4Addr,
    remote_ips: &Ipv4Net,
    source_port: u16,
    remote_ports: Vec<u16>,
    gate_mac: MacAddr,
    mac: MacAddr,
    umem: &Umem,
    mut tx_q: TxQueue,
    cq: &mut CompQueue,
    descs: &mut [FrameDesc],
    send_mul: u32,
) -> Result<u128, Box<dyn std::error::Error>> {
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
    }
    //let mut packet = MutableIpv4Packet::from(ip_packet);
    let mut fill_amt = descs.len();
    for port in remote_ports.iter() {
        println!("port {}", port);
        {
            let mut base_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
            base_packet.set_destination(*port);
        }
        fill_amt = send_loop(
            descs,
            &umem,
            remote_ips,
            part_sum,
            &ip_packet,
            &eth_buffer,
            &mut tx_q,
            cq,
            fill_amt,
            send_mul,
        );
    }
    Ok(remote_ports.len() as u128 * 2u128.pow(remote_ips.prefix_len() as u32))
}

fn calculate_ips(range: String) -> Ipv4Net {
    let ips: Ipv4Net = Ipv4Net::from_str(&range).expect(&format!("Could not parse {}", range));
    ips
}

fn make_socket(
    interface: &NetworkInterface,
    buffer: u32,
    q_id: u32,
) -> (
    (TxQueue, RxQueue, Option<(FillQueue, CompQueue)>),
    Umem,
    Vec<FrameDesc>,
) {
    println!("making socket");
    let (umem, descs) = Umem::new(
        UmemConfig::builder()
            .comp_queue_size(QueueSize::new(1024).unwrap())
            .fill_queue_size(QueueSize::new(1024).unwrap())
            //.frame_size(FrameSize::new(2048).unwrap())
            .build()
            .unwrap(),
        buffer.try_into().unwrap(),
        false,
    )
    .unwrap();
    println!("made umem");
    let socket = unsafe {
        Socket::new(
            SocketConfig::builder()
                .tx_queue_size(QueueSize::new(1024).unwrap())
                .xdp_flags(XdpFlags::XDP_FLAGS_SKB_MODE)
                .build(),
            &umem,
            &interface.name.parse().unwrap(),
            q_id,
        )
    }
    .unwrap();
    (socket, umem, descs)
}

#[tokio::main]
async fn main() {
    let range = env::args().nth(1).unwrap();
    let mut ports: Vec<u16> = Vec::new();
    let scan_range_1 = env::args().nth(2).unwrap().parse::<u16>().unwrap();
    let scan_range_2 = env::args().nth(3).unwrap_or("".to_string());
    if scan_range_2 != "" {
        let scan_range_2 = scan_range_2.parse::<u16>().unwrap();
        (scan_range_1..scan_range_2).for_each(|x| ports.push(x));
    } else {
        ports.push(scan_range_1);
    }
    let tx_amt: u32 = 4;
    let ips = calculate_ips(range);
    let packets: u128 = ports.len() as u128 * 2u128.pow(32 - ips.prefix_len() as u32) as u128;
    println!("Sending: {}", packets);
    println!("Total size (bytes): {}", packets * 54);
    let ifs = interfaces();
    let if_default = default_net::get_default_interface().unwrap();
    let interface = ifs.into_iter().find(|x| x.name == if_default.name).unwrap();
    let gate = default_net::get_default_gateway().unwrap();
    let mac: MacAddr = interface.mac.unwrap();
    let gate_mac: MacAddr = MacAddr::from(gate.mac_addr.octets());
    let ip_len = 2u128.pow(32 - ips.prefix_len() as u32);
    let chunk_prefix = std::cmp::min(32, ips.prefix_len() + tx_amt.ilog2() as u8);
    let chunk_amt = 2_i32.pow(chunk_prefix - ips.prefix_len());
    let ip_chunks = ips.subnets(chunk_prefix).unwrap();
    let ip = interface.ips.first().unwrap().ip();
    println!("if: {}", interface.name);
    let mut q_id: u32 = 0;
    let start = Instant::now();
    match ip {
        IpAddr::V4(v4_addr) => {
            println!("{}", v4_addr);
            for (idx, ip_chunk) in ip_chunks.enumerate() {
                println!("{}", idx);
                if q_id == (chunk_amt - 1) as u32 {
                    let ((tx_q, rx_q, fq_cq), umem, mut descs) =
                        make_socket(&interface, 2048, q_id);
                    let desc_len = descs.len();
                    let (mut rx_desc, mut tx_desc) = descs.split_at_mut(desc_len / 2);
                    let (fq, mut cq) = fq_cq.unwrap();
                    let ips_clone = ips.clone();
                    std::thread::scope(|s| {
                        let umem_ref = &umem;
                        s.spawn(move || {
                            recv(rx_q, fq, &mut rx_desc, umem_ref, &ips_clone);
                        });
                        let ip_ref = ip_chunk;
                        let ports_clone = ports.clone();
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
                            &mut tx_desc,
                            tx_amt as u32,
                        )
                        .unwrap();
                        let elapsed = start.elapsed().as_millis();
                        std::thread::sleep(Duration::from_secs(2));
                        println!("meowtime {:.2}", packets * 1000 / elapsed);
                        return;
                    });
                } else {
                    let ((tx_q, _rx_q, fq_cq), umem, mut descs) =
                        make_socket(&interface, 1024, q_id);
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
