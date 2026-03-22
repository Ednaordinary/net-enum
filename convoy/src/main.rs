extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::interfaces;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::{
    MutablePacket, Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags::SYN, TcpPacket},
};
use pnet::util::MacAddr;
use pnet_macros_support::types::u16be;

use cidr_utils::cidr::Ipv4Cidr;
use xsk_rs::config::{BindFlags, FrameSize, QueueSize, SocketConfig, UmemConfig, XdpFlags};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use std::env;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

fn handle_recv(packet: &[u8], ranges: &Vec<Ipv4Cidr>) {
    let eth = EthernetPacket::new(packet).unwrap();
    let packet_vec = eth.payload().to_vec();
    let ip_packet = Ipv4Packet::new(&packet_vec).unwrap();
    let source = ip_packet.get_source();
    let in_range = ranges.iter().any(|range| range.contains(&source));
    if in_range {
        println!("from: {:02X?}", packet_vec);
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
    ranges: &Vec<Ipv4Cidr>,
) {
    loop {
        unsafe {
            fq.produce(descs);
            let packets = rx_q.poll_and_consume(descs, 100).unwrap();
            for packet in descs.iter().take(packets) {
                let data = umem.data(packet);
                //handle_recv(data.contents(), ranges);
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

fn send_packets(
    source_ip: &Ipv4Addr,
    remote_ips: &Vec<Ipv4Cidr>,
    source_port: u16,
    remote_ports: Vec<u16>,
    gate_mac: MacAddr,
    mac: Option<MacAddr>,
    tx_umem: &Umem,
    mut tx_q: TxQueue,
    packet_batch_size: u16,
    mut cq: CompQueue,
    tx_descs: &mut [FrameDesc],
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let mut packets = 0u64;
    let mut packets_size = 0u64;
    let mut eth_buffer = [0; 14];
    let eth_packet;
    let eth_packet_buff: &[u8];
    let mut allowed_write = packet_batch_size - 1;
    println!("allowed_write: {}", allowed_write);
    let mut consumed = 0;
    match mac {
        Some(mac) => {
            eth_packet = craft_eth_packet(mac, gate_mac, &mut eth_buffer);
            eth_packet_buff = eth_packet.packet();
        }
        None => {
            eth_packet_buff = &[0; 0];
        }
    }
    for remote_port in remote_ports {
        println!("Now scanning port {}", remote_port);
        //std::thread::sleep(std::time::Duration::from_millis(2000));
        let start_time = std::time::Instant::now();
        let mut ip_buffer = [0; 40];
        let tcp_seq = rand::random::<u32>();
        let mut ip_packet = craft_ip_packet(*source_ip, &mut ip_buffer);
        {
            let mut base_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
            base_packet.set_source(source_port);
            base_packet.set_destination(remote_port);
            base_packet.set_sequence(tcp_seq);
            base_packet.set_window(64240);
            base_packet.set_flags(SYN);
            base_packet.set_data_offset(5);
            base_packet.set_reserved(0);
            base_packet.set_urgent_ptr(0);
        }
        let mut packet = MutableIpv4Packet::from(ip_packet);
        let mut unfinished_sum = 0u32;
        let mut dyn_sum: u32;
        unfinished_sum += ipv4_word_sum(source_ip);
        let protocol = IpNextHeaderProtocols::Tcp;
        let IpNextHeaderProtocol(protocol) = protocol;
        unfinished_sum += protocol as u32;
        unfinished_sum += 20; // data.len()
        for ip_set in remote_ips {
            for ip in ip_set.iter().addresses() {
                packet.set_destination(ip);

                packet.set_checksum(pnet::packet::ipv4::checksum(&packet.to_immutable()));
                let mut base_packet = MutableTcpPacket::new(packet.payload_mut()).unwrap();
                dyn_sum = unfinished_sum;
                dyn_sum += ipv4_word_sum(&ip);
                dyn_sum += sum_be_words(base_packet.packet(), 8);
                base_packet.set_checksum(finalize_checksum(dyn_sum));
                // base_packet.set_sequence(base_packet.get_sequence() + 1);
                packets += 1;
                packets_size += packet.packet().len() as u64;
                packets_size += eth_packet_buff.len() as u64;
                unsafe {
                    let mut mut_data = tx_umem.data_mut(&mut tx_descs[allowed_write as usize]);
                    let mut cursor = mut_data.cursor();
                    // cursor.set_pos(0);
                    let final_pack = &[eth_packet_buff, packet.packet()].concat();
                    //println!("to: {:02X?}", final_pack);
                    let write_res = cursor.write_all(final_pack).err();
                    if write_res.is_some() {
                        println!("Could not write full frame buffer {}", allowed_write);
                    }
                    //content_ptr[0..final_pack.len()] = final_pack;
                    //.cursor()
                    //.write_all(&[eth_packet_buff, packet.packet()].concat())
                    //.unwrap_or_else(|_x| {
                    //    println!(
                    //        "allowed_write: {}\nconsumed: {}\nlen: {}",
                    //        allowed_write,
                    //        consumed,
                    //        tx_descs.len()
                    //    )
                    //});
                    while !tx_q.poll(100).unwrap() {
                        println!("poll failed");
                    }
                    while { tx_q.produce_one(&tx_descs[allowed_write as usize]) } != 1 as usize {}
                }
                if allowed_write < 1 {
                    while consumed == 0 {
                        unsafe {
                            consumed += cq.consume(&mut tx_descs[..]) as u16;
                        }
                        if consumed == 0 && tx_q.needs_wakeup() {
                            tx_q.wakeup().unwrap();
                        }
                    }
                    allowed_write = consumed;
                    consumed = 0;
                }
                allowed_write -= 1;
            }
        }
        let mut remaining = packet_batch_size - allowed_write - 1;
        println!("remainder {}", remaining);
        unsafe {
            while remaining > 0 {
                while !tx_q.poll(100).unwrap() {
                    println!("poll failed (outer)");
                }
                let mut fr_recv = 0;
                while fr_recv == 0 {
                    fr_recv = cq.consume(&mut tx_descs[..]);
                    // println!("consumed {}", fr_recv);
                    if fr_recv == 0 {
                        if tx_q.needs_wakeup() {
                            tx_q.wakeup().unwrap();
                        }
                    }
                    break;
                }
                remaining -= fr_recv as u16;
            }
            allowed_write = packet_batch_size - 1;
            consumed = 0;
        }
        let end_time = std::time::Instant::now();
        let time_taken = end_time - start_time;
        //std::thread::sleep(std::time::Duration::from_millis(1000));
        //println!(
        //    "Packets per second ({}): {}",
        //    remote_port,
        //    packets as u128 * 1000000 / time_taken.as_micros()
        //);
    }
    Ok((packets, packets_size))
}

fn calculate_ips(ranges: Vec<String>) -> Vec<Ipv4Cidr> {
    let ips: Vec<Ipv4Cidr> = ranges
        .into_iter()
        .map(|x| Ipv4Cidr::from_str(&x).expect(&format!("Could not parse {}", x)))
        .collect();
    ips
}

fn craft_transport(
    interface: &NetworkInterface,
) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let mut config = datalink::Config::default();
    config.read_timeout = Some(Duration::from_secs(1));
    match datalink::channel(interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Bad channel type"),
        Err(e) => panic!("Error: {}", e),
    }
}

fn main() {
    let range = env::args().nth(1).unwrap();
    let scan_port = env::args().nth(2).unwrap().parse::<u16>().unwrap();
    let tx_buffer = 65536;
    let mut ranges: Vec<String> = Vec::new();
    ranges.push(range);
    let ips = calculate_ips(ranges);
    let mut ports: Vec<u16> = Vec::new();
    //ports.push(scan_port);
    (1..1001).for_each(|x| ports.push(x)); // Use this to add a range instead
    let ifs = interfaces();
    let if_default = default_net::get_default_interface().unwrap();
    let interface = ifs.into_iter().find(|x| x.name == if_default.name).unwrap();
    let gate = default_net::get_default_gateway().unwrap();
    //let (_, rx) = craft_transport(&interface);
    let mac: Option<MacAddr> = interface.mac;
    let ips_clone = ips.clone();
    //std::thread::spawn(move || {
    //    recv(rx, mac, ips_clone);
    //});
    let gate_mac: MacAddr = MacAddr::from(gate.mac_addr.octets());
    let (dev_umem, mut dev_descs) = Umem::new(
        UmemConfig::builder()
            .comp_queue_size(QueueSize::new(65536).unwrap())
            .fill_queue_size(QueueSize::new(65536).unwrap())
            //.frame_size(FrameSize::new(2048).unwrap())
            .build()
            .unwrap(),
        tx_buffer.try_into().unwrap(),
        false,
    )
    .expect("Could not create UMEM");
    let desc_len = dev_descs.len();
    println!("Desc len {}", desc_len);
    let (rx_descs, tx_descs) = dev_descs.split_at_mut(desc_len / 2);
    let (tx_q, rx_q, fq_cq) = unsafe {
        Socket::new(
            SocketConfig::builder()
                .tx_queue_size(QueueSize::new(65536 * 1024).unwrap())
                //.bind_flags(BindFlags::XDP_ZEROCOPY)
                .xdp_flags(XdpFlags::XDP_FLAGS_DRV_MODE)
                .build(),
            &dev_umem,
            &interface.name.parse().unwrap(),
            0,
        )
    }
    .expect("Failed tx creation");
    let (fq, cq) = fq_cq.expect("Failed to create fill queue and comp queue");
    std::thread::scope(|s| {
        let umem_ref = &dev_umem;
        s.spawn(move || {
            recv(rx_q, fq, rx_descs, umem_ref, &ips_clone);
        });
        let ip = interface.ips.first().unwrap().ip();
        println!("if: {}", interface.name);
        match ip {
            IpAddr::V4(v4_addr) => {
                println!("{}", v4_addr);
                let (packets, packets_size) = send_packets(
                    &v4_addr,
                    &ips,
                    34567,
                    ports,
                    gate_mac,
                    mac,
                    &dev_umem,
                    tx_q,
                    (tx_buffer / 2) as u16,
                    cq,
                    tx_descs,
                )
                .unwrap();
                std::thread::sleep(Duration::from_secs(2));
                println!("Packets sent: {}", packets);
                println!("Total packets: {}", packets_size);
            }
            IpAddr::V6(_) => {
                println!("Source is v6! Not implemented");
            }
        }
    });
}
