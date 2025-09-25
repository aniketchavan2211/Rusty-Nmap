use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use rand::random;
use std::net::IpAddr;
use std::time::Duration;
use crate::utils::packet_receiver::PacketReceiver;

pub async fn syn_scan(target: &str, ports: Vec<u16>, verbose: bool, quiet: bool) {
    println!("[*] SYN Scan: {}", target);

    let (mut tx, mut rx) = match transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("[!] Failed to create raw socket: {}", e);
            return;
        }
    };

    let target_ip: IpAddr = target.parse().expect("Invalid IP address");
    let mut receiver = PacketReceiver::new(&mut rx, Duration::from_secs(1));

    for port in ports {
        let mut tcp_buffer = [0u8; 20];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(random::<u16>());
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(random::<u32>());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_window(5840);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_urgent_ptr(0);

        if let Err(e) = tx.send_to(tcp_packet.to_immutable(), target_ip) {
            if verbose && !quiet {
                eprintln!("[-] Error sending to port {}: {}", port, e);
            }
            continue;
        }

        if let Some(packet_bytes) = receiver.recv() {
            if let Some(tcp_resp) = TcpPacket::new(&packet_bytes) {
                if tcp_resp.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
                    println!("[+] Port {:>5} OPEN", port);
                } else if tcp_resp.get_flags() == (TcpFlags::RST | TcpFlags::ACK) {
                    if verbose && !quiet {
                        println!("[-] Port {:>5} CLOSED", port);
                    }
                }
            }
        } else if verbose && !quiet {
            println!("[?] Port {:>5} FILTERED (no response)", port);
        }
    }
}
