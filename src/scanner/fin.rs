use pnet::packet::tcp::{TcpFlags, MutableTcpPacket};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::IpAddr;
use std::time::Duration;
use rand::random;

pub async fn fin_scan(target: &str, ports: Vec<u16>, verbose: bool, quiet: bool) {
    println!("[*] FIN Scan: {}", target);

    let (mut tx, mut rx) = match transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("[!] Failed to create raw socket: {}", e);
            if verbose {
                eprintln!("[!] Note: FIN scan requires root privileges on most systems");
            }
            return;
        }
    };

    let target_ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("[!] Invalid target IP address");
            return;
        }
    };

    for port in ports {
        let mut tcp_buffer = [0u8; 20];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(random::<u16>());
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(random::<u32>());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_window(5840);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::FIN);
        tcp_packet.set_urgent_ptr(0);

        if let Err(e) = tx.send_to(tcp_packet.to_immutable(), target_ip) {
            if verbose && !quiet {
                eprintln!("[-] Error sending to port {}: {}", port, e);
            }
            continue;
        }

        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok((packet, _)) => {
                if let Some(tcp_response) = pnet::packet::tcp::TcpPacket::new(packet) {
                    if tcp_response.get_flags() == TcpFlags::RST {
                        if verbose && !quiet {
                            println!("[-] Port {:>5} CLOSED", port);
                        }
                    } else {
                        println!("[+] Port {:>5} OPEN|FILTERED", port);
                    }
                }
            }
            Err(_) => {
                println!("[+] Port {:>5} OPEN|FILTERED (no response)", port);
            }
        }
    }
}