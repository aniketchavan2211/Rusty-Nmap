use std::net::UdpSocket;
use std::time::{Duration, Instant};
use tokio::task;
use futures::stream::{FuturesUnordered, StreamExt};

pub async fn scan_udp(target: &str, ports: Vec<u16>, verbose: bool, quiet: bool) {
    println!("[*] UDP Scan: {}", target);

    let mut tasks = FuturesUnordered::new();

    for port in ports {
        let target = target.to_string();

        tasks.push(task::spawn_blocking(move || {
            let addr = format!("{}:{}", target, port);
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();

                    let payload = match port {
                        53 => dns_query_packet(),
                        123 => ntp_request_packet(),
                        161 => snmp_request_packet(),
                        137 => netbios_ns_request(),
                        _ => b"RUSTY-NMAP".to_vec(), // Default probe
                    };

                    let _ = socket.send_to(&payload, &addr);
                    let mut buf = [0u8; 1024];
                    let start = Instant::now();

                    match socket.recv_from(&mut buf) {
                        Ok(_) => {
                            Some(format!("[+] Port {:>5} OPEN or FILTERED", port))
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            Some(format!("[+] Port {:>5} OPEN|FILTERED (no response)", port))
                        }
                        Err(_) => {
                            if verbose && !quiet {
                                Some(format!("[-] Port {:>5} maybe CLOSED or ICMP filtered", port))
                            } else {
                                None
                            }
                        }
                    }.map(|msg| {
                        if verbose {
                            let elapsed = start.elapsed();
                            format!("{msg}\n    [Latency] {}: {:.2?}", port, elapsed)
                        } else {
                            msg
                        }
                    })
                }
                Err(e) => Some(format!("[!] Failed to bind socket for port {}: {}", port, e)),
            }
        }));
    }

    while let Some(result) = tasks.next().await {
        if let Ok(Some(output)) = result {
            println!("{}", output);
        }
    }
}

fn dns_query_packet() -> Vec<u8> {
    vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Standard query
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT, ARCOUNT
        0x06, b'g', b'o', b'o', b'g', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // End of domain
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    ]
}

fn ntp_request_packet() -> Vec<u8> {
    let mut packet = vec![0; 48];
    packet[0] = 0x1B; // LI=0, Version=3, Mode=3 (client)
    packet
}

fn snmp_request_packet() -> Vec<u8> {
    vec![
        0x30, 0x26, // Sequence
        0x02, 0x01, 0x00, // Version: v1
        0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // Community
        0xA0, 0x19, // GetRequest
        0x02, 0x04, 0x70, 0x00, 0x00, 0x01, // Request ID
        0x02, 0x01, 0x00, // Error
        0x02, 0x01, 0x00, // Error index
        0x30, 0x0B, // Varbind list
        0x30, 0x09,
        0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01, // sysDescr
        0x05, 0x00
    ]
}

fn netbios_ns_request() -> Vec<u8> {
    vec![
        0x81, 0x00, 0x00, 0x01, // Transaction ID, Flags, Questions
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer, Authority, Additional
        0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x00,
        0x00, 0x21, // NBSTAT
        0x00, 0x01  // Class IN
    ]
}
