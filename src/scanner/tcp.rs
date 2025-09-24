use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::net::ToSocketAddrs;
use std::io;
use std::time::Instant;

pub async fn scan_tcp(target: &str, ports: Vec<u16>, verbose: bool, quiet: bool) {
    println!("[*] TCP Scan: {}", target);

    let start = Instant::now();  // Start timer

    for port in ports {
        match scan_port(target, port, verbose, quiet).await {
            Ok(()) => {}
            Err(e) => {
                if verbose && !quiet {
                    eprintln!("[-] Error scanning port {}: {}", port, e);
                }
            }
        }
    }

    let duration = start.elapsed();  // Calculate elapsed time
    println!("[*] Scan of {} completed in {:.2?}", target, duration);
}

pub async fn scan_port(target: &str, port: u16, verbose: bool, quiet: bool) -> Result<(), io::Error> {
    let address = format!("{}:{}", target, port);
    let timeout_duration = Duration::from_secs(1);

    let mut addrs_iter = address.to_socket_addrs()?;

    if let Some(socket_addr) = addrs_iter.next() {
        match timeout(timeout_duration, TcpStream::connect(&socket_addr)).await {
            Ok(connect_result) => {
                match connect_result {
                    Ok(_) => {
                        println!("[+] Port {:>5} OPEN", port);
                        Ok(())
                    }
                    Err(err) => {
                        if verbose && !quiet {
                            match err.kind() {
                                io::ErrorKind::ConnectionRefused => {
                                    println!("[-] Port {:>5} CLOSED", port);
                                }
                                io::ErrorKind::TimedOut => {
                                    println!("[?] Port {:>5} FILTERED (timeout)", port);
                                }
                                io::ErrorKind::NetworkUnreachable => {
                                    println!("[!] Port {:>5} FILTERED (unreachable)", port);
                                }
                                _ => {
                                    println!("[?] Port {:>5} UNFILTERED / UNKNOWN: {:?}", port, err.kind());
                                }
                            }
                        }
                        Ok(())
                    }
                }
            }
            Err(_) => {
                if verbose && !quiet {
                    println!("[?] Port {:>5} FILTERED (timeout)", port);
                }
                Ok(())
            }
        }
    } else {
        if verbose && !quiet {
            eprintln!("[-] No address found for: {}", address);
        }
        Ok(())
    }
}
