use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Perform a simple TCP-based ping on common ports
pub fn is_host_up(host: &str) -> bool {
    let common_ports = [80, 443, 53]; // Use safe & fast ports for TCP ping
    let timeout = Duration::from_millis(800);

    for port in common_ports {
        let addr = format!("{host}:{port}");
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            if let Some(sock) = addrs.next() {
                if TcpStream::connect_timeout(&sock, timeout).is_ok() {
                    return true;
                }
            }
        }
    }

    false
}