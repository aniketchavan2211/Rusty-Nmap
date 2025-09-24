use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:8888")?;
    println!("UDP Server listening on 127.0.0.1:8888");

    let mut buf = [0u8; 1024];
    loop {
        let (size, src) = socket.recv_from(&mut buf)?;
        println!("Received {} bytes from {}: {:?}", size, src, &buf[..size]);
        
        // Send a response back
        socket.send_to(b"RUSTY-NMAP-RESPONSE", src)?;
        println!("Sent response");
    }
}
