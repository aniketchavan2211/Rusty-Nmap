use pnet::transport::TransportReceiver;
use std::time::{Duration, Instant};

pub struct PacketReceiver<'a> {
    rx: &'a mut TransportReceiver,
    timeout: Duration,
}

impl<'a> PacketReceiver<'a> {
    pub fn new(rx: &'a mut TransportReceiver, timeout: Duration) -> Self {
        Self { rx, timeout }
    }

    pub fn recv(&mut self) -> Option<Vec<u8>> {
        let start = Instant::now();
        loop {
            match self.rx.next() {
                Ok(packet) => return Some(packet.to_vec()),
                Err(_) => {}
            }
            if start.elapsed() > self.timeout {
                return None;
            }
        }
    }
}
