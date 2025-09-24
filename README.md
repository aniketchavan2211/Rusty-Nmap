# 🦀 Rusty Nmap

Rusty Nmap is a **fast, async port scanner written in Rust**, inspired by Nmap.  
It supports both **TCP** and **UDP** scanning, with concurrent execution and smart payloads for better service detection.

---

## ✨ Features
- ⚡ Multi-threaded TCP and UDP scanning
- 🔍 Smart UDP payloads (DNS, NTP, SNMP, etc.)
- 📡 Host discovery and latency measurement
- 🎛️ Command-line flags for flexible scanning (`--tcp-scan`, `--udp-scan`, `-p 1-65535`, etc.)
- 📊 Verbose/quiet modes for detailed or minimal output
- 🦀 Written in safe and performant Rust

---

## 🚀 Usage
Build the scanner:
```bash
cargo build --release
```
Run a TCP scan:
```bash
./target/release/rusty-nmap 192.168.1.1 --tcp-scan -p 1-1000
```
Run a UDP scan:
```bash
./target/release/rusty-nmap 192.168.1.1 --udp-scan -p 53,123,161
```
Scan both TCP and UDP:
```bash
./target/release/rusty-nmap 192.168.1.1 -p T:22,80,U:53,123
```

## 📦 Installation

Clone and build:
```bash
git clone https://github.com/your-username/rusty-nmap.git
cd rusty-nmap
cargo build --release
```

## ⚖️ License

This project is licensed under the MIT License – see the LICENSE


## 📚 Disclaimer

This tool is for educational and ethical security testing purposes only.
The author is not responsible for any misuse or damage caused.
