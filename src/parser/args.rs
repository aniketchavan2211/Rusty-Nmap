use clap::Parser;
use ipnetwork::IpNetwork;

#[derive(Parser, Debug)]
#[command(
    name = "Rusty Nmap",
    version = env!("CARGO_PKG_VERSION"),
    author = "Aniket Chavan <aniketchavan2211@gmail.com>",
    about = "A fast async TCP/UDP port scanner written in Rust",
    long_about = None,
    after_help = "EXAMPLES:\n    rusty-nmap 127.0.0.1 -p T:22,80,U:53\n    rusty-nmap 192.168.1.1/24 -p 1-1000 --verbose --syn-scan",
    disable_help_subcommand = true,
)]
pub struct Args {
    #[arg(short = 'p', long = "ports", default_value = "22,80,443", help = "-p <ports> like 22,80 or 1-100, or protocol-prefixed T:22,U:53")]
    pub ports: String,

    #[arg(help = "Target IP or hostname", required = true)]
    pub targets: Vec<String>,

    #[arg(short = 'v', long = "verbose", default_value_t = false)]
    pub verbose: bool,

    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    pub quiet: bool,

    #[arg(long = "ping-scan", help = "Enable ping scan (host discovery)", aliases = ["sn"])]
    pub ping_scan: bool,

    #[arg(long = "no-ping", help = "Disable ping scan (skip host discovery)", aliases = ["Pn"])]
    pub no_ping: bool,

    // Scan types
    #[arg(long = "tcp-scan", default_value_t = true, help = "Enable TCP connect scan", aliases = ["sT"])]
    pub tcp_scan: bool,

    #[arg(long = "syn-scan", help = "Enable SYN scan (requires root)", aliases = ["sS"])]
    pub syn_scan: bool,

    #[arg(long = "ack-scan", help = "Enable ACK scan", aliases = ["sA"])]
    pub ack_scan: bool,

    #[arg(long = "fin-scan", help = "Enable FIN scan", aliases = ["sF"])]
    pub fin_scan: bool,

    #[arg(long = "xmas-scan", help = "Enable Xmas scan", aliases = ["sX"])]
    pub xmas_scan: bool,

    #[arg(long = "null-scan", help = "Enable Null scan", aliases = ["sN"])]
    pub null_scan: bool,

    #[arg(long = "udp-scan", help = "Enable UDP scan", aliases = ["sU"])]
    pub udp_scan: bool,

    #[arg(long = "rate", default_value_t = 1000, help = "Packets per second")]
    pub rate: u32,

    #[arg(long = "timeout", default_value_t = 1, help = "Timeout in seconds")]
    pub timeout: u64,
}

impl Args {
    pub fn normalized_targets(&self) -> Vec<String> {
        let mut result = vec![];

        for entry in &self.targets {
            let target = if entry == "localhost" {
                "127.0.0.1".to_string()
            } else {
                entry.to_string()
            };

            if let Ok(network) = target.parse::<IpNetwork>() {
                for ip in network.iter() {
                    result.push(ip.to_string());
                }
            } else {
                result.push(target);
            }
        }

        result
    }
}