mod parser;
mod scanner;
mod utils;

use clap::Parser;
use parser::args::Args;
use utils::port_parser::parse_ports;
use scanner::ping::is_host_up;
use scanner::tcp::scan_tcp;
use scanner::udp::scan_udp;
// use scanner::syn::syn_scan;
// use scanner::ack::ack_scan;
// use scanner::fin::fin_scan;
// use scanner::xmas::xmas_scan;
// use scanner::null::null_scan;

use chrono::Local;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let args = Args::parse();
    let targets: Vec<String> = args.normalized_targets();
    let (tcp_ports, udp_ports) = parse_ports(&args.ports, args.tcp_scan, args.udp_scan);
    
    println!("[DEBUG] TCP Ports: {:?}\n[DEBUG] UDP Ports: {:?}", tcp_ports, udp_ports);

    if args.verbose && args.quiet {
        eprintln!("Cannot use --verbose and --quiet together.");
        std::process::exit(1);
    }

    // Record start time
    let start_time = Instant::now();
    let timestamp = Local::now().format("%Y-%m-%d %H:%M %Z");
    println!(
        "Starting Rusty Nmap v{} at {}",
        version, timestamp
    );

    for target in &targets {
        println!("\nRusty Nmap scan report for {}", target);

        // Start latency timer
        let latency_start = Instant::now();

        let is_up = if args.ping_scan {
            is_host_up(target.as_str())
        } else if !args.no_ping {
            is_host_up(target.as_str())
        } else {
            true
        };

        let latency = latency_start.elapsed().as_secs_f64();

        if args.ping_scan {
            if is_up {
                println!("Host is up ({:.7}s latency).", latency);
            } else {
                println!("Host is down or unreachable.");
            }
            continue;
        }

        if !args.no_ping && !is_up {
            println!("Host appears down (use --no-ping to force scan).");
            continue;
        }

        println!("Host is up ({:.7}s latency).", latency);
        
        // TCP Scans

        if args.tcp_scan {
            scan_tcp(target, tcp_ports.clone(), args.verbose, args.quiet).await;
        }

        // Temp disable advanced TCP scans
        // if args.syn_scan {
        //     syn_scan(target, tcp_ports.clone(), args.verbose, args.quiet).await;
        // } else if args.ack_scan {
        //     ack_scan(target, tcp_ports.clone(), args.verbose, args.quiet).await;
        // } else if args.fin_scan {
        //     fin_scan(target, tcp_ports.clone(), args.verbose, args.quiet).await;
        // } else if args.xmas_scan {
        //     xmas_scan(target, tcp_ports.clone(), args.verbose, args.quiet).await;
        // } else if args.null_scan {
        //     null_scan(target, tcp_ports.clone(), args.verbose, args.quiet).await;
        // } else if args.tcp_scan {
        //     scan_tcp(target, tcp_ports.clone(), args.verbose, args.quiet).await;
        // }

        // UDP Scan
        if args.udp_scan {
            scan_udp(target, udp_ports.clone(), args.verbose, args.quiet).await;
        }
    }

    // Record total scan time
    let total_time = start_time.elapsed().as_secs_f64();
    println!(
        "\nRusty Nmap done: {} IP address{} scanned in {:.2} seconds",
        targets.len(),
        if targets.len() > 1 { "es" } else { "" },
        total_time
    );
}