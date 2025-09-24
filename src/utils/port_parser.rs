pub fn parse_ports(input: &str, tcp_scan: bool, udp_scan: bool) -> (Vec<u16>, Vec<u16>) {
    let mut tcp_ports = vec![];
    let mut udp_ports = vec![];

    for section in input.split(',') {
        if section.starts_with("T:") && tcp_scan {
            tcp_ports.extend(parse_range(&section[2..]));
        } else if section.starts_with("U:") && udp_scan {
            udp_ports.extend(parse_range(&section[2..]));
        } else if tcp_scan {
            // Default to TCP if TCP scanning is enabled
            tcp_ports.extend(parse_range(section));
        } else if udp_scan {
            // If only UDP scanning is enabled, treat unprefixed ports as UDP
            udp_ports.extend(parse_range(section));
        }
    }

    tcp_ports.sort();
    tcp_ports.dedup();

    udp_ports.sort();
    udp_ports.dedup();

    (tcp_ports, udp_ports)
}

fn parse_range(part: &str) -> Vec<u16> {
    let mut result = vec![];

    if part.contains('-') {
        let bounds: Vec<&str> = part.split('-').collect();
        if bounds.len() == 2 {
            if let (Ok(start), Ok(end)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                result.extend(start..=end);
            }
        }
    } else if let Ok(port) = part.parse::<u16>() {
        result.push(port);
    }

    result
}