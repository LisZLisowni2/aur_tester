use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use pcap::{Device, Capture};
use etherparse::PacketHeaders;

struct DnsCache {
    map: HashMap<Ipv4Addr, String>,
}

pub fn run_sniffer(container_ip: &str, device_name: &str, allowed_domains: HashSet<String>, kill_tx: tokio::sync::mpsc::Sender<String>, quiet: &bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut cache = DnsCache { map: HashMap::new() };

    if let Ok(aur_ip) = "209.126.35.78".parse::<Ipv4Addr>() {
        cache.map.insert(aur_ip, "aur.archlinux.org".to_string());
    }

    if let Ok(arch_ip) = "95.217.163.50".parse::<Ipv4Addr>() {
        cache.map.insert(arch_ip, "archlinux.org".to_string());
    }
    
    if !quiet { println!("[-] Sniffer: Connecting to '{}'...", device_name); }

    let mut cap = Capture::from_device(device_name)?
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .open()?;

    let bpf_filter = format!("host {}", container_ip);
    cap.filter(&bpf_filter, true)?;
    if !quiet { println!("[+] Sniffer: Activated BPF filter: '{}'", bpf_filter); }
    
    let mut has_killed = false;

    while let Ok(packet) = cap.next_packet() {
        if has_killed {
            break;
        }
        
        if let Ok(value) = PacketHeaders::from_ethernet_slice(packet.data) {
            if let Some(ip_header) = value.net {
                if let etherparse::NetHeaders::Ipv4(ipv4, _) = ip_header {
                    let src_ip = Ipv4Addr::from(ipv4.source);
                    let dest_ip = Ipv4Addr::from(ipv4.destination);

                    match value.transport {
                        Some(etherparse::TransportHeader::Udp(udp)) => {
                            let src_port = udp.source_port;
                            let dest_port = udp.destination_port;

                            if src_port == 53 && value.payload.slice().len() > 0 {
                                if let Ok(dns) = dns_parser::Packet::parse(value.payload.slice()) {
                                    for answer in dns.answers {
                                        if let dns_parser::RData::A(dns_parser::rdata::a::Record(ip)) = answer.data {
                                            let resolved_ip = ip;
                                            let domain_name = answer.name.to_string();

                                            cache.map.insert(resolved_ip, domain_name.clone());
                                            if !quiet { println!("[+] DNS-Resolver: Resolved DNS name and added to cache: '{}'", domain_name) };
                                        }
                                    }
                                }
                            }
                        }

                        Some(etherparse::TransportHeader::Tcp(tcp)) => {
                            let dest_port = tcp.destination_port;
                            if src_ip.to_string() == container_ip {
                                let domain = cache.map.get(&dest_ip)
                                    .map(|d| d.to_string())
                                    .unwrap_or("UNKNOWN DOMAIN".to_string());

                                if !quiet { println!(
                                    "[NETWORK ALERT] Container connects with: {} ({}:{})",
                                    domain, dest_ip, dest_port
                                ); }

                                let is_allowed = allowed_domains.iter().any(|allowed| {
                                    domain == *allowed || domain.ends_with(&format!(".{}", allowed))
                                });

                                if dest_port != 53 && !is_allowed {
                                    println!("[!!!] HACK ATTEMPT. Connection with unauthorized domain/IP: {}", domain);
                                    has_killed = true;
                                    let _ = kill_tx.blocking_send(domain.clone());
                                    break
                                }
                            }
                        }

                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}