extern crate rayon;

use std::{net, env, thread, time, fs, collections};
use pnet::packet::{tcp, ip};
use pnet::transport::{self, TransportProtocol};

const TCP_SIZE: usize = 20;
const MAXIMUM_PORT_NUM: u16 = 1023;

struct PacketInfo {
    my_ipaddr: net::Ipv4Addr,
    target_ipaddr: net::Ipv4Addr,
    my_port: u16,
    maximum_port: u16,
    scan_type: ScanType,
}

#[derive(Copy, Clone)]
enum ScanType {
    Syn = tcp::TcpFlags::SYN as isize,
    Fin = tcp::TcpFlags::FIN as isize,
    Xmas = (tcp::TcpFlags::FIN | tcp::TcpFlags::URG | tcp::TcpFlags::PSH) as isize,
    Null = 0,
}

fn main() {

    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Bat number of arguments. [ipaddr] [scantype]");
        std::process::exit(1);
    }

    let packet_info = {
        let contents = fs::read_to_string(".env").expect("Failed to read env file");
        let lines: Vec<_> = contents.split("\n").collect();
        let mut map = collections::HashMap::new();
        for line in lines {

            let elm: Vec<_> = line.split("=").map(str::trim).collect();
            if elm.len() == 2 {
                map.insert(elm[0], elm[1]);
            }
        }
        PacketInfo {
            my_ipaddr: map["MY_IPADDR"].parse().expect("invalid ipaddr"),
            target_ipaddr: args[1].parse().expect("invalid target ipaddr"),
            my_port: map["MY_PORT"].parse().expect("invalid port number"),
            maximum_port: map["MAXIMUM_PORT_NUM"].parse().expect("invalid maximum port num"),
            scan_type: match args[2].as_str() {
                "sS" => ScanType::Syn,
                "sF" => ScanType::Fin,
                "sX" => ScanType::Xmas,
                "sN" => ScanType::Null,
                _ => {
                    panic!("Undefined scan method, only accept [sS|sF|sN|sX].");
                }
            },
        }
    };
    print!("{} {} {}", packet_info.my_ipaddr, packet_info.my_port, packet_info.target_ipaddr);
}
