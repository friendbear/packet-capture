extern crate pnet;
#[macro_use]
extern crate log;

use std::env;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;

mod packets;
use packets::GettableEndPoints;

const WIDTH: usize = 20;

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        error!("Please specify target interface name");
        std::process::exit(1);
    }

    let interface_name = &args[1];

    let interfaces = datalink::interfaces();
    let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == *interface_name)
            .expect("Failed to get interface");

    /* [1]: データリンクのチャンネルを取得 */
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel {}", e),
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                // 受信データからイーサネットフレームの構築
                let frame = EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        ipv4_handler(&frame);
                    }
                    EtherTypes::Ipv6 => {
                        ipv6_handler(&frame);
                    }
                    _ => {
                        info!("Not an IPv4 or IPv6 packet");
                    }
                }
            }
            Err(e) => {
                error!("Failed to read: {}", e);
            }
        }
    }
}
/**
 * IPv4パケットを構築し次のレイアのハンドラを呼び出す
 */
fn ipv4_handler(ethernet: &EthernetPacket) {
    if let Some(packet) = Ipv4Packet::new(ethernet.payload()) {
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet);
            }
            IpNextHeaderProtocols::Udp => {
                udp_handler(&packet);
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

/**
 * IPv6パケットを構築し次のレイアのハンドラを呼び出す
 */
fn ipv6_handler(ethernet: &EthernetPacket) {
    if let Some(packet) = Ipv6Packet::new(ethernet.payload()) {
        match packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet);
            }
            IpNextHeaderProtocols::Udp => {
                udp_handler(&packet);
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

/**
 * TCPパケットを構築する
 */
fn tcp_handler(packet: &GettableEndPoints) {
    let tcp = TcpPacket::new(packet.get_payload());
    if let Some(tcp) = tcp {
        print_packet_info(packet, &tcp, "TCP");
    }
}

/**
 * UDPパケットを構築する
 */
fn udp_handler(packet: &GettableEndPoints) {
    let udp = UdpPacket::new(packet.get_payload());
    if let Some(udp) = udp {
        print_packet_info(packet, &udp, "UDP")
    }
}

/**
 * アプリケーション層のデータをバイナリで表示する。
 */
fn print_packet_info(l3: &GettableEndPoints, l4: &GettableEndPoints, proto: &str) {

    println!(
        "Captured a {} packet from {}|{} to {}|{}\n",
        proto,
        l3.get_source(),
        l4.get_source(),
        l3.get_destination(),
        l4.get_destination()
    );
}