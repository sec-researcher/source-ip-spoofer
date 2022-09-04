extern crate pnet;
use hex::FromHex;
use pnet::datalink::{Channel, MacAddr};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet };
use pnet::packet::udp::{MutableUdpPacket, UdpPacket };
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use std::env;
use std::str::FromStr;

fn main() {    
    let iface_name = env::args()
        .nth(1)
        .expect("Please specifiy interface name as first argument");
    let source = env::args()
        .nth(2)
        .expect("Please specifiy source IP as second argument");
    let destination = env::args()
        .nth(3)
        .expect("Please specifiy destination IP as third argument");
    let source_port = env::args()
        .nth(4)
        .expect("Please specifiy source port as fourth argument");
    let dest_port = env::args()
        .nth(5)
        .expect("Please specifiy destination port as fifth argument");
    let destination_mac = env::args()
        .nth(6)
        .expect("Please specifiy destination mac as sixth argument");
    let payload = env::args()
        .nth(7)
        .expect("Please specifiy payload as seventh argument");
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .unwrap();

    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened on creating ethernet channel {}", e),
    };
    let mut ethernet_buffer = [0u8; 1047];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .expect("Error on creating ethernet packet");
    let destination_mac = MacAddr::from_str(&destination_mac)
        .expect("Destination MAC address is not in correct format");
    ethernet_packet.set_destination(destination_mac);
    ethernet_packet.set_source(interface.mac.expect("Can not obtain source MAC address"));
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4buffer = [0u8; 1033];
    let mut ipv4packet = create_packet(
        &mut ipv4buffer,
        &source,
        &destination,
        &source_port,
        &dest_port,
        &payload,
    )
    .expect("Can not create ipv4 packet");

    ethernet_packet.set_payload(ipv4packet.packet_mut());
    sender
        .send_to(ethernet_packet.packet(), None)
        .expect("Error in sending ipv4 packet")
        .expect("Error in sending ipv4 packet");
    println!("payload sent successfully");


    let buf = receiver.next().expect("Error happened on recieving response");
    let ipv4 = Ipv4Packet::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).expect("Can not get IPv4 packet");
    let udp = UdpPacket::new(&ipv4.payload()).expect("Can not get udp packet");    
    if let Ok(response) = String::from_utf8(udp.payload().to_vec()) {
        println!("Response: {}", response)
    }
    else {
        println!("Can not conver response to string")
    }
}

fn create_packet<'a>(
    ipv4buffer: &'a mut [u8],
    source: &str,
    destination: &str,
    source_port: &str,
    dest_port: &str,
    payload: &str,
) -> Option<MutableIpv4Packet<'a>> {    
    let mut udpbuffer = vec![0; 8 + payload.len() / 2];
    if let Some(mut udppacket) = MutableUdpPacket::new(&mut udpbuffer) {
        //setup UDP packet
        let data = Vec::from_hex(payload).expect("Entered payload is not a valid hex");
        udppacket.set_source(source_port.parse().expect("Source port is not valid"));
        udppacket.set_destination(dest_port.parse().expect("Destination port is not valid"));
        udppacket.set_length((8 + data.len()) as u16);
        udppacket.set_payload(&data);
        use pnet::packet::udp::ipv4_checksum;
        let dest = std::net::Ipv4Addr::from_str(&destination).expect("Destination IP is not valid");
        udppacket.set_checksum(ipv4_checksum(
            &udppacket.to_immutable(),
            &std::net::Ipv4Addr::from_str(&source).expect("Destination IP is not valid"),
            &dest,
        ));
        let mut ipv4packet =
            MutableIpv4Packet::new(ipv4buffer).expect("Can not create ipv4 packet");
        //set source and dest
        ipv4packet.set_source(
            std::net::Ipv4Addr::from_str(&source).expect("Can not set source ip in ipv4 packet"),
        );
        ipv4packet.set_destination(dest);
        let totallen = (20 + 8 + data.len()) as u16;
        ipv4packet.set_total_length(totallen);
        ipv4packet.set_version(4);
        ipv4packet.set_header_length(5);
        ipv4packet.set_dscp(0);
        ipv4packet.set_ecn(0);
        ipv4packet.set_identification(0x1234);
        ipv4packet.set_flags(0);
        ipv4packet.set_fragment_offset(0);
        ipv4packet.set_ttl(64);
        ipv4packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        use pnet::packet::ipv4::checksum;
        ipv4packet.set_checksum(checksum(&ipv4packet.to_immutable()));

        //set udp packet to payload of ipv4 packet
        let udplen = udppacket.get_length() as usize;
        let udppacketmut = udppacket.packet_mut();
        ipv4packet.set_payload(&udppacketmut[0..udplen]);
        return Some(ipv4packet);
    }
    None
}
