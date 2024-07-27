use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use pnet::datalink;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::DataLinkSender;
use pnet::datalink::NetworkInterface;
use pnet::packet::arp::ArpHardwareTypes;
use pnet::packet::arp::ArpOperations;
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::Packet;
pub use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct MacCollector {
    iface: NetworkInterface,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
}

impl MacCollector {
    pub fn new(iface_name: &str, src_ip: Ipv4Addr) -> Result<Self> {
        let interfaces = datalink::interfaces();
        let iface = interfaces
            .into_iter()
            .find(|iface| iface.name == iface_name)
            .ok_or(anyhow!("iface not found"))?;
        let src_mac = iface.mac.ok_or(anyhow!("no MAC"))?;
        Ok(Self {
            iface,
            src_mac,
            src_ip,
        })
    }

    pub fn collect(&self, collector: &mut Vec<MacAddr>, dst_ip: Ipv4Addr) -> Result<()> {
        let cfg = pnet::datalink::Config {
            ..Default::default()
        };
        let (mut tx, mut rx) = match datalink::channel(&self.iface, cfg)? {
            pnet::datalink::Channel::Ethernet(tx, rx) => (tx, rx),
            _ => bail!("can't get Ethernet channel"),
        };

        let dur = Duration::from_secs(1);
        for _ in 0..3 {
            self.send_arp(&mut tx, dst_ip)?;
            self.collect_macs(&mut rx, collector, dur);
        }
        Ok(())
    }

    fn collect_macs(
        &self,
        rx: &mut Box<dyn DataLinkReceiver>,
        collector: &mut Vec<MacAddr>,
        dur: Duration,
    ) {
        let start_time = Instant::now();
        while let Ok(pkt) = rx.next() {
            if start_time.elapsed() > dur {
                break;
            }
            if let Some(eth_pkt) = EthernetPacket::new(pkt) {
                if eth_pkt.get_ethertype() != EtherTypes::Arp {
                    continue;
                }
                if let Some(arp_pkt) = ArpPacket::new(eth_pkt.payload()) {
                    if arp_pkt.get_operation() != ArpOperations::Reply {
                        continue;
                    }
                    if arp_pkt.get_target_proto_addr() == self.src_ip {
                        let mac = arp_pkt.get_sender_hw_addr();
                        if !collector.contains(&mac) {
                            collector.push(mac);
                        }
                    }
                }
            }
        }
    }

    fn send_arp(&self, tx: &mut Box<dyn DataLinkSender>, dst_ip: Ipv4Addr) -> Result<()> {
        // creating eth pkt
        let mut eth_buf = [0u8; 42];
        let mut eth_pkt =
            MutableEthernetPacket::new(&mut eth_buf).ok_or(anyhow!("can't construct eth pkt"))?;
        eth_pkt.set_source(self.src_mac);
        eth_pkt.set_destination(MacAddr::broadcast());
        eth_pkt.set_ethertype(EtherTypes::Arp);

        // creating arp pkt
        let mut arp_buf = [0u8; 28];
        let mut arp_pkt =
            MutableArpPacket::new(&mut arp_buf).ok_or(anyhow!("can't construct arp pkt"))?;
        arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_pkt.set_protocol_type(EtherTypes::Ipv4);
        arp_pkt.set_hw_addr_len(6);
        arp_pkt.set_proto_addr_len(4);
        arp_pkt.set_operation(ArpOperations::Request);
        arp_pkt.set_sender_hw_addr(self.src_mac);
        arp_pkt.set_sender_proto_addr(self.src_ip);
        arp_pkt.set_target_hw_addr(MacAddr::zero());
        arp_pkt.set_target_proto_addr(dst_ip);

        eth_pkt.set_payload(arp_pkt.packet());
        tx.send_to(&eth_buf, None);

        Ok(())
    }
}
