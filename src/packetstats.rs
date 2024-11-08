use std::fmt::Debug;
use anyhow::Error;
use pcap_parser::data::PacketData;
use etherparse::*;
use etherparse::icmpv4::TYPE_DEST_UNREACH;
use std::net::*;
use domain::base::*;
use log::debug;
use serde_json::Value;

#[derive(Default, Debug, Clone)]
pub struct PacketStats {
    pub frame_time: Option<i64>,
    pub frame_len: Option<u32>,
    pub eth_type: Option<u16>,
    pub ip_src_raw: u32,
    pub ip_id: u16,
    pub more_fragments: bool,
    pub ip_src: Option<String>,
    pub ip_dst: Option<String>,
    pub ip_proto: u8,
    pub ip_ttl: Option<u8>,
    pub ip_frag_offset: u16,
    pub icmp_type: Option<u8>,
    pub udp_length: Option<u16>,
    pub udp_srcport: Option<u16>,
    pub udp_dstport: Option<u16>,
    pub tcp_flags: Option<String>,
    pub tcp_srcport: Option<u16>,
    pub tcp_dstport: Option<u16>,
    pub col_info: Option<String>,
    pub col_source: Option<String>,
    pub col_destination: Option<String>,
    pub col_protocol: Option<String>,
    pub dns_qry_name: Option<String>,
    pub dns_qry_type: Option<u16>,
    pub http_request_uri: Option<String>,
    pub http_host: Option<String>,
    pub http_request_method: Option<String>,
    pub http_user_agent: Option<String>,
    pub http_file_data: Option<String>,
    pub ntp_priv_reqcode: Option<u8>,
    pub dhip_device: Option<String>,
    pub ip_total_len: u16,
    // pub cache_miss: i64,
    pub errors: i64,
}

fn read_transport(ip_payload: IpPayloadSlice) -> Result<(Option<TransportHeader>, PayloadSlice), err::tcp::HeaderSliceError> {
    // helper function to set the len source in len errors
    use etherparse::ip_number::*;
    use err::tcp::HeaderSliceError::*;
    use etherparse::err::LenError;

    let add_len_source = |mut len_error: LenError| -> err::tcp::HeaderSliceError {
        // only change the len source if the lower layer has not set it
        if LenSource::Slice == len_error.len_source {
            len_error.len_source = ip_payload.len_source;
        }
        Len(len_error)
    };

    match ip_payload.ip_number {
        ICMP => Icmpv4Slice::from_slice(ip_payload.payload)
            .map_err(add_len_source)
            .map(|value| {
                (
                    Some(TransportHeader::Icmpv4(value.header())),
                    PayloadSlice::Icmpv4(value.payload()),
                )
            }),
        IPV6_ICMP => Icmpv6Slice::from_slice(ip_payload.payload)
            .map_err(add_len_source)
            .map(|value| {
                (
                    Some(TransportHeader::Icmpv6(value.header())),
                    PayloadSlice::Icmpv6(value.payload()),
                )
            }),
        UDP => UdpHeader::from_slice(ip_payload.payload)
            .map_err(add_len_source)
            .map(|value| {
                (
                    Some(TransportHeader::Udp(value.0)),
                    PayloadSlice::Udp(value.1),
                )
            }),
        TCP => TcpHeader::from_slice(ip_payload.payload)
            .map_err(|err| match err {
                Len(err) => add_len_source(err),
                Content(err) => Content(err),
            })
            .map(|value| {
                (
                    Some(TransportHeader::Tcp(value.0)),
                    PayloadSlice::Tcp(value.1),
                )
            }),
        _ => Err(Len(LenError {
            required_len: TcpHeader::MIN_LEN,
            len: 0,
            len_source: LenSource::Slice,
            layer: err::Layer::TcpHeader,
            layer_start_offset: 0,
        })),
    }
}

impl PacketStats {
    pub fn new() -> PacketStats {
        PacketStats { ..Default::default()}
    }

    fn tcp_flags_as_string(&mut self, tcp: TcpHeader) -> String {
        let mut flags = String::from("........");
        if tcp.fin {
            flags.replace_range(7..8, "F")
        };
        if tcp.syn {
            flags.replace_range(6..7, "S")
        };
        if tcp.rst {
            flags.replace_range(5..6, "R")
        };
        if tcp.psh {
            flags.replace_range(4..5, "P")
        };
        if tcp.ack {
            flags.replace_range(3..4, "A")
        };
        if tcp.urg {
            flags.replace_range(1..3, "U")
        };
        if tcp.ece {
            flags.replace_range(1..2, "E")
        };
        if tcp.cwr {
            flags.replace_range(0..1, "C")
        };

        return flags;
    }


    pub fn analyze_packet(&mut self, pkt_data: PacketData) -> Result<(),Error> {
        match pkt_data {
            PacketData::L2(eth_data) => {
                let result = PacketHeaders::from_ethernet_slice(eth_data);
                match result {
                    Ok(pkt_headers) => {
                            self.analyze_packet_headers(pkt_headers);
                    }

                    Err(slice_error) => {
                        // eprintln!("{:?}", slice_error);
                        debug!("slice error: {}", slice_error);
                        self.errors += 1;
                    }
                }
            }

            PacketData::L3(_, ip_data) => {
                let result = PacketHeaders::from_ip_slice(ip_data);
                match result {
                    Ok(pkt_headers) => {
                        self.analyze_packet_headers(pkt_headers);
                    }

                    Err(slice_error) => {
                        // eprintln!("{:?}", slice_error);
                        debug!("slice error: {}", slice_error);
                        self.errors += 1;
                    }
                }
            }
            _ => (),
        };

        Ok(())
    }


    // fn analyze_packet_headers(&mut self, pkt_headers: PacketHeaders, cache: &mut HashMap<u16, FragmentCache>) {
    fn analyze_packet_headers(&mut self, pkt_headers: PacketHeaders) {

        let EtherType(et) = pkt_headers.link.clone().unwrap().ethernet2().unwrap().ether_type;

        self.eth_type = Some(et);

        let mut transport_header: Option<TransportHeader> = pkt_headers.transport.clone();
        let mut transport_payload: PayloadSlice = pkt_headers.payload.clone();

        match pkt_headers.net {
            Some(NetHeaders::Ipv4(ref ip, _)) => {
                // May be replaced by transport or application protocol later on
                self.col_protocol = Some("IPv4".to_string());
                // self.frame_len = Some(ip.total_len as u32);
                self.ip_id = ip.identification;
                self.ip_total_len = ip.total_len;

                self.ip_src = Some(Ipv4Addr::from(ip.source).to_string());
                self.ip_src_raw = u32::from_be_bytes(ip.source);
                self.ip_dst = Some(Ipv4Addr::from(ip.destination).to_string());
                self.col_source = Some(Ipv4Addr::from(ip.source).to_string());
                self.col_destination =
                    Some(Ipv4Addr::from(ip.destination).to_string());
                self.ip_ttl = Some(ip.time_to_live);
                self.ip_proto = u8::from(ip.protocol);

                let frag_offset = u16::from(ip.fragment_offset);
                self.more_fragments = ip.more_fragments;
                self.ip_frag_offset = frag_offset;

                if frag_offset > 0 {
                    return;

                } else {
                    // etherparse will not try to parse a first fragment
                    // Hence this approach.
                    // Only do this with fragmented packets!

                    if ip.more_fragments {
                        match pkt_headers.payload {
                            PayloadSlice::Ip(ip_payload) => {
                                let result = read_transport(ip_payload);
                                match result {
                                    Ok((transport, payload)) => {
                                        transport_header = transport;
                                        transport_payload = payload;
                                    }
                                    _ => (),
                                }
                            }
                            _ => ()
                        }
                    }
                }
            }

            Some(NetHeaders::Ipv6(ref ip, _)) => {
                // May be replaced by transport or application protocol later on
                self.col_protocol = Some("IPv6".to_string());
                // self.frame_len = Some((ip.payload_length+ip.header_len() as u16) as u32);
                self.ip_src = Some(Ipv6Addr::from(ip.source).to_string());
                self.ip_dst = Some(Ipv6Addr::from(ip.destination).to_string());
                self.col_source = Some(Ipv6Addr::from(ip.source).to_string());
                self.col_destination =
                    Some(Ipv6Addr::from(ip.destination).to_string());
                self.ip_ttl = Some(ip.hop_limit);
                self.ip_proto = u8::from(ip.next_header);
            }
            _ => (),
        }

        // match pkt_headers.transport {
        match transport_header {
            Some(TransportHeader::Udp(udp)) => {

                // May be replaced by transport protocol later on
                self.col_protocol = Some("UDP".to_string());

                self.udp_srcport = Some(udp.source_port);
                self.udp_dstport = Some(udp.destination_port);
                self.udp_length = Some(udp.length);

                if udp.source_port == 53 || udp.destination_port == 53 {
                    self.col_protocol = Some("DNS".to_string());
                    match Message::from_octets(&transport_payload.slice()) {
                        Ok(dns) => {
                            match dns.first_question() {
                                Some(question) => {
                                    let name = if question.qname().is_root() {
                                        "<Root>".to_string()
                                    } else {
                                        question.qname().to_string()
                                    };
                                    self.dns_qry_name = Some(name.clone());
                                    self.dns_qry_type = Some(question.qtype().to_int());
                                }
                                _ => ()
                            }
                        }

                        Err(e) => {
                            // eprintln!("{}", _e);
                            debug!("DNS message too short: {}", e);
                            self.errors += 1;
                        }
                    }
                } else if udp.source_port == 123 || udp.destination_port == 123 {
                    self.col_protocol = Some("NTP".to_string());
                    // eprintln!("==> {:?}", &pkt_headers.payload.slice());

                        match ntp_parser::parse_ntp(&transport_payload.slice()) {
                            Ok(_ntp) => {
                            // eprintln!("{:?}", ntp);
                            // todo!();
                        },
                        Err(_e) => {
                            // eprintln!("{:?}", _e);
                            // let i = pkt_headers.payload.slice();
                            let i = transport_payload.slice();
                            // Is it a V2 NTP packet?
                            if (i[0] >> 3) & 0b111 == 2 {
                                // Yes, simply take the request code from the 4th byte
                                self.ntp_priv_reqcode = Some(i[3]);
                            } else {
                                debug!("NTP decode error");
                                self.errors += 1;
                            }
                        },
                  
                    }
                } else if udp.source_port == 37810 {
                    self.col_protocol = Some("DHDiscover".to_string());
                    // eprintln!("==> {:?}", &transport_payload.slice());
                    let replace_str = b' ';
                    let mut result = vec![];
                    for &b in transport_payload.slice() {
                        if b < 32 || b > 127{
                            result.push(replace_str);
                        } else {
                            result.push(b);
                        }
                    }
                    // eprintln!("==> {:?}", &result);
                    let s = match std::str::from_utf8(&result) {
                        Ok(v) => v,
                        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                    };
                    if s.starts_with("    DHIP") {
                        let device_json = s.get(32..).unwrap();
                        let v: Value = serde_json::from_str(device_json).unwrap();
                        self.dhip_device = Some(v["params"]["deviceInfo"]["DeviceType"].to_string());
                    }
                }
            }

            Some(TransportHeader::Tcp(tcp)) => {
                // May be replaced by transport protocol later on
                self.col_protocol = Some("TCP".to_string());

                self.tcp_srcport = Some(tcp.source_port);
                self.tcp_dstport = Some(tcp.destination_port);
                let flags = self.tcp_flags_as_string(tcp);
                self.tcp_flags = Some(flags);
            }

            Some(TransportHeader::Icmpv4(icmp)) => {
                // May be replaced by transport or application protocol later on
                self.col_protocol = Some("ICMP".to_string());

                let bytes = icmp.to_bytes();
                self.icmp_type = Some(bytes[0]);
                if bytes[0] == TYPE_DEST_UNREACH {
                    // Payload contains header of the original packet
                    // eprintln!("{:?}", pkt_headers.payload);
                    match PacketHeaders::from_ip_slice(transport_payload.slice()) {
                        Ok(icmp_ph) => {
                            // eprintln!("{:#?}", icmp_ph);
                            match icmp_ph.transport {
                                Some(TransportHeader::Udp(udp)) => {
                                    // eprintln!("UDP: {:?}", udp);
                                    self.udp_srcport = Some(udp.source_port);
                                    self.udp_dstport = Some(udp.destination_port);
                                }
                                Some(TransportHeader::Tcp(tcp)) => {
                                    // eprintln!("TCP: {:#?}", tcp);
                                    self.tcp_srcport = Some(tcp.source_port);
                                    self.tcp_dstport = Some(tcp.destination_port);
                                    let flags = self.tcp_flags_as_string(tcp);
                                    self.tcp_flags = Some(flags);
                                }
                                _ => (),
                            }
                        }
                        Err(_) => {
                            debug!("ICMPv4 decode error ({}->{})", self.ip_src.clone().unwrap(), self.ip_dst.clone().unwrap());
                            self.errors += 1; 
                        },
                    }
                }
            }


            Some(TransportHeader::Icmpv6(_icmp)) => (),

            _ => ()
        }
    }

    pub fn set_ip_src(&mut self, ip_src: String) { self.ip_src = Some(ip_src)}
    pub fn set_frame_time(&mut self, frame_time: i64) { self.frame_time = Some(frame_time)}

}

