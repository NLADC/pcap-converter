use std::{fmt::Debug, sync::Arc};
use std::path::Path;
use crate::{packetstats::*, PacketBatch};
use anyhow::Error;
use arrow::datatypes::*;
use arrow::array::*;
use arrow::datatypes::DataType::*;
use crossbeam::channel::Sender;

#[derive(Debug)]
pub struct StatsCollector {
    pcap_file: String,
    schema: Schema,
    packets: Vec<PacketStats>,
    errors: i64,
    tx: Sender<PacketBatch>,
 }

impl StatsCollector {
    pub fn new(pcap_file: &str, tx: Sender<PacketBatch>) -> Result<StatsCollector, Error> {
        let path = Path::new(pcap_file);
        let filename = path.file_name().unwrap();

        let fields = StatsCollector::create_fields();
        let schema = Schema::new(fields.clone());
        let sc = StatsCollector { 
            pcap_file: filename.to_str().unwrap().to_string(),
            schema: schema,
            packets: Vec::new(),
            errors: 0,
            tx: tx,
        };
    
        Ok(sc)
    }

    pub fn create_fields() -> Vec<Field> {
        let mut fields: Vec<Field> = Vec::new();
    
        fields.push(Field::new(
            "frame_time",
            Timestamp(TimeUnit::Microsecond, None),
            true,
        ));
        fields.push(Field::new("frame_len", UInt32, true));
        fields.push(Field::new("eth_type", UInt16, true));
        fields.push(Field::new("ip_src", Utf8, true));
        fields.push(Field::new("ip_dst", Utf8, true));
        fields.push(Field::new("ip_proto", UInt8, true));
        fields.push(Field::new("ip_ttl", UInt8, true));
        fields.push(Field::new("ip_frag_offset", UInt16, true));
        fields.push(Field::new("ip_id", UInt16, true));
        fields.push(Field::new("ip_mf", Boolean, true));
        fields.push(Field::new("icmp_type", UInt8, true));
        fields.push(Field::new("udp_length", UInt16, true));
        fields.push(Field::new("udp_srcport", UInt16, true));
        fields.push(Field::new("udp_dstport", UInt16, true));
        fields.push(Field::new("tcp_flags", Utf8, true));
        fields.push(Field::new("tcp_srcport", UInt16, true));
        fields.push(Field::new("tcp_dstport", UInt16, true));
        fields.push(Field::new("col_info", Utf8, true));
        fields.push(Field::new("col_source", Utf8, true));
        fields.push(Field::new("col_destination", Utf8, true));
        fields.push(Field::new("col_protocol", Utf8, true));
        fields.push(Field::new("dns_qry_name", Utf8, true));
        fields.push(Field::new("dns_qry_type", UInt16, true));
        fields.push(Field::new("http_request_uri", Utf8, true));
        fields.push(Field::new("http_host", Utf8, true));
        fields.push(Field::new("http_request_method", Utf8, true));
        fields.push(Field::new("http_user_agent", Utf8, true));
        fields.push(Field::new("http_file_data", Utf8, true));
        fields.push(Field::new("ntp_priv_reqcode", UInt8, true));
        fields.push(Field::new("dhip_device", Utf8, true));
        fields.push(Field::new("pcap_file", Utf8, true));
    
        fields
    }
    
    // pub fn push(&mut self, mut packet: PacketStats) {
    pub fn push(&mut self, packet: PacketStats) {

        self.errors += packet.errors;

        self.packets.push(packet);

        if self.packets.len() >= 10_000 {
            self.send_batch();
        }

    }

    fn record_batch(&mut self) -> RecordBatch {
        let frame_time = TimestampMicrosecondArray::from(self.packets.iter().map(|p| p.frame_time).collect::<Vec<Option<i64>>>());
        let frame_len = UInt32Array::from(self.packets.iter().map(|p| p.frame_len).collect::<Vec<Option<u32>>>());
        let eth_type = UInt16Array::from(self.packets.iter().map(|p| p.eth_type).collect::<Vec<Option<u16>>>());
        let ip_src = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.ip_src.clone()).collect::<Vec<Option<String>>>());
        let ip_dst = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.ip_dst.clone()).collect::<Vec<Option<String>>>());
        let ip_proto = UInt8Array::from(self.packets.iter().map(|p| p.ip_proto).collect::<Vec<u8>>());
        let ip_ttl = UInt8Array::from(self.packets.iter().map(|p| p.ip_ttl).collect::<Vec<Option<u8>>>());
        let ip_frag_offset = UInt16Array::from(self.packets.iter().map(|p| p.ip_frag_offset).collect::<Vec<u16>>());
        let ip_id = UInt16Array::from(self.packets.iter().map(|p| p.ip_id).collect::<Vec<u16>>());
        let ip_mf = BooleanArray::from(self.packets.iter().map(|p| p.more_fragments).collect::<Vec<bool>>());
        let icmp_type = UInt8Array::from(self.packets.iter().map(|p| p.icmp_type).collect::<Vec<Option<u8>>>());
        let udp_length = UInt16Array::from(self.packets.iter().map(|p| p.udp_length).collect::<Vec<Option<u16>>>());
        let udp_srcport = UInt16Array::from(self.packets.iter().map(|p| p.udp_srcport).collect::<Vec<Option<u16>>>());
        let udp_dstport = UInt16Array::from(self.packets.iter().map(|p| p.udp_dstport).collect::<Vec<Option<u16>>>());
        let tcp_flags = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.tcp_flags.clone()).collect::<Vec<Option<String>>>());
        let tcp_srcport = UInt16Array::from(self.packets.iter().map(|p| p.tcp_srcport).collect::<Vec<Option<u16>>>());
        let tcp_dstport = UInt16Array::from(self.packets.iter().map(|p| p.tcp_dstport).collect::<Vec<Option<u16>>>());
        let col_info = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_info.clone()).collect::<Vec<Option<String>>>());
        let col_source = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_source.clone()).collect::<Vec<Option<String>>>());
        let col_destination = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_destination.clone()).collect::<Vec<Option<String>>>());
        let col_protocol = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_protocol.clone()).collect::<Vec<Option<String>>>());
        let dns_qry_name = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.dns_qry_name.clone()).collect::<Vec<Option<String>>>());
        let dns_qry_type = UInt16Array::from(self.packets.iter().map(|p| p.dns_qry_type).collect::<Vec<Option<u16>>>());
        let http_request_uri = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_request_uri.clone()).collect::<Vec<Option<String>>>());
        let http_host = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_host.clone()).collect::<Vec<Option<String>>>());
        let http_request_method = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_request_method.clone()).collect::<Vec<Option<String>>>());
        let http_user_agent = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_user_agent.clone()).collect::<Vec<Option<String>>>());
        let http_file_data = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_file_data.clone()).collect::<Vec<Option<String>>>());
        let ntp_priv_reqcode = UInt8Array::from(self.packets.iter().map(|p| p.ntp_priv_reqcode).collect::<Vec<Option<u8>>>());
        let dhip_device = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.dhip_device.clone()).collect::<Vec<Option<String>>>());
        let pcap_file = GenericStringArray::<i32>::from(vec![self.pcap_file.clone(); self.packets.len()]);
        

        let batch = RecordBatch::try_new(
            Arc::new(self.schema.clone()),
            vec![
                Arc::new(frame_time),
                Arc::new(frame_len),
                Arc::new(eth_type),
                Arc::new(ip_src),
                Arc::new(ip_dst),
                Arc::new(ip_proto),
                Arc::new(ip_ttl),
                Arc::new(ip_frag_offset),
                Arc::new(ip_id),
                Arc::new(ip_mf),
                Arc::new(icmp_type),
                Arc::new(udp_length),
                Arc::new(udp_srcport),
                Arc::new(udp_dstport),
                Arc::new(tcp_flags),
                Arc::new(tcp_srcport),
                Arc::new(tcp_dstport),
                Arc::new(col_info),
                Arc::new(col_source),
                Arc::new(col_destination),
                Arc::new(col_protocol),
                Arc::new(dns_qry_name),
                Arc::new(dns_qry_type),
                Arc::new(http_request_uri),
                Arc::new(http_host),
                Arc::new(http_request_method),
                Arc::new(http_user_agent),
                Arc::new(http_file_data),
                Arc::new(ntp_priv_reqcode),
                Arc::new(dhip_device),
                Arc::new(pcap_file),
                ]
        ).unwrap();

        return batch;

    }


    pub fn send_batch(&mut self) {
        let batch = self.record_batch();
        let pkt_batch = PacketBatch{
            batch: batch,
            packet_count: self.packets.len(),
            errors: self.errors,
        };
        self.tx.send(pkt_batch).unwrap();
        self.packets = Vec::new();
        self.errors = 0;

    }
 
 
}


