use anyhow::Result;
use clap::Parser;
use pcap_parser::*;
use std::{fmt::Debug, fs};
use std::fs::*;
use rand::distributions::{Alphanumeric, DistString};
use std::env;
use std::thread::{self, JoinHandle};
use duckdb::Connection;
use crossbeam::channel::{bounded, unbounded};
// use log::debug;
// use log::error;
use log::info;
// use log::warn;

use packetstats::*;
use statscollector::*;
use statswriter::*;

pub mod packetstats;
pub mod statscollector;
pub mod statswriter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File path of the PCAP file
    #[arg(short, long)]
    file: String,
    /// File path of the parquet file
    #[arg(short, long)]
    out: String,
    /// Show counter while processing
    #[arg(short, long)]
    verbose: bool,
    /// Do not combine fragments
    #[arg(short, long)]
    nodefrag: bool,
    /// Number of processing threads
    #[arg(short, default_value("4")) ]
    j: isize,
}

// ****************************************************************************************************** //
#[derive(Debug, Clone)]
pub struct PktMsg {
    pub frame_time: i64,
    pub frame_len: u32,
    pub data: Vec<u8>,
    pub caplen: u32,
    pub linktype: Linktype,
}

// ****************************************************************************************************** //

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Create a temporary file for storing first pass parquet file
    let temp_file = format!("{}/pcap-converter-{}.parquet", env::temp_dir().display(), Alphanumeric.sample_string(&mut rand::thread_rng(), 16));

    // Open input (pcap) file
    info!("Opening input file ({})", args.file.clone());
    let file = File::open(&args.file)?;

    // pcap is processed in 2+j threads:
    // 1. This main thread, reading the pcap file in packets (circular buffer)
    // 2. j threads for processing each packet: decoding and getting the information needed for analysis.
    //      e.g. is it IPv4/6, IP, UDP, DNS/NTP, TCP, etc.
    //    Each thread collects this packet information and when it has collected info on 10k packets
    //    transforms it into a 'recordbatch' ready for writing by the  
    // 3. Writer thread, which does simply that: writing record batches to the parquet file
    //
    // Communication between 1 & 2, and 2 & 3 is done with channels
    // When EOF is reached, channel between 1 & 2 is closed. Once no more packets are in the channel
    // the 2 thread(s) flush the remaining (<10k) info packets to the channel to 3
    // then channel between 2 & 3 is closed, which causes 3 to close the file
    
    info!("Opening temp output file");
    let mut statswriter: StatsWriter = StatsWriter::new(&temp_file,  args.verbose)?;
    
    info!("Setting up channels to be used between threads");
    // Channel between 1 & 2 (Single Producer, Multiple Consumers)
    let (pkt_tx, pkt_rx) = bounded::<PktMsg>(4_000_000);
    // Channel between 2 & 3 (Multiple Producers, Single Consumer)
    let (stw_tx, stw_rx) = unbounded::<PacketBatch>();

    // Create the StatsWriter thread (3)
    info!("Creating the output writer thread");
    let sw_thread = thread::spawn(move || {
        for batch in stw_rx.iter() {
            statswriter.write_batch(batch);
        }
        statswriter.close_parquet();
        statswriter.writer.close().unwrap();
    });

    // Create the PacketStats thread(s) (2)
    info!("Creating the {} threads for analyzing packets", args.j);
    let mut pkt_threads:Vec<JoinHandle<()>> = Vec::new();
    for _ in 0..args.j {
        let rx = pkt_rx.clone();
        let tx = stw_tx.clone();
        let pcap_file = args.file.clone();
        let pkt_thread = thread::spawn( move || {
            let mut collector = StatsCollector::new(&pcap_file, tx).unwrap();
            for pkt_msg in rx.iter() {
                let mut packet_stats:PacketStats = PacketStats::new();
                packet_stats.frame_time = Some(pkt_msg.frame_time);
                packet_stats.frame_len = Some(pkt_msg.frame_len);
                let slice = pkt_msg.data;
                let pkt_data = pcap_parser::data::get_packetdata(&slice, pkt_msg.linktype, pkt_msg.caplen as usize).expect("Error getting packet data");

                let result = packet_stats.analyze_packet(pkt_data);
                match result {
                    // Ok(_) => s.send(packet_stats).unwrap(),
                    Ok(_) => {
                        collector.push(packet_stats);
                    },
                    Err(_) => (),
                }
            }
            // Input channel closed, send remaining collected packets as a record batch to 3
            collector.send_batch();
        });
        pkt_threads.push(pkt_thread);
    }

    let mut consecutive_errors = 0;
    let mut linktype = Linktype::ETHERNET; // Legacy PCAP files
    let mut if_linktypes = Vec::new(); // PCAP-NG files
    let mut if_tsresol: u8 = 6;
    info!("Creating PcapReaderIterator for {}", args.file.clone());
    let mut reader = create_reader(65536 , file)?;

    info!("Processing packets");
    loop {
        match reader.next() {
            Ok((offset, block)) => {

                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let frame_time: i64 =
                            i64::from(b.ts_sec) * i64::pow(10, 6) + i64::from(b.ts_usec);
                        let frame_len: u32 = b.origlen;
                        let pkt_msg = PktMsg {
                            frame_time: frame_time,
                            frame_len: frame_len,
                            data: b.data.to_owned(),
                            caplen: b.caplen,
                            linktype: linktype,
                        };
                        pkt_tx.send(pkt_msg).unwrap();
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        if_linktypes = Vec::new();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                        if_tsresol = idb.if_tsresol;
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let ts_pkt: i64 =
                            i64::from(epb.ts_high) * i64::pow(2, 32) + i64::from(epb.ts_low);
                        let ts_res: i64 =
                            i64::from(ts_pkt) * i64::pow(10, 9 - u32::from(if_tsresol));
                        let frame_time = ts_res / 1000;
                        let frame_len = epb.caplen;
                        let pkt_msg = PktMsg {
                            frame_time: frame_time,
                            frame_len: frame_len,
                            data: epb.data.to_owned(),
                            caplen: epb.caplen,
                            linktype: linktype,
                        };
                        pkt_tx.send(pkt_msg).unwrap();
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = spb.block_len1 - 16;
                        let pkt_msg = PktMsg {
                            frame_time: 0,
                            frame_len: spb.origlen,
                            data: spb.data.to_owned(),
                            caplen: blen,
                            linktype: linktype,
                        };
                        pkt_tx.send(pkt_msg).unwrap();
                    }
                    PcapBlockOwned::NG(_block) => {
                    }
                }

                reader.consume(offset);
                consecutive_errors = 0;
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                // If the last packet is not complete, the reader might get stuck in a loop.
                // In that case, after too many consecutive errors we stop the execution.
                consecutive_errors += 1;
                if consecutive_errors > 1000 {
                    break;
                }
                reader.refill().unwrap();
            }
            Err(e) => panic!("Error reading file: {:?}", e),
        }
    }

    // All packets processed, drop first channel between 1 and 2
    info!("Reading pcap done, dropping channel between reader and analysers");
    drop(pkt_tx);

    // Wait till all packetstats (2) threads have finished
    info!("Waiting for analysers to finish");
    for pkt_thread in pkt_threads {
        match pkt_thread.join() {
            Ok(_) => (),
            Err(err) => {
                eprintln!("{:#?}", err);
            }
        }
    }

    // Drop second channel between 2 and 3
    info!("Dropping channel between analysers and writer thread");
    drop(stw_tx);
    // Wait for the write thread (3) to finish
    info!("Waiting for writer thread to finish");
    sw_thread.join().unwrap();

    if args.verbose {
        eprintln!();
    }

    if args.nodefrag {
        // If explicitly requested not to do defragmentation: Simply copy the temp file to args.out
        // Move/rename will not work if moving to another filesystem
        // Which is the default case in Debian
        info!("No defragmentation requested, copying temp output to final destination");
        fs::copy(&temp_file, &args.out)?;
    } else {
        // Do some smart duckdb wrangling for defragmentation
        // But first determine if it is needed in the first place (>1% fragmentation)
        info!("Determine if defragmentation is needed");
        let conn = Connection::open_in_memory()?;
        conn.execute(&format!("create view pcap as select * from '{}'", temp_file), [])?;

        let row = conn.query_row("select round(100*count()/(select count() from 'pcap')) from 'pcap' where (ip_frag_offset=0 and ip_mf=true) or ip_frag_offset>0", [], |row| {row.get::<usize, f64>(0)});
        let percentage = row.unwrap();

        if percentage < 1.0 { 
            // Fewer than 1% fragmented packets, don't bother to defragment
            info!("Fewer than 1% fragmented packets, don't bother to defragment");
            drop(conn);
            if args.verbose {
                eprintln!("{}% fragmented traffic (<1%), not doing defragmentation", percentage);
            }
            fs::copy(&temp_file, &args.out)?;
 
        } else {
            info!("{}% fragmented traffic. Doing defragmentation", percentage);
            if args.verbose {
                eprintln!("{}% fragmented traffic. Setting UDP/DNS/NTP info based on first fragment (if available)", percentage);
            }
            // Create a view that only contains the first packet of a fragmented UDP datagram
            conn.execute("create view ff as select ip_src, ip_dst, ip_id, ip_proto, first(udp_srcport) as udp_srcport, first(udp_dstport) as udp_dstport, first(ntp_priv_reqcode) as ntp_priv_reqcode, first(dns_qry_type) as dns_qry_type, first(dns_qry_name) as dns_qry_name, first(col_protocol) as col_protocol from pcap where ip_proto=17 and ip_mf=1 and ip_frag_offset=0 group by all", [])?;

            // create a second view that takes specific fields from the view created above if needed
            // In effect it sets information for specific fields of the fragmented packets based on the first packet of that fragmented datagram
            conn.execute("create view raw as select pcap.* exclude (udp_srcport, udp_dstport, ntp_priv_reqcode, dns_qry_type, dns_qry_name, col_protocol), coalesce(pcap.udp_srcport, ff.udp_srcport) as udp_srcport, coalesce(pcap.udp_dstport, ff.udp_dstport) as udp_dstport, coalesce(pcap.ntp_priv_reqcode,ff.ntp_priv_reqcode) as ntp_priv_reqcode, coalesce(pcap.dns_qry_type, ff.dns_qry_type) as dns_qry_type, coalesce(pcap.dns_qry_name, ff.dns_qry_name) as dns_qry_name, coalesce(pcap.col_protocol, ff.col_protocol) as col_protocol from pcap left join ff using (ip_src,ip_dst, ip_proto, ip_id)", [])?;

            // Write out that second (defragmented) view to the output file specified
            info!("Copying defragmented view to output file");
            conn.execute(&format!("COPY raw to '{}' (format parquet)", args.out), [])?;
        }
    }

    info!("Removing temp file");
    // Remove the temp file
    fs::remove_file(temp_file)?;

    Ok(())
}
