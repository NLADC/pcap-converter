# pcap-converter

pcap-converter is a Dissector helper tool written in Rust. pcap-converter directly converts a pcap file into parquet, which is the file format the dissector uses for its analysis. Only information relevant for analysis is extracted by pcap-converter, making it much faster than the dissector's fallback approach of using tshark for extracting the relevant information from a pcap file.
```
Usage: pcap-converter [OPTIONS] --file <FILE> --out <OUT>

Options:
  -f, --file <FILE>  File path of the PCAP file
  -o, --out <OUT>    File path of the parquet file
  -v, --verbose      Show packet counter while processing
  -n, --nodefrag     Do not combine fragments
  -j <J>             Number of processing threads [default: 4]
  -h, --help         Print help
  -V, --version      Print version

```
pcap-converter reads in the pcap/pcapng file (specified with -f), processes its content and writes the results in parquet format to the file specified with -o

If you use the dissector the recommended way (with Docker), then there is no need to follow the steps below, as pcap-converter is included in the docker image.

If you want to run the dissector locally, then it makes sense to build and install pcap-converter locally as well; since it is a much faster option than having the dissector use tshark and tcpdump. 

## Building and installing

### Requirements
As pcap-converter is written in Rust, a Rust development setup is needed. Luckily this is well-documented and not too difficult.
Simply follow the ['Getting started'](https://www.rust-lang.org/learn/get-started) instructions from the [Rust website](https://www.rust-lang.org/).

### Building
Clone this repository to your PC
```
git clone https://github.com/NLADC/pcap-converter.git
```

Change into the repository and start the build. This will take several minutes, how many depends on the specs of your computer.
```
cd pcap-converter
cargo build --release
```

The resulting binary can be found in the `./target/release` directory of your local repository clone.

### Installing

To install pcap-converter to a place where the dissector can find it, simply do:
```
cargo install --path .
```
This will most likely put the binary in `~/.cargo/bin`, which is fine if you are the only one running the dissector locally on this computer. If not, make sure to copy the binary to a directory that is in everyone's `$PATH`, e.g.
```
sudo cp target/release/pcap-converter /usr/local/bin
``` 

### Usage
The dissector automatically detects the presence of pcap-converter and uses it, unless explicitly told not to. If the dissector uses pcap-converter, the number of packets processed will be printed on screen as they are processed. 

````
python src/main.py -f ../../data/pcap/anon-Booter8.pcap 
[INFO] 
    ____  _                     __            
   / __ \(_)____________  _____/ /_____  _____
  / / / / / ___/ ___/ _ \/ ___/ __/ __ \/ ___/
 / /_/ / (__  |__  )  __/ /__/ /_/ /_/ / /    
/_____/_/____/____/\___/\___/\__/\____/_/     

Packets: 5,758,016 Errors: 29,809
90% fragmented traffic. Setting UDP/DNS/NTP info based on first fragment (if available)
[INFO] Conversion took 11.65s
[INFO] Extracting attack vectors.
[INFO] Analysis took 3.80s

````

Just for comparison, the same file processed by dissector using tshark instead of pcap-converter. The dissector needs roughly 80 seconds to process and analyse the same pcap, as opposed to just 15 seconds when using pcap-converter (as shown above). 
```
python src/main.py -f ../../data/pcap/anon-Booter8.pcap --tshark
[INFO] 
    ____  _                     __            
   / __ \(_)____________  _____/ /_____  _____
  / / / / / ___/ ___/ _ \/ ___/ __/ __ \/ ___/
 / /_/ / (__  |__  )  __/ /__/ /_/ /_/ / /    
/_____/_/____/____/\___/\___/\__/\____/_/     

[INFO] Conversion took 73.43s
[INFO] Extracting attack vectors.
[INFO] Analysis took 6.24s
```

For bigger pcap's the speed gains increase: A pcap of roughly 50GB, containing 36.6 million packets, takes the dissector over thirty minutes to process when using tshark. With pcap-converter this can be processed in under two minutes (105 seconds). 

## Other uses
Although pcap-converter is written explicitly with the Dissector in mind, you can use it on its own to convert a pcap file to parquet for easy analysis of packet characteristics. The dissector uses [duckdb](https://duckdb.org/), but any tool that can handle parquet files is suitable.  

### Parquet schema 

The (duckdb) table below shows the schema/column information in the resulting parquet file.
```
┌─────────────────────┬─────────────┬─────────┬─────────┬─────────┬─────────┐
│     column_name     │ column_type │  null   │   key   │ default │  extra  │
│       varchar       │   varchar   │ varchar │ varchar │ varchar │ varchar │
├─────────────────────┼─────────────┼─────────┼─────────┼─────────┼─────────┤
│ frame_time          │ TIMESTAMP   │ YES     │         │         │         │
│ frame_len           │ UINTEGER    │ YES     │         │         │         │
│ eth_type            │ USMALLINT   │ YES     │         │         │         │
│ ip_src              │ VARCHAR     │ YES     │         │         │         │
│ ip_dst              │ VARCHAR     │ YES     │         │         │         │
│ ip_proto            │ UTINYINT    │ YES     │         │         │         │
│ ip_ttl              │ UTINYINT    │ YES     │         │         │         │
│ ip_frag_offset      │ USMALLINT   │ YES     │         │         │         │
│ ip_id               │ USMALLINT   │ YES     │         │         │         │
│ ip_mf               │ BOOLEAN     │ YES     │         │         │         │
│ icmp_type           │ UTINYINT    │ YES     │         │         │         │
│ udp_length          │ USMALLINT   │ YES     │         │         │         │
│ tcp_flags           │ VARCHAR     │ YES     │         │         │         │
│ tcp_srcport         │ USMALLINT   │ YES     │         │         │         │
│ tcp_dstport         │ USMALLINT   │ YES     │         │         │         │
│ col_info            │ VARCHAR     │ YES     │         │         │         │
│ col_source          │ VARCHAR     │ YES     │         │         │         │
│ col_destination     │ VARCHAR     │ YES     │         │         │         │
│ dhip_device         │ VARCHAR     │ YES     │         │         │         │
│ pcap_file           │ VARCHAR     │ YES     │         │         │         │
│ udp_srcport         │ USMALLINT   │ YES     │         │         │         │
│ udp_dstport         │ USMALLINT   │ YES     │         │         │         │
│ ntp_priv_reqcode    │ UTINYINT    │ YES     │         │         │         │
│ dns_qry_type        │ USMALLINT   │ YES     │         │         │         │
│ dns_qry_name        │ VARCHAR     │ YES     │         │         │         │
│ col_protocol        │ VARCHAR     │ YES     │         │         │         │
├─────────────────────┴─────────────┴─────────┴─────────┴─────────┴─────────┤
│ 31 rows                                                         6 columns │
└───────────────────────────────────────────────────────────────────────────┘

```