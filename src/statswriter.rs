use std::{fmt::Debug, sync::Arc};
use std::fs::File;
use crate::StatsCollector;
use anyhow::Error;
use num_format::{Locale, ToFormattedString};
use arrow::datatypes::*;
use arrow::array::*;
use parquet::{
    basic::{Compression, Encoding},
    file::properties::*,
    arrow::ArrowWriter,
};
// use std::hash::{DefaultHasher, Hash, Hasher};

#[derive(Debug)]
pub struct PacketBatch {
    pub batch: RecordBatch,
    pub packet_count: usize,
    pub errors: i64,
}

#[derive(Debug)]
pub struct StatsWriter {
    pub writer: ArrowWriter<std::fs::File>,
    packet_count: usize,
    errors: i64,
    verbose: bool,
}

impl StatsWriter {
    pub fn new(filename: &str, verbose: bool) -> Result<StatsWriter, Error> {
        // return Default::default()

        let fields = StatsCollector::create_fields();
        let schema = Schema::new(fields.clone());
        let props = WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_encoding(Encoding::PLAIN)
        .set_compression(Compression::SNAPPY)
        .build();
    // .set_column_encoding(ColumnPath::from("col1"), Encoding::DELTA_BINARY_PACKED)
    
        // eprintln!("Trying to open file {}", filename);
        let file = File::create(filename).unwrap();

        let writer = ArrowWriter::try_new(file, Arc::new(schema.clone()), Some(props))?;
    
        let sw = StatsWriter { 
                writer: writer,
                packet_count: 0,
                errors: 0,
                verbose: verbose,
            };
    
        Ok(sw)
    }

    pub fn write_batch(&mut self, batch: PacketBatch) {
        // let batch = self.record_batch();
        self.writer.write(&batch.batch).unwrap();
        self.packet_count += batch.packet_count;
        self.errors += batch.errors;

        if self.verbose {
            eprint!("\rPackets: {} Errors: {}", 
                self.packet_count.to_formatted_string(&Locale::en), 
                self.errors.to_formatted_string(&Locale::en));
        }
    }
 
    pub fn close_parquet(&mut self) {
        // self.flush();
        let _ = self.writer.flush();
    }

}


