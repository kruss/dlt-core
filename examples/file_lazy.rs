use dlt_core::{lazy::StoredMessageSlice, read::DltMessageReader};
use std::{
    env,
    fmt::{self, Formatter},
    fs,
    fs::File,
    io,
    io::Write,
    path::PathBuf,
    time::Instant,
};

fn main() {
    // collect input file details
    let dlt_file_path = PathBuf::from(&env::args().nth(1).expect("no filename given"));
    let dlt_file = File::open(&dlt_file_path).expect("open input file");
    let dlt_file_size = fs::metadata(&dlt_file_path).expect("file size error").len();
    // now parse all file content
    let mut dlt_reader = DltMessageReader::new(dlt_file, true);
    let mut message_count = 0usize;
    let mut bytes_count = 0usize;
    let mut sink = io::sink();
    let start = Instant::now();
    loop {
        let slice = dlt_reader.next_message_slice().expect("next");
        if slice.is_empty() {
            break;
        }

        let message = StoredMessageSlice::new(&slice);
        message_count += 1;

        let formatter = MessageFormatter { message };
        let string = format!("{}", formatter);

        let buffer = string.as_bytes();
        sink.write(&buffer).unwrap();
        bytes_count += buffer.len();
    }
    // print some stats
    let duration_in_s = start.elapsed().as_millis() as f64 / 1000.0;
    let file_size_in_mb = dlt_file_size as f64 / 1024.0 / 1024.0;
    let amount_per_second: f64 = file_size_in_mb / duration_in_s;
    println!(
        "parsing {} messages and consuming {} bytes took {:.3}s! ({:.3} MB/s)",
        message_count, bytes_count, duration_in_s, amount_per_second
    );
}

struct MessageFormatter<'a> {
    message: StoredMessageSlice<'a>,
}

impl fmt::Display for MessageFormatter<'_> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let storage_header = self.message.storage_header();
        let timestamp = storage_header.timestamp().expect("timestamp");
        write!(f, "{}:{} ", timestamp.seconds, timestamp.microseconds)?;

        let message = self.message.message();
        let standard_header = message.standard_header().expect("standard_header");
        write!(f, "V{} ", standard_header.version().expect("version"))?;
        write!(
            f,
            "#{} ",
            standard_header.message_counter().expect("message_counter")
        )?;
        if let Some(timestamp) = standard_header.timestamp().expect("timestamp") {
            write!(f, "@{} ", timestamp)?;
        }
        if let Some(ecu_id) = standard_header.ecu_id().expect("ecu_id") {
            write!(f, "E{} ", ecu_id)?;
        }
        if let Ok(Some(session_id)) = standard_header.session_id() {
            write!(f, "S{} ", session_id)?;
        }

        if let Some(extended_header) = message.extended_header().expect("extended_header") {
            write!(
                f,
                "T:{:?} ",
                extended_header.message_type().expect("message_type")
            )?;

            write!(
                f,
                "A:{} ",
                extended_header.application_id().expect("application_id")
            )?;
            write!(
                f,
                "C:{} ",
                extended_header.context_id().expect("context_id")
            )?;
        }

        let payload = message.payload().expect("payload");
        write!(f, "{:?}", payload)?;

        Ok(())
    }
}
