//! Client for the `com.apple.os_trace_relay` lockdown service (unified log).
//!
//! The legacy `com.apple.syslog_relay` stream omits the Info/Debug resource
//! lookups that carry Wallet card (`.pkpass`) paths on recent iOS releases
//! (see Mak5er/AirCard PR #34 and issue #28). This module implements the
//! unified activity stream protocol on top of an `AMDServiceConnection`.
//!
//! Wire format (see also libimobiledevice `include/libimobiledevice/ostrace.h`):
//! every message is framed as `[type byte][u32 payload length]`. Plist
//! messages (type 1) use a big-endian length; activity records (type 2) use a
//! little-endian length. Activity records carry a 129-byte header followed by
//! length-delimited, NUL-terminated process, image and message strings.

/// Lockdown service providing the unified log activity stream.
pub const OS_TRACE_SERVICE: &str = "com.apple.os_trace_relay";

/// Frame type of plist messages (requests and status replies).
pub const FRAME_PLIST: u8 = 1;
/// Frame type of activity (log) records.
pub const FRAME_ACTIVITY: u8 = 2;

/// Largest frame payload we are willing to buffer (16 MiB, as on macOS).
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

const REQUEST_START_ACTIVITY: &str = "StartActivity";
/// Watch every process (UINT32_MAX).
const PID_ALL: u64 = u32::MAX as u64;
/// Accept every message type.
const MESSAGE_FILTER_ALL: u64 = 0xFFFF;
/// Payload, historical, callstack and debug-style events. Info/Debug resource
/// lookups containing Wallet card paths only appear with these flags.
const STREAM_FLAGS: u64 = 0x3C;

/// Build the `StartActivity` request dictionary that begins log streaming.
pub fn start_activity_request() -> plist::Value {
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "Request".to_string(),
        plist::Value::String(REQUEST_START_ACTIVITY.to_string()),
    );
    dict.insert(
        "Pid".to_string(),
        plist::Value::Integer(plist::Integer::from(PID_ALL)),
    );
    dict.insert(
        "MessageFilter".to_string(),
        plist::Value::Integer(plist::Integer::from(MESSAGE_FILTER_ALL)),
    );
    dict.insert(
        "StreamFlags".to_string(),
        plist::Value::Integer(plist::Integer::from(STREAM_FLAGS)),
    );
    plist::Value::Dictionary(dict)
}

/// Errors surfaced while reading the framed log stream.
#[derive(Debug)]
pub enum FrameError {
    /// The stop flag fired while waiting for data; the stream is healthy.
    Interrupted,
    /// The stream closed or violated the protocol.
    Stream(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Interrupted => write!(f, "interrupted by stop request"),
            FrameError::Stream(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Reads length-prefixed frames from a blocking byte source.
///
/// `receive` mirrors `AMDServiceConnectionReceive`: it returns the number of
/// bytes read (possibly fewer than requested), `0` on close and a negative
/// value on timeout or transient failure. Reading through the service
/// connection keeps secure (TLS-wrapped) sessions working as well.
pub struct FrameReader<R, S>
where
    R: FnMut(&mut [u8]) -> i32,
    S: Fn() -> bool,
{
    receive: R,
    should_stop: S,
}

impl<R, S> FrameReader<R, S>
where
    R: FnMut(&mut [u8]) -> i32,
    S: Fn() -> bool,
{
    pub fn new(receive: R, should_stop: S) -> Self {
        Self { receive, should_stop }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), FrameError> {
        let mut offset = 0;
        while offset < buf.len() {
            let count = (self.receive)(&mut buf[offset..]);
            if count < 0 {
                // Socket receive timeout or transient error: keep waiting
                // unless a stop was requested.
                if (self.should_stop)() {
                    return Err(FrameError::Interrupted);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            if count == 0 {
                return Err(FrameError::Stream("connection closed by device".to_string()));
            }
            offset += count as usize;
        }
        Ok(())
    }

    /// Read one full frame, returning `(frame type, payload)`.
    pub fn read_frame(&mut self) -> Result<(u8, Vec<u8>), FrameError> {
        let mut header = [0u8; 5];
        self.read_exact(&mut header)?;
        let frame_type = header[0];
        let length = match frame_type {
            FRAME_PLIST => {
                u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize
            }
            FRAME_ACTIVITY => {
                u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize
            }
            other => {
                return Err(FrameError::Stream(format!(
                    "unsupported log frame type {other}"
                )));
            }
        };
        // Reject corrupt lengths before allocating or waiting for a payload.
        if length == 0 || length > MAX_FRAME_LEN {
            return Err(FrameError::Stream(format!(
                "invalid log frame length {length}"
            )));
        }
        let mut payload = vec![0u8; length];
        self.read_exact(&mut payload)?;
        Ok((frame_type, payload))
    }

    /// Read one frame and decode it as a plist reply.
    pub fn read_plist_frame(&mut self) -> Result<plist::Value, FrameError> {
        let (frame_type, payload) = self.read_frame()?;
        if frame_type != FRAME_PLIST {
            return Err(FrameError::Stream(format!(
                "expected plist reply, got frame type {frame_type}"
            )));
        }
        plist::Value::from_reader(std::io::Cursor::new(&payload))
            .map_err(|e| FrameError::Stream(format!("failed to parse plist reply: {e}")))
    }
}

/// Decoded strings of one activity record.
pub struct ActivityRecord {
    pub process: String,
    pub image: String,
    pub message: String,
}

fn read_le16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]))
}

fn read_le32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

/// Decode a length-delimited, NUL-terminated UTF-8 (Latin-1 tolerated) string.
fn decode_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn last_path_component(text: String) -> String {
    text.rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or(text)
}

/// Parse one activity record payload into its strings.
///
/// Field offsets follow the activity record layout used by os_trace_relay:
/// record type at 0, header length at 5, process name length at 37, image
/// path length at 107 and message length at 109. Non-log or malformed
/// records yield `None`.
pub fn parse_activity_record(payload: &[u8]) -> Option<ActivityRecord> {
    if payload.len() < 129 || payload[0] != FRAME_ACTIVITY {
        return None;
    }
    let header_len = read_le32(payload, 5)? as usize;
    if header_len < 129 || header_len > payload.len() {
        return None;
    }
    let process_len = read_le16(payload, 37)? as usize;
    let image_len = read_le16(payload, 107)? as usize;
    let message_len = read_le32(payload, 109)? as usize;
    if process_len == 0 || message_len == 0 {
        return None;
    }
    if process_len + image_len + message_len > payload.len() - header_len {
        return None;
    }

    let text = &payload[header_len..];
    let process = decode_field(&text[..process_len]);
    let image = decode_field(&text[process_len..process_len + image_len]);
    let message = decode_field(&text[process_len + image_len..process_len + image_len + message_len]);

    Some(ActivityRecord {
        process: last_path_component(process),
        image: last_path_component(image),
        message,
    })
}

/// Format a record the same way the macOS AirCard helper does:
/// `process(image): message`. Multiline messages are kept intact —
/// CoreFoundation resource lookup logs expose Wallet `.pkpass` paths on a
/// continuation line, which the existing card filters match.
pub fn format_activity_line(record: &ActivityRecord) -> String {
    format!("{}({}): {}", record.process, record.image, record.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic Info-level CoreFoundation resource lookup record matching the
    /// iOS message shape. Uses the synthetic hash from the scanner tests; no
    /// identifiers from a real device are used here.
    fn fixture_record() -> Vec<u8> {
        let process = b"/usr/libexec/passd\0";
        let image =
            b"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation\0";
        let message = b"Resource lookup\n\tResult        : file:///var/mobile/Library/Passes/Cards/OM6NYhwXMZrAw0sRUjR62wmF4ZQ=.pkpass/en.lproj/actions.strings\0";
        let mut record = vec![0u8; 129];
        record[0] = FRAME_ACTIVITY;
        record[1] = 8;
        record[5..9].copy_from_slice(&129u32.to_le_bytes());
        record[37..39].copy_from_slice(&(process.len() as u16).to_le_bytes());
        record[68] = 1; // log level Info, unused by the parser
        record[107..109].copy_from_slice(&(image.len() as u16).to_le_bytes());
        record[109..113].copy_from_slice(&(message.len() as u32).to_le_bytes());
        record.extend_from_slice(process);
        record.extend_from_slice(image);
        record.extend_from_slice(message);
        record
    }

    fn frame_bytes(frame_type: u8, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u32;
        let mut out = vec![frame_type];
        if frame_type == FRAME_PLIST {
            out.extend_from_slice(&length.to_be_bytes());
        } else {
            out.extend_from_slice(&length.to_le_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    fn ack_frame_bytes() -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        dict.insert("Status".to_string(), plist::Value::String("RequestSuccessful".into()));
        let value = plist::Value::Dictionary(dict);
        let mut payload = Vec::new();
        plist::to_writer_binary(&mut payload, &value).unwrap();
        frame_bytes(FRAME_PLIST, &payload)
    }

    /// In-memory byte source delivering at most `chunk` bytes per call.
    fn mem_receive(data: Vec<u8>, chunk: usize) -> impl FnMut(&mut [u8]) -> i32 {
        let mut pos = 0usize;
        move |buf: &mut [u8]| {
            if pos >= data.len() {
                return 0;
            }
            let n = buf.len().min(chunk).min(data.len() - pos);
            buf[..n].copy_from_slice(&data[pos..pos + n]);
            pos += n;
            n as i32
        }
    }

    fn never_stop() -> bool {
        false
    }

    #[test]
    fn frames_handle_fragmentation_and_coalescing() {
        let mut wire = ack_frame_bytes();
        wire.extend_from_slice(&frame_bytes(FRAME_ACTIVITY, &fixture_record()));

        for chunk in [1usize, 3, 5, wire.len()] {
            let mut reader = FrameReader::new(mem_receive(wire.clone(), chunk), never_stop);
            let reply = reader.read_plist_frame().expect("plist frame");
            assert_eq!(
                reply
                    .as_dictionary()
                    .and_then(|d| d.get("Status"))
                    .and_then(|v| v.as_string()),
                Some("RequestSuccessful")
            );
            let (frame_type, payload) = reader.read_frame().expect("activity frame");
            assert_eq!(frame_type, FRAME_ACTIVITY);
            assert_eq!(payload, fixture_record());
            // Stream exhausted -> clean EOF error.
            assert!(matches!(
                reader.read_frame(),
                Err(FrameError::Stream(_))
            ));
        }
    }

    #[test]
    fn frames_reject_malformed_input() {
        let cases: Vec<Vec<u8>> = vec![
            vec![3, 1, 0, 0, 0],                                   // unknown type
            vec![FRAME_PLIST, 0, 0, 0, 0],                         // zero length
            vec![FRAME_ACTIVITY, 0xFF, 0xFF, 0xFF, 0x7F],          // oversized
            frame_bytes(FRAME_ACTIVITY, &fixture_record())[..10].to_vec(), // truncated
            vec![FRAME_PLIST, 0, 0, 0, 2],                         // header w/o payload
        ];
        for wire in cases {
            let mut reader = FrameReader::new(mem_receive(wire, 2), never_stop);
            assert!(
                reader.read_frame().is_err(),
                "expected malformed frame to fail"
            );
        }
    }

    #[test]
    fn stop_flag_interrupts_waiting_reader() {
        // Receive "times out" (negative return, like a socket SO_RCVTIMEO hit)
        // on an idle stream; the stop callback must interrupt the wait loop.
        let mut reader = FrameReader::new(|_buf: &mut [u8]| -1, || true);
        assert!(matches!(
            reader.read_frame(),
            Err(FrameError::Interrupted)
        ));
    }

    #[test]
    fn records_decode_process_image_and_message() {
        let record = parse_activity_record(&fixture_record()).expect("valid record");
        assert_eq!(record.process, "passd");
        assert_eq!(record.image, "CoreFoundation");
        assert!(record.message.starts_with("Resource lookup\n"));

        let line = format_activity_line(&record);
        assert!(line.starts_with("passd(CoreFoundation): Resource lookup\n"));
        assert!(line.contains(
            "/Cards/OM6NYhwXMZrAw0sRUjR62wmF4ZQ=.pkpass/en.lproj/actions.strings"
        ));
        assert!(!line.contains('\0'));
    }

    #[test]
    fn records_reject_malformed_payloads() {
        let record = fixture_record();
        // Truncated variants must not parse.
        assert!(parse_activity_record(&record[..128]).is_none());
        assert!(parse_activity_record(&record[..record.len() - 1]).is_none());

        // Corrupted length fields must not parse.
        for (offset, value) in [(5usize, u32::MAX), (109, u32::MAX)] {
            let mut corrupt = record.clone();
            corrupt[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(parse_activity_record(&corrupt).is_none());
        }
        let mut corrupt = record.clone();
        corrupt[37..39].copy_from_slice(&0u16.to_le_bytes()); // empty process
        assert!(parse_activity_record(&corrupt).is_none());

        // Wrong record type must not parse.
        let mut wrong_type = record.clone();
        wrong_type[0] = 1;
        assert!(parse_activity_record(&wrong_type).is_none());
    }

    #[test]
    fn multiline_path_reaches_existing_card_filters() {
        let record = parse_activity_record(&fixture_record()).unwrap();
        let line = format_activity_line(&record);
        let mut found = Vec::new();
        for part in line.split('\n') {
            found.extend(crate::scanner::extract_card_hashes_from_line(part));
        }
        assert_eq!(found, vec!["OM6NYhwXMZrAw0sRUjR62wmF4ZQ=".to_string()]);
    }
}
