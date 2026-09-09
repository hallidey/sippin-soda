use super::*;
use std::io::{self, BufReader as SyncReader, BufWriter, Write};

const SCAN_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchStep {
    pub found: Option<u64>,
    pub next_offset: u64,
    pub scanned_to: u64,
    pub done: bool,
}

#[derive(Clone, Serialize)]
pub struct JsonStatus {
    pub state: String,
    pub error: Option<String>,
}

pub(super) struct JsonView {
    pub file: Option<tempfile::NamedTempFile>,
    total: u64,
    status: JsonStatus,
    cancel: Arc<AtomicBool>,
}
impl Default for JsonView {
    fn default() -> Self {
        Self {
            file: None,
            total: 0,
            status: JsonStatus {
                state: "idle".into(),
                error: None,
            },
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl BodyStore {
    fn entry(&self, id: u64) -> Result<Arc<Entry>, String> {
        self.entries
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or("Body not recorded, cleared or evicted.".into())
    }
    pub async fn search(
        &self,
        id: u64,
        needle: String,
        start: u64,
        end: u64,
    ) -> Result<SearchStep, String> {
        if needle.is_empty() || needle.len() > 4096 {
            return Err("Search requires 1–4096 UTF-8 bytes.".into());
        }
        let entry = self.entry(id)?;
        let permit = self
            .analysis
            .clone()
            .try_acquire_owned()
            .map_err(|_| "Body analysis is busy. Try again.")?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if start > end || end > entry.total.load(Ordering::Acquire) {
                return Err("Invalid search range.".into());
            }
            let mut reader = entry
                .file
                .lock()
                .unwrap()
                .as_ref()
                .ok_or("Body cleared.")?
                .reopen()
                .map_err(|_| "Cannot open body.")?;
            reader
                .seek(SeekFrom::Start(start))
                .map_err(|_| "Cannot seek body.")?;
            scan(&mut reader, needle.as_bytes(), start, end, || {
                entry.cancelled.load(Ordering::Relaxed)
            })
        })
        .await
        .map_err(|_| "Search worker failed.".to_string())?
    }
    pub fn json_view(&self, id: u64, start: bool, cancel: bool) -> Result<JsonStatus, String> {
        let entry = self.entry(id)?;
        if entry.result.lock().unwrap().0 != "complete" {
            return Err("JSON layout requires a complete recorded body.".into());
        }
        let mut view = entry.json.lock().unwrap();
        if cancel {
            view.cancel.store(true, Ordering::Relaxed);
            return Ok(view.status.clone());
        }
        if !start {
            return Ok(view.status.clone());
        }
        if view.status.state == "building" || view.status.state == "ready" {
            return Ok(view.status.clone());
        }
        let permit = self
            .analysis
            .clone()
            .try_acquire_owned()
            .map_err(|_| "Body analysis is busy. Try again.")?;
        view.cancel = Arc::new(AtomicBool::new(false));
        view.status = JsonStatus {
            state: "building".into(),
            error: None,
        };
        let result = view.status.clone();
        let token = view.cancel.clone();
        drop(view);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut outcome = format_json(&entry, token.clone());
            if token.load(Ordering::Relaxed) || entry.cancelled.load(Ordering::Relaxed) {
                if let Ok((_, total)) = &outcome {
                    let _guard = entry.result.lock().unwrap();
                    if !entry.cancelled.load(Ordering::Relaxed) {
                        entry.reserved.fetch_sub(*total, Ordering::Relaxed);
                        entry.budget.fetch_sub(*total, Ordering::Relaxed);
                    }
                }
                outcome = Err("JSON layout cancelled.".into());
            }
            let mut view = entry.json.lock().unwrap();
            match outcome {
                Ok((file, total)) => {
                    view.file = Some(file);
                    view.total = total;
                    view.status = JsonStatus {
                        state: "ready".into(),
                        error: None,
                    };
                }
                other => {
                    view.status = JsonStatus {
                        state: "error".into(),
                        error: Some(
                            other
                                .err()
                                .unwrap_or_else(|| "JSON layout cancelled.".into()),
                        ),
                    };
                }
            }
        });
        Ok(result)
    }
    pub async fn json_page(&self, id: u64, offset: u64, length: usize) -> Result<BodyPage, String> {
        if length == 0 || length > PAGE_SIZE {
            return Err("Read size must be between 1 and 65536 bytes.".into());
        }
        let entry = self.entry(id)?;
        tokio::task::spawn_blocking(move || {
            let (mut reader, total) = {
                let view = entry.json.lock().unwrap();
                (
                    view.file
                        .as_ref()
                        .ok_or("JSON layout is not ready.")?
                        .reopen()
                        .map_err(|_| "Cannot open JSON layout.")?,
                    view.total,
                )
            };
            if offset > total {
                return Err("Offset exceeds JSON layout.".into());
            }
            reader
                .seek(SeekFrom::Start(offset))
                .map_err(|_| "Cannot seek JSON layout.")?;
            let mut bytes = vec![0; length.min((total - offset) as usize)];
            reader
                .read_exact(&mut bytes)
                .map_err(|_| "Cannot read JSON layout.")?;
            if entry.cancelled.load(Ordering::Relaxed) {
                return Err("Body cleared or evicted.".into());
            }
            Ok(BodyPage {
                offset,
                total,
                bytes,
                state: "complete".into(),
                error: None,
                encoding: "JSON layout".into(),
            })
        })
        .await
        .map_err(|_| "JSON reader failed.".to_string())?
    }
}

// KMP: linear scan, including matches split across buffers/IPC scan steps.
fn scan(
    reader: &mut impl Read,
    needle: &[u8],
    start: u64,
    end: u64,
    cancelled: impl Fn() -> bool,
) -> Result<SearchStep, String> {
    let mut prefix = vec![0; needle.len()];
    let mut matched = 0;
    for index in 1..needle.len() {
        while matched > 0 && needle[index] != needle[matched] {
            matched = prefix[matched - 1];
        }
        if needle[index] == needle[matched] {
            matched += 1;
        }
        prefix[index] = matched;
    }
    matched = 0;
    let stop = end.min(start.saturating_add(SCAN_BYTES));
    let mut position = start;
    let mut buffer = vec![0; PAGE_SIZE];
    while position < stop {
        if cancelled() {
            return Err("Search cancelled: body cleared or evicted.".into());
        }
        let count = buffer.len().min((stop - position) as usize);
        reader
            .read_exact(&mut buffer[..count])
            .map_err(|_| "Cannot read search range.")?;
        for byte in &buffer[..count] {
            while matched > 0 && *byte != needle[matched] {
                matched = prefix[matched - 1];
            }
            if *byte == needle[matched] {
                matched += 1;
            }
            position += 1;
            if matched == needle.len() {
                let found = position - needle.len() as u64;
                return Ok(SearchStep {
                    found: Some(found),
                    next_offset: found + 1,
                    scanned_to: position,
                    done: true,
                });
            }
        }
    }
    Ok(SearchStep {
        found: None,
        next_offset: if stop == end {
            end
        } else {
            position - matched as u64
        },
        scanned_to: stop,
        done: stop == end,
    })
}

// Validation and formatting use bounded buffers; strings are never materialized.
struct CheckedReader {
    file: std::fs::File,
    entry: Arc<Entry>,
    token: Arc<AtomicBool>,
    depth: usize,
    string: bool,
    escaped: bool,
    utf8_tail: Vec<u8>,
}
impl Read for CheckedReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.entry.cancelled.load(Ordering::Relaxed) || self.token.load(Ordering::Relaxed) {
            return Err(io::Error::other("JSON layout cancelled."));
        }
        let count = self.file.read(bytes)?;
        let mut utf8 = std::mem::take(&mut self.utf8_tail);
        utf8.extend_from_slice(&bytes[..count]);
        if let Err(error) = std::str::from_utf8(&utf8) {
            if error.error_len().is_some() || count == 0 {
                return Err(io::Error::other("JSON is not valid UTF-8."));
            }
            self.utf8_tail
                .extend_from_slice(&utf8[error.valid_up_to()..]);
        }
        for byte in &bytes[..count] {
            if self.string {
                if self.escaped {
                    self.escaped = false;
                } else if *byte == b'\\' {
                    self.escaped = true;
                } else if *byte == b'"' {
                    self.string = false;
                }
            } else if *byte == b'"' {
                self.string = true;
            } else if *byte == b'{' || *byte == b'[' {
                self.depth += 1;
                if self.depth > 128 {
                    return Err(io::Error::other(
                        "JSON layout supports nesting up to 128 levels.",
                    ));
                }
            } else if *byte == b'}' || *byte == b']' {
                self.depth = self.depth.saturating_sub(1);
            }
        }
        Ok(count)
    }
}

struct BudgetWriter<'a> {
    file: std::fs::File,
    entry: &'a Entry,
    token: Arc<AtomicBool>,
    reserved: u64,
    keep: bool,
}
impl Write for BudgetWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        {
            let _guard = self.entry.result.lock().unwrap();
            if self.entry.cancelled.load(Ordering::Relaxed) || self.token.load(Ordering::Relaxed) {
                return Err(io::Error::other("JSON layout cancelled."));
            }
            self.entry
                .budget
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(bytes.len() as u64)
                        .filter(|next| *next <= self.entry.limit)
                })
                .map_err(|_| {
                    io::Error::other(
                        "Session disk budget reached; original body remains available.",
                    )
                })?;
            self.entry
                .reserved
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            self.reserved += bytes.len() as u64;
        }
        self.file.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Drop for BudgetWriter<'_> {
    fn drop(&mut self) {
        let _guard = self.entry.result.lock().unwrap();
        if !self.keep && !self.entry.cancelled.load(Ordering::Relaxed) {
            self.entry
                .reserved
                .fetch_sub(self.reserved, Ordering::Relaxed);
            self.entry
                .budget
                .fetch_sub(self.reserved, Ordering::Relaxed);
        }
    }
}

fn format_json(
    entry: &Arc<Entry>,
    token: Arc<AtomicBool>,
) -> Result<(tempfile::NamedTempFile, u64), String> {
    let open = || -> Result<SyncReader<CheckedReader>, String> {
        let file = entry
            .file
            .lock()
            .unwrap()
            .as_ref()
            .ok_or("Body cleared.")?
            .reopen()
            .map_err(|_| "Cannot open body.")?;
        Ok(SyncReader::with_capacity(
            PAGE_SIZE,
            CheckedReader {
                file,
                entry: entry.clone(),
                token: token.clone(),
                depth: 0,
                string: false,
                escaped: false,
                utf8_tail: vec![],
            },
        ))
    };
    let mut de = serde_json::Deserializer::from_reader(open()?);
    <serde::de::IgnoredAny as serde::Deserialize>::deserialize(&mut de)
        .and_then(|_| de.end())
        .map_err(|error| format!("JSON layout unavailable: {error}"))?;
    let file = tempfile::Builder::new()
        .prefix("sippin-json-")
        .tempfile()
        .map_err(|_| "Cannot create JSON layout.")?;
    let handle = file.reopen().map_err(|_| "Cannot open JSON writer.")?;
    let mut output = BufWriter::with_capacity(
        PAGE_SIZE,
        BudgetWriter {
            file: handle,
            entry,
            token: token.clone(),
            reserved: 0,
            keep: false,
        },
    );
    let mut string = false;
    let mut escaped = false;
    let mut depth = 0;
    for byte in open()?.bytes() {
        let byte = byte.map_err(|error| error.to_string())?;
        let write = |output: &mut BufWriter<BudgetWriter<'_>>, bytes: &[u8]| {
            output.write_all(bytes).map_err(|error| error.to_string())
        };
        if string {
            write(&mut output, &[byte])?;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => {
                    string = true;
                    write(&mut output, &[byte])?;
                }
                b'{' | b'[' => {
                    depth += 1;
                    write(&mut output, &[byte, b'\n'])?;
                    write(&mut output, &vec![b' '; depth * 2])?;
                }
                b'}' | b']' => {
                    depth -= 1;
                    write(&mut output, b"\n")?;
                    write(&mut output, &vec![b' '; depth * 2])?;
                    write(&mut output, &[byte])?;
                }
                b',' => {
                    write(&mut output, b",\n")?;
                    write(&mut output, &vec![b' '; depth * 2])?;
                }
                b':' => write(&mut output, b": ")?,
                b' ' | b'\n' | b'\r' | b'\t' => {}
                _ => write(&mut output, &[byte])?,
            }
        }
    }
    output.flush().map_err(|error| error.to_string())?;
    let size = output.get_ref().reserved;
    output.get_mut().keep = true;
    Ok((file, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn search_crosses_buffer_and_step_boundaries_and_preserves_overlaps() {
        for boundary in [PAGE_SIZE, SCAN_BYTES as usize] {
            let mut body = vec![b'x'; boundary - 2];
            body.extend_from_slice("èabababa".as_bytes());
            let mut cursor = Cursor::new(&body);
            let mut offset = 0;
            let hit = loop {
                cursor.set_position(offset);
                let step = scan(
                    &mut cursor,
                    "èababa".as_bytes(),
                    offset,
                    body.len() as u64,
                    || false,
                )
                .unwrap();
                if let Some(hit) = step.found {
                    break hit;
                }
                assert!(!step.done);
                assert!(step.next_offset > offset);
                offset = step.next_offset;
            };
            assert_eq!(hit, boundary as u64 - 2);
        }
        let mut reader = Cursor::new(b"abababa");
        assert_eq!(
            scan(&mut reader, b"ababa", 0, 7, || false).unwrap().found,
            Some(0)
        );
        reader.set_position(1);
        assert_eq!(
            scan(&mut reader, b"ababa", 1, 7, || false).unwrap().found,
            Some(2)
        );
    }

    #[test]
    fn search_honors_frozen_range_and_cancellation() {
        let mut reader = Cursor::new(b"prefix-needle");
        assert!(scan(&mut reader, b"needle", 0, 10, || false)
            .unwrap()
            .found
            .is_none());
        reader.set_position(0);
        assert!(scan(&mut reader, b"needle", 0, 13, || true).is_err());
    }
}
