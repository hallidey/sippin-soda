use super::*;
mod inspect;
pub use inspect::{JsonStatus, SearchStep};
use std::future::Future;
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream};

pub const PAGE_SIZE: usize = 64 * 1024;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyPage {
    pub offset: u64,
    pub total: u64,
    pub bytes: Vec<u8>,
    pub state: String,
    pub error: Option<String>,
    pub encoding: String,
}

pub(super) struct BodyInfo {
    pub total: u64,
    pub state: String,
    pub error: Option<String>,
    pub encoding: String,
}

struct Entry {
    json: Mutex<inspect::JsonView>,
    limit: u64,
    file: Mutex<Option<tempfile::NamedTempFile>>,
    worker: Mutex<Option<tokio::task::AbortHandle>>,
    budget: Arc<AtomicU64>,
    reserved: AtomicU64,
    total: AtomicU64,
    cancelled: AtomicBool,
    result: Mutex<(String, Option<String>)>,
    encoding: String,
}
impl Entry {
    fn cancel(&self) {
        let _result = self.result.lock().unwrap();
        self.cancelled.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.lock().unwrap().as_ref() {
            worker.abort();
        }
        self.file.lock().unwrap().take();
        self.json.lock().unwrap().file.take();
        self.budget
            .fetch_sub(self.reserved.swap(0, Ordering::Relaxed), Ordering::Relaxed);
    }
    fn finish(&self, state: &str, error: Option<&str>) {
        let mut result = self.result.lock().unwrap();
        if result.0 == "recording" {
            *result = (state.into(), error.map(String::from));
        }
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.budget
            .fetch_sub(self.reserved.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

pub(super) struct BodyStore {
    entries: Mutex<HashMap<u64, Arc<Entry>>>,
    used: Arc<AtomicU64>,
    analysis: Arc<tokio::sync::Semaphore>,
}
impl Default for BodyStore {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            used: Arc::new(AtomicU64::new(0)),
            analysis: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
}
impl BodyStore {
    pub fn info(&self, id: u64) -> Result<BodyInfo, String> {
        let entry = self
            .entries
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or("Body not recorded, cleared or evicted.")?;
        let (state, error) = entry.result.lock().unwrap().clone();
        Ok(BodyInfo {
            total: entry.total.load(Ordering::Acquire),
            state,
            error,
            encoding: entry.encoding.clone(),
        })
    }

    pub async fn export(&self, id: u64, destination: std::path::PathBuf) -> Result<u64, String> {
        let entry = self
            .entries
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or("Body not recorded, cleared or evicted.")?;
        tokio::task::spawn_blocking(move || {
            let (state, error) = entry.result.lock().unwrap().clone();
            if state != "complete" {
                return Err(error.unwrap_or_else(|| {
                    "Only a complete body can be exported; wait for recording to finish.".into()
                }));
            }
            let mut source = entry
                .file
                .lock()
                .unwrap()
                .as_ref()
                .ok_or("Body cleared or evicted.")?
                .reopen()
                .map_err(|_| "Cannot open the recorded body for export.")?;
            let mut output = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(destination)
                .map_err(|_| "Cannot create the selected export file.")?;
            let copied = std::io::copy(&mut source, &mut output)
                .map_err(|_| "Body export failed; the destination file may be incomplete.")?;
            output
                .flush()
                .map_err(|_| "Cannot flush the exported body.")?;
            Ok(copied)
        })
        .await
        .map_err(|_| "Body export worker failed.".to_string())?
    }

    pub(super) fn shared_pair() -> (Arc<Self>, Arc<Self>) {
        let used = Arc::new(AtomicU64::new(0));
        let analysis = Arc::new(tokio::sync::Semaphore::new(2));
        let make = || {
            Arc::new(Self {
                entries: Mutex::new(HashMap::new()),
                used: used.clone(),
                analysis: analysis.clone(),
            })
        };
        (make(), make())
    }
    pub async fn store_redacted_json(
        &self,
        id: u64,
        bytes: Vec<u8>,
        content_type: String,
        limit: u64,
        redaction_paths: Vec<Vec<String>>,
    ) -> Result<(), String> {
        let used = self.used.clone();
        let (file, length) = tokio::task::spawn_blocking(move || {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| "Request JSON is invalid or incomplete; original bytes were forwarded but not recorded.".to_string())?;
            redact_json(&mut value);
            for path in &redaction_paths {
                redact_path(&mut value, path);
            }
            let safe = serde_json::to_vec_pretty(&value)
                .map_err(|_| "Cannot serialize the redacted request body.".to_string())?;
            let length = safe.len() as u64;
            used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(length).filter(|next| *next <= limit)
            })
            .map_err(|_| "Session disk budget reached; redacted request body was not recorded.".to_string())?;
            let result: Result<(tempfile::NamedTempFile, u64), String> = (|| {
                let mut file = tempfile::Builder::new()
                    .prefix("sippin-request-")
                    .tempfile()
                    .map_err(|_| "Cannot create redacted request storage.".to_string())?;
                file.write_all(&safe)
                    .map_err(|_| "Cannot write redacted request storage.".to_string())?;
                file.flush()
                    .map_err(|_| "Cannot flush redacted request storage.".to_string())?;
                Ok((file, length))
            })();
            if result.is_err() {
                used.fetch_sub(length, Ordering::Relaxed);
            }
            result
        })
        .await
        .map_err(|_| "Request redaction worker failed.".to_string())??;
        let entry = Arc::new(Entry {
            json: Mutex::new(inspect::JsonView::default()),
            limit,
            file: Mutex::new(Some(file)),
            worker: Mutex::new(None),
            budget: self.used.clone(),
            reserved: AtomicU64::new(length),
            total: AtomicU64::new(length),
            cancelled: AtomicBool::new(false),
            result: Mutex::new(("complete".into(), None)),
            encoding: format!("redacted {content_type}"),
        });
        if let Some(previous) = self.entries.lock().unwrap().insert(id, entry) {
            previous.cancel();
        }
        Ok(())
    }
    pub async fn store_complete(&self, id: u64, bytes: Vec<u8>, limit: u64) -> Result<(), String> {
        let used = self.used.clone();
        let (file, length) = tokio::task::spawn_blocking(move || {
            let length = bytes.len() as u64;
            used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(length).filter(|next| *next <= limit)
            })
            .map_err(|_| {
                "Session disk budget reached; replacement body was not recorded.".to_string()
            })?;
            let result: Result<(tempfile::NamedTempFile, u64), String> = (|| {
                let mut file = tempfile::Builder::new()
                    .prefix("sippin-body-")
                    .tempfile()
                    .map_err(|_| "Cannot create replacement body storage.".to_string())?;
                file.write_all(&bytes)
                    .map_err(|_| "Cannot write replacement body storage.".to_string())?;
                file.flush()
                    .map_err(|_| "Cannot flush replacement body storage.".to_string())?;
                Ok((file, length))
            })();
            if result.is_err() {
                used.fetch_sub(length, Ordering::Relaxed);
            }
            result
        })
        .await
        .map_err(|_| "Replacement body storage worker failed.".to_string())??;
        let entry = Arc::new(Entry {
            json: Mutex::new(inspect::JsonView::default()),
            limit,
            file: Mutex::new(Some(file)),
            worker: Mutex::new(None),
            budget: self.used.clone(),
            reserved: AtomicU64::new(length),
            total: AtomicU64::new(length),
            cancelled: AtomicBool::new(false),
            result: Mutex::new(("complete".into(), None)),
            encoding: "identity".into(),
        });
        if let Some(previous) = self.entries.lock().unwrap().insert(id, entry) {
            previous.cancel();
        }
        Ok(())
    }
    pub fn remove(&self, id: u64) {
        if let Some(entry) = self.entries.lock().unwrap().remove(&id) {
            entry.cancel();
        }
    }
    pub fn clear(&self) {
        for (_, entry) in self.entries.lock().unwrap().drain() {
            entry.cancel();
        }
    }
    pub async fn page(&self, id: u64, offset: u64, length: usize) -> Result<BodyPage, String> {
        if length == 0 || length > PAGE_SIZE {
            return Err("Read size must be between 1 and 65536 bytes.".into());
        }
        let entry = self
            .entries
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or("Body not recorded, cleared or evicted.")?;
        tokio::task::spawn_blocking(move || {
            // Observe completion before length: a complete page must never
            // advertise a stale shorter length while the writer finishes.
            let (state, error) = entry.result.lock().unwrap().clone();
            let total = entry.total.load(Ordering::Acquire);
            if offset > total {
                return Err("Offset exceeds the recorded body.".into());
            }
            let mut reader = entry
                .file
                .lock()
                .unwrap()
                .as_ref()
                .ok_or("Body cleared or evicted.")?
                .reopen()
                .map_err(|_| "Cannot open recorded body.")?;
            reader
                .seek(SeekFrom::Start(offset))
                .map_err(|_| "Cannot seek recorded body.")?;
            let mut bytes = vec![0; length.min((total - offset) as usize)];
            reader
                .read_exact(&mut bytes)
                .map_err(|_| "Cannot read recorded body.")?;
            Ok(BodyPage {
                offset,
                total,
                bytes,
                state,
                error,
                encoding: entry.encoding.clone(),
            })
        })
        .await
        .map_err(|_| "Body reader failed.".to_string())?
    }
    pub async fn record(&self, id: u64, encoding: String, limit: u64) -> Result<Tap, String> {
        let file = tokio::task::spawn_blocking(|| {
            tempfile::Builder::new().prefix("sippin-body-").tempfile()
        })
        .await
        .map_err(|_| "Cannot start body storage.")?
        .map_err(|_| "Cannot create body storage.")?;
        let writer = file.reopen().map_err(|_| "Cannot open body writer.")?;
        let entry = Arc::new(Entry {
            json: Mutex::new(inspect::JsonView::default()),
            limit,
            file: Mutex::new(Some(file)),
            worker: Mutex::new(None),
            budget: self.used.clone(),
            reserved: AtomicU64::new(0),
            total: AtomicU64::new(0),
            cancelled: AtomicBool::new(false),
            result: Mutex::new(("recording".into(), None)),
            encoding: encoding.clone(),
        });
        self.entries.lock().unwrap().insert(id, entry.clone());
        let (input, reader) = tokio::io::duplex(PAGE_SIZE);
        let entry_task = entry.clone();
        let task = tokio::spawn(async move {
            let reader = BufReader::with_capacity(PAGE_SIZE, reader);
            use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder};
            let mut source: Pin<Box<dyn AsyncRead + Send>> = match encoding.as_str() {
                "" | "identity" => Box::pin(reader),
                "gzip" => {
                    let mut decoder = GzipDecoder::new(reader);
                    decoder.multiple_members(true);
                    Box::pin(decoder)
                }
                "deflate" => Box::pin(ZlibDecoder::new(reader)),
                "br" => Box::pin(BrotliDecoder::new(reader)),
                _ => {
                    entry_task.finish(
                        "unavailable",
                        Some("Unsupported Content-Encoding; response forwarding is unchanged."),
                    );
                    return;
                }
            };
            let mut output = tokio::fs::File::from_std(writer);
            let mut buffer = vec![0; PAGE_SIZE];
            loop {
                if entry_task.cancelled.load(Ordering::Relaxed) {
                    return;
                }
                let count = match source.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(_) => {
                        entry_task.finish("partial", Some("Body decoding or transport failed."));
                        return;
                    }
                };
                {
                    let mut result = entry_task.result.lock().unwrap();
                    if entry_task.cancelled.load(Ordering::Relaxed) {
                        return;
                    }
                    if entry_task
                        .budget
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                            used.checked_add(count as u64).filter(|next| *next <= limit)
                        })
                        .is_err()
                    {
                        *result = ("partial".into(), Some("Session disk budget reached. Increase the budget before retrying; forwarding continues.".into()));
                        return;
                    }
                    entry_task
                        .reserved
                        .fetch_add(count as u64, Ordering::Relaxed);
                }
                if output.write_all(&buffer[..count]).await.is_err()
                    || output.flush().await.is_err()
                {
                    entry_task.finish(
                        "partial",
                        Some("Body storage write failed; forwarding continues."),
                    );
                    return;
                }
                entry_task.total.fetch_add(count as u64, Ordering::Release);
            }
            entry_task.finish("complete", None);
        });
        *entry.worker.lock().unwrap() = Some(task.abort_handle());
        if entry.cancelled.load(Ordering::Relaxed) {
            entry.cancel();
        }
        Ok(Tap {
            input: Some(input),
            task,
            entry,
        })
    }
}

fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let normalized: String = key
                    .chars()
                    .filter(|character| !matches!(character, '-' | '_' | '.'))
                    .flat_map(char::to_lowercase)
                    .collect();
                if [
                    "authorization",
                    "password",
                    "passwd",
                    "token",
                    "accesstoken",
                    "refreshtoken",
                    "apikey",
                    "secret",
                    "clientsecret",
                    "cookie",
                    "session",
                ]
                .contains(&normalized.as_str())
                {
                    *value = serde_json::Value::String("[REDACTED]".into());
                } else {
                    redact_json(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json),
        _ => {}
    }
}

pub(super) fn compile_redaction_paths(paths: &[String]) -> Result<Vec<Vec<String>>, String> {
    if paths.len() > 64 {
        return Err("At most 64 custom request redaction paths are allowed.".into());
    }
    paths
        .iter()
        .filter(|path| !path.trim().is_empty())
        .map(|path| {
            let path = path.trim();
            if path.len() > 512 || !path.starts_with('/') {
                return Err(
                    "Redaction paths must be JSON Pointers beginning with '/' and at most 512 characters."
                        .into(),
                );
            }
            path[1..]
                .split('/')
                .map(decode_pointer_segment)
                .collect()
        })
        .collect()
}

fn decode_pointer_segment(segment: &str) -> Result<String, String> {
    let mut decoded = String::with_capacity(segment.len());
    let mut characters = segment.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => return Err("Redaction paths contain an invalid JSON Pointer escape.".into()),
        }
    }
    Ok(decoded)
}

fn redact_path(value: &mut serde_json::Value, path: &[String]) {
    let Some((segment, remaining)) = path.split_first() else {
        *value = serde_json::Value::String("[REDACTED]".into());
        return;
    };
    match value {
        serde_json::Value::Object(object) if segment == "*" => {
            object
                .values_mut()
                .for_each(|value| redact_path(value, remaining));
        }
        serde_json::Value::Object(object) => {
            if let Some(value) = object.get_mut(segment) {
                redact_path(value, remaining);
            }
        }
        serde_json::Value::Array(values) if segment == "*" => {
            values
                .iter_mut()
                .for_each(|value| redact_path(value, remaining));
        }
        serde_json::Value::Array(values) => {
            if let Ok(index) = segment.parse::<usize>() {
                if let Some(value) = values.get_mut(index) {
                    redact_path(value, remaining);
                }
            }
        }
        _ => {}
    }
}

pub(super) struct Tap {
    input: Option<DuplexStream>,
    task: JoinHandle<()>,
    entry: Arc<Entry>,
}
impl Tap {
    pub async fn finish_empty(mut self) {
        self.input.take();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Tap {
    fn drop(&mut self) {
        self.entry
            .finish("partial", Some("Body capture interrupted."));
        self.task.abort();
    }
}

/// Tee to a bounded pipe. A slow disk applies backpressure, never a growing queue.
pub(super) struct RecordedBody {
    pub inner: ObservedBody,
    pub tap: Option<Tap>,
    pub pending: Option<Frame<Bytes>>,
    pub written: usize,
}
impl Body for RecordedBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        if self.pending.is_none() {
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => {
                    self.pending = Some(frame);
                    self.written = 0;
                }
                Poll::Ready(Some(Err(error))) => {
                    self.tap.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    if let Some(tap) = &mut self.tap {
                        tap.input.take();
                        if Pin::new(&mut tap.task).poll(cx).is_pending() {
                            return Poll::Pending;
                        }
                    }
                    self.tap.take();
                    return Poll::Ready(None);
                }
            }
        }
        let this = &mut *self;
        if let Some(bytes) = this.pending.as_ref().and_then(Frame::data_ref) {
            while this.written < bytes.len() {
                let Some(tap) = &mut this.tap else {
                    break;
                };
                if tap.entry.cancelled.load(Ordering::Relaxed) {
                    this.tap.take();
                    break;
                }
                let Some(input) = &mut tap.input else {
                    break;
                };
                match Pin::new(input).poll_write(cx, &bytes[this.written..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0) | Err(_)) => {
                        this.tap.take();
                        break;
                    }
                    Poll::Ready(Ok(count)) => this.written += count,
                }
            }
        }
        if this.inner.is_end_stream() {
            if let Some(tap) = &mut this.tap {
                tap.input.take();
                if Pin::new(&mut tap.task).poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            this.tap.take();
        }
        Poll::Ready(this.pending.take().map(Ok))
    }
    fn is_end_stream(&self) -> bool {
        self.tap.is_none() && self.pending.is_none() && self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::{compile_redaction_paths, redact_json, redact_path, BodyStore};

    #[test]
    fn redacts_sensitive_keys_recursively_without_changing_safe_values() {
        let mut value = serde_json::json!({
            "email": "dev@example.test",
            "password": "hunter2",
            "nested": { "access_token": "abc", "count": 3 },
            "items": [{ "client-secret": "xyz" }]
        });
        redact_json(&mut value);
        assert_eq!(value["email"], "dev@example.test");
        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["nested"]["access_token"], "[REDACTED]");
        assert_eq!(value["nested"]["count"], 3);
        assert_eq!(value["items"][0]["client-secret"], "[REDACTED]");
    }

    #[test]
    fn custom_json_pointers_support_arrays_wildcards_and_escapes() {
        let paths = compile_redaction_paths(&[
            "/customers/*/email".into(),
            "/metadata/card~1number".into(),
        ])
        .unwrap();
        let mut value = serde_json::json!({
            "customers": [{"email": "one@test"}, {"email": "two@test"}],
            "metadata": {"card/number": "4111", "safe": true}
        });
        for path in &paths {
            redact_path(&mut value, path);
        }
        assert_eq!(value["customers"][0]["email"], "[REDACTED]");
        assert_eq!(value["customers"][1]["email"], "[REDACTED]");
        assert_eq!(value["metadata"]["card/number"], "[REDACTED]");
        assert_eq!(value["metadata"]["safe"], true);
        assert!(compile_redaction_paths(&["customers/email".into()]).is_err());
        assert!(compile_redaction_paths(&["/bad~2escape".into()]).is_err());
    }

    #[tokio::test]
    async fn request_and_response_stores_share_one_session_budget() {
        let (request, response) = BodyStore::shared_pair();
        let body = format!(r#"{{"safe":"{}"}}"#, "x".repeat(60)).into_bytes();
        request
            .store_redacted_json(1, body.clone(), "application/json".into(), 100, vec![])
            .await
            .unwrap();
        assert!(response
            .store_redacted_json(2, body, "application/json".into(), 100, vec![])
            .await
            .is_err());
    }
}
