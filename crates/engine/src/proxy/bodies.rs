use super::*;
use std::future::Future;
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
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

struct Entry {
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

#[derive(Default)]
pub(super) struct BodyStore {
    entries: Mutex<HashMap<u64, Arc<Entry>>>,
    used: Arc<AtomicU64>,
}
impl BodyStore {
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
