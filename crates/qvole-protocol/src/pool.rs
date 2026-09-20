//! Reusable 32 KiB buffers for bulk data copy (Go `internal/engine/pool.go`).
//!
//! Go uses a `sync.Pool` (per-goroutine caching, GC-eligible). The closest
//! Rust analog with the same observable behavior - fresh 32 KiB buffers,
//! zeroed before return to the pool - is a thread-local stack of `Vec<u8>`:
//! buffers are reused within a thread and never shared across threads, which
//! is also what the copy loops need (one buffer per direction per task).

const BUFFER_POOL_SIZE: usize = 32 * 1024;

thread_local! {
    static POOL: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Returns a 32 KiB buffer (reused from this thread's pool when available).
///
/// Port of `BufferPool.Get()`.
#[must_use]
pub fn get_buffer() -> Vec<u8> {
    POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .unwrap_or_else(|| vec![0u8; BUFFER_POOL_SIZE])
    })
}

/// Zeroes `buf` and returns it to the pool (Go `PutBuffer`).
///
/// The buffer is zeroed so reused buffers cannot leak bulk data into the next
/// consumer. Only exact-size buffers are pooled; anything else (Go: `nil`)
/// is just zeroed and dropped.
pub fn put_buffer(buf: &mut Vec<u8>) {
    qvole_spake2::zero_bytes(&mut buf[..]);
    if buf.len() == BUFFER_POOL_SIZE {
        POOL.with(|pool| pool.borrow_mut().push(std::mem::take(buf)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_correct_size() {
        let mut buf = get_buffer();
        assert_eq!(buf.len(), 32 * 1024);
        put_buffer(&mut buf);
    }

    #[test]
    fn capacity() {
        let mut buf = get_buffer();
        assert!(buf.capacity() >= 32 * 1024);
        put_buffer(&mut buf);
    }

    #[test]
    fn put_zeros_contents() {
        let mut buf = get_buffer();
        buf.fill(0xFF);
        put_buffer(&mut buf);

        let mut buf2 = get_buffer();
        assert!(
            buf2.iter().all(|&b| b == 0),
            "PutBuffer did not zero the buffer contents"
        );
        put_buffer(&mut buf2);
    }

    #[test]
    fn returns_to_pool() {
        let mut buf = get_buffer();
        put_buffer(&mut buf);
        // Should be able to get another buffer without panic.
        let mut buf2 = get_buffer();
        put_buffer(&mut buf2);
    }

    // Rust analog of TestPutBuffer_Nil (no nil slices): an empty buffer must
    // not panic and must not pollute the pool.
    #[test]
    fn put_buffer_empty() {
        let mut empty = Vec::new();
        put_buffer(&mut empty);
        let mut buf = get_buffer();
        assert_eq!(
            buf.len(),
            32 * 1024,
            "empty vec must not be served from pool"
        );
        put_buffer(&mut buf);
    }
}
