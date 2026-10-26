//! Native readers for the on-disk formats package managers use, so matsya
//! never has to run another program to learn what is installed.

pub mod rpmdb;
pub mod sqlite;

use std::io::Read;
use std::path::Path;

use crate::util::{Error, Result};

/// Read a file and transparently decompress gzip, xz, zstd and lz4 (by
/// magic number, not by extension, because apt keeps indexes either way).
pub fn read_decompressed(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    let raw = std::fs::read(path).map_err(|e| Error(format!("cannot read {}: {e}", path.display())))?;
    decompress(raw).map_err(|e| Error(format!("cannot decompress {}: {e}", path.display())))
}

/// Upper bound for any decompressed package index or database. The largest
/// real ones (Ubuntu's universe Packages list) are around 100 MB; anything
/// beyond this is a corrupt or hostile file, not something to buffer.
pub const MAX_DECOMPRESSED: u64 = 1 << 30;

/// Read at most MAX_DECOMPRESSED bytes, failing instead of exhausting memory
/// on a decompression bomb.
fn read_capped(r: impl Read, limit: u64) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    r.take(limit + 1).read_to_end(&mut out).map_err(|e| e.to_string())?;
    if out.len() as u64 > limit {
        return Err(format!("decompressed data exceeds {limit} bytes"));
    }
    Ok(out)
}

/// A writer that refuses to grow past its limit (for push-style decoders).
struct CappedWriter(Vec<u8>, u64);

impl std::io::Write for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.0.len() as u64 + buf.len() as u64 > self.1 {
            return Err(std::io::Error::other("decompressed data exceeds the size limit"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A reader over decompressed data (gzip, zstd or plain), capped at
/// MAX_DECOMPRESSED, for streaming consumers such as tar archives.
pub fn capped_reader(data: Vec<u8>) -> std::result::Result<Box<dyn Read>, String> {
    let r: Box<dyn Read> = if data.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(std::io::Cursor::new(data)))
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Box::new(ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(data)).map_err(|e| e.to_string())?)
    } else {
        Box::new(std::io::Cursor::new(data))
    };
    Ok(Box::new(r.take(MAX_DECOMPRESSED)))
}

pub fn decompress(raw: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    decompress_limited(raw, MAX_DECOMPRESSED)
}

fn decompress_limited(raw: Vec<u8>, limit: u64) -> std::result::Result<Vec<u8>, String> {
    if raw.starts_with(&[0x1f, 0x8b]) {
        read_capped(flate2::read::MultiGzDecoder::new(&raw[..]), limit)
    } else if raw.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        let mut out = CappedWriter(Vec::new(), limit);
        lzma_rs::xz_decompress(&mut &raw[..], &mut out).map_err(|e| e.to_string())?;
        Ok(out.0)
    } else if raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        read_capped(ruzstd::decoding::StreamingDecoder::new(&raw[..]).map_err(|e| e.to_string())?, limit)
    } else if raw.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        read_capped(lz4_flex::frame::FrameDecoder::new(&raw[..]), limit)
    } else if raw.len() as u64 > limit {
        Err(format!("data exceeds {limit} bytes"))
    } else {
        Ok(raw)
    }
}

pub fn read_text_decompressed(path: impl AsRef<Path>) -> Result<String> {
    Ok(String::from_utf8_lossy(&read_decompressed(path)?).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn formats() {
        let text = b"Package: x\nVersion: 1\n\n".to_vec();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&text).unwrap();
        assert_eq!(decompress(gz.finish().unwrap()).unwrap(), text);
        let mut lz = lz4_flex::frame::FrameEncoder::new(Vec::new());
        lz.write_all(&text).unwrap();
        assert_eq!(decompress(lz.finish().unwrap()).unwrap(), text);
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut &text[..], &mut xz).unwrap();
        assert_eq!(decompress(xz).unwrap(), text);
        assert_eq!(decompress(text.clone()).unwrap(), text);
    }

    /// A small input that expands past the limit is rejected for every
    /// format instead of being buffered (decompression bombs).
    #[test]
    fn decompression_bombs_are_rejected() {
        let big = vec![0u8; 1 << 20];
        let limit = 64 * 1024;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(&big).unwrap();
        let gz = gz.finish().unwrap();
        let mut lz = lz4_flex::frame::FrameEncoder::new(Vec::new());
        lz.write_all(&big).unwrap();
        let lz = lz.finish().unwrap();
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut &big[..], &mut xz).unwrap();
        for (name, data) in [("gzip", gz), ("lz4", lz), ("xz", xz), ("plain", big.clone())] {
            let err = decompress_limited(data.clone(), limit).unwrap_err();
            assert!(err.contains("exceeds") || err.contains("limit"), "{name}: {err}");
            assert_eq!(decompress_limited(data, 2 << 20).unwrap().len(), big.len(), "{name}");
        }
    }
}
