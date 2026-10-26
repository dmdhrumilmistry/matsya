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

pub fn decompress(raw: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    if raw.starts_with(&[0x1f, 0x8b]) {
        flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut out).map_err(|e| e.to_string())?;
    } else if raw.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        lzma_rs::xz_decompress(&mut &raw[..], &mut out).map_err(|e| e.to_string())?;
    } else if raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        ruzstd::decoding::StreamingDecoder::new(&raw[..])
            .map_err(|e| e.to_string())?
            .read_to_end(&mut out)
            .map_err(|e| e.to_string())?;
    } else if raw.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        lz4_flex::frame::FrameDecoder::new(&raw[..]).read_to_end(&mut out).map_err(|e| e.to_string())?;
    } else {
        return Ok(raw);
    }
    Ok(out)
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
}
