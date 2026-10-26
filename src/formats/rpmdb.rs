//! Native RPM database reading: header blobs from the three backends rpm
//! has used over the years, without running `rpm`.
//!
//! * sqlite (`rpmdb.sqlite`): Fedora 33+, RHEL/Rocky/Alma 9+
//! * ndb (`Packages.db`): openSUSE, SLES 15 SP3+
//! * BerkeleyDB hash (`Packages`): RHEL/CentOS 7-8, Amazon Linux 2

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::sqlite;
use crate::bail;
use crate::util::Result;

pub const NAME: u32 = 1000;
pub const VERSION: u32 = 1001;
pub const RELEASE: u32 = 1002;
pub const EPOCH: u32 = 1003;
pub const VENDOR: u32 = 1011;
pub const LICENSE: u32 = 1014;
pub const ARCH: u32 = 1022;
pub const SOURCERPM: u32 = 1044;
pub const PROVIDENAME: u32 = 1047;
pub const REQUIRENAME: u32 = 1049;
pub const DIRINDEXES: u32 = 1116;
pub const BASENAMES: u32 = 1117;
pub const DIRNAMES: u32 = 1118;
pub const SIGMD5: u32 = 261;
/// PAYLOADDIGEST before RPM 6, PAYLOADSHA256 since; same tag number.
pub const PAYLOADDIGEST: u32 = 5092;

#[derive(Debug, Clone, PartialEq)]
pub enum Tag {
    Ints(Vec<i64>),
    Strings(Vec<String>),
    Bin(Vec<u8>),
}

/// A parsed RPM header: tag -> value.
#[derive(Debug, Default, Clone)]
pub struct Header {
    pub tags: BTreeMap<u32, Tag>,
}

impl Header {
    pub fn string(&self, tag: u32) -> Option<&str> {
        match self.tags.get(&tag)? {
            Tag::Strings(v) => v.first().map(String::as_str),
            _ => None,
        }
    }
    pub fn strings(&self, tag: u32) -> &[String] {
        match self.tags.get(&tag) {
            Some(Tag::Strings(v)) => v,
            _ => &[],
        }
    }
    pub fn int(&self, tag: u32) -> Option<i64> {
        match self.tags.get(&tag)? {
            Tag::Ints(v) => v.first().copied(),
            _ => None,
        }
    }
    pub fn ints(&self, tag: u32) -> &[i64] {
        match self.tags.get(&tag) {
            Some(Tag::Ints(v)) => v,
            _ => &[],
        }
    }
    pub fn hex(&self, tag: u32) -> Option<String> {
        match self.tags.get(&tag)? {
            Tag::Bin(b) => Some(crate::util::hex(b)),
            Tag::Strings(v) => v.first().cloned(),
            _ => None,
        }
    }
    /// Full paths of all files in the package.
    pub fn files(&self) -> Vec<String> {
        let (dirs, idx) = (self.strings(DIRNAMES), self.ints(DIRINDEXES));
        self.strings(BASENAMES)
            .iter()
            .zip(idx)
            .filter_map(|(b, i)| dirs.get(*i as usize).map(|d| format!("{d}{b}")))
            .collect()
    }
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Parse a header blob as stored in the database: il, dl, index, data.
pub fn parse_header(blob: &[u8]) -> Result<Header> {
    let (Some(il), Some(dl)) = (be32(blob, 0), be32(blob, 4)) else { bail!("rpm header: too short") };
    let (il, dl) = (il as usize, dl as usize);
    let data_start = 8 + il * 16;
    if il == 0 || il > 0x10000 || data_start + dl > blob.len() {
        bail!("rpm header: bad index/data size");
    }
    let data = &blob[data_start..data_start + dl];
    let mut h = Header::default();
    for i in 0..il {
        let e = 8 + i * 16;
        let (tag, typ, off, count) = (
            be32(blob, e).unwrap(),
            be32(blob, e + 4).unwrap(),
            be32(blob, e + 8).unwrap() as usize,
            be32(blob, e + 12).unwrap() as usize,
        );
        if (61..=63).contains(&tag) || off > data.len() {
            continue; // region markers and out-of-range entries
        }
        let d = &data[off..];
        let val = match typ {
            2 | 1 => Tag::Ints(d.iter().take(count).map(|b| *b as i64).collect()),
            3 => Tag::Ints(d.chunks_exact(2).take(count).map(|c| u16::from_be_bytes([c[0], c[1]]) as i64).collect()),
            4 => Tag::Ints(
                d.chunks_exact(4).take(count).map(|c| u32::from_be_bytes(c.try_into().unwrap()) as i64).collect(),
            ),
            5 => Tag::Ints(
                d.chunks_exact(8).take(count).map(|c| u64::from_be_bytes(c.try_into().unwrap()) as i64).collect(),
            ),
            6 => Tag::Strings(d.split(|b| *b == 0).take(1).map(|s| String::from_utf8_lossy(s).into_owned()).collect()),
            8 | 9 => Tag::Strings(
                d.split(|b| *b == 0).take(count).map(|s| String::from_utf8_lossy(s).into_owned()).collect(),
            ),
            7 => Tag::Bin(d.get(..count).unwrap_or(d).to_vec()),
            _ => continue,
        };
        h.tags.insert(tag, val);
    }
    Ok(h)
}

/// The main header of an .rpm file (skipping lead and signature header).
pub fn read_rpm_file(path: &Path) -> Result<Header> {
    let b = std::fs::read(path)?;
    if b.len() < 96 + 16 || b[..4] != [0xed, 0xab, 0xee, 0xdb] {
        bail!("{} is not an rpm package", path.display());
    }
    let section = |o: usize| -> Result<(usize, usize)> {
        if b.get(o..o + 3) != Some(&[0x8e, 0xad, 0xe8][..]) {
            bail!("rpm: bad header magic");
        }
        let il = be32(&b, o + 8).unwrap_or(0) as usize;
        let dl = be32(&b, o + 12).unwrap_or(0) as usize;
        Ok((o + 8, 8 + il * 16 + dl))
    };
    let (_, sig_len) = section(96)?;
    let main = (96 + 8 + sig_len).div_ceil(8) * 8; // signature header is padded to 8 bytes
    let (start, len) = section(main)?;
    parse_header(b.get(start..start + len).unwrap_or(&[]))
}

/// Locate the rpm database under a root ("/" normally).
pub fn find(root: &Path) -> Option<PathBuf> {
    ["usr/lib/sysimage/rpm", "var/lib/rpm"]
        .iter()
        .map(|d| root.join(d))
        .find(|d| ["rpmdb.sqlite", "Packages.db", "Packages"].iter().any(|f| d.join(f).is_file()))
}

/// All package headers in the database directory, any backend.
pub fn read_all(dir: &Path) -> Result<Vec<Header>> {
    let blobs = if dir.join("rpmdb.sqlite").is_file() {
        let db = sqlite::Db::open(dir.join("rpmdb.sqlite"))?;
        db.table("Packages")?.into_iter().filter_map(|r| r.get("blob").as_blob().map(<[u8]>::to_vec)).collect()
    } else if dir.join("Packages.db").is_file() {
        ndb_blobs(&std::fs::read(dir.join("Packages.db"))?)?
    } else if dir.join("Packages").is_file() {
        bdb_blobs(&std::fs::read(dir.join("Packages"))?)?
    } else {
        bail!("no rpm database in {}", dir.display());
    };
    let mut out = Vec::new();
    for b in blobs {
        match parse_header(&b) {
            Ok(h) if h.string(NAME).is_some() => out.push(h),
            _ => {} // bookkeeping records (e.g. bdb key 0) are not headers
        }
    }
    Ok(out)
}

fn le32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}

/// rpm's "ndb" backend: a slot table pointing at 16-byte aligned blobs.
fn ndb_blobs(b: &[u8]) -> Result<Vec<Vec<u8>>> {
    const HEADER_MAGIC: u32 = u32::from_le_bytes(*b"RpmP");
    const SLOT_MAGIC: u32 = u32::from_le_bytes(*b"Slot");
    const BLOB_MAGIC: u32 = u32::from_le_bytes(*b"BlbS");
    if le32(b, 0) != HEADER_MAGIC {
        bail!("Packages.db: not an ndb database");
    }
    let slot_pages = le32(b, 12) as usize;
    let nslots = (slot_pages * 4096 / 16).saturating_sub(2);
    let mut out = Vec::new();
    for i in 0..nslots {
        let o = 32 + i * 16;
        if o + 16 > b.len() {
            break;
        }
        if le32(b, o) != SLOT_MAGIC || le32(b, o + 4) == 0 {
            continue;
        }
        let blk = le32(b, o + 8) as usize * 16;
        if le32(b, blk) != BLOB_MAGIC {
            continue;
        }
        let len = le32(b, blk + 12) as usize;
        if let Some(blob) = b.get(blk + 16..blk + 16 + len) {
            out.push(blob.to_vec());
        }
    }
    Ok(out)
}

/// BerkeleyDB hash database (rpm's historical "Packages").
fn bdb_blobs(b: &[u8]) -> Result<Vec<Vec<u8>>> {
    // Generic meta page: magic at 12, page size at 20, last page at 32.
    let (le, magic) = (le32(b, 12), be32(b, 12).unwrap_or(0));
    let little = match (le, magic) {
        (0x061561, _) => true,
        (_, 0x061561) => false,
        _ => bail!("Packages: not a BerkeleyDB hash database"),
    };
    let rd32 = |o: usize| if little { le32(b, o) } else { be32(b, o).unwrap_or(0) };
    let rd16 = |o: usize| {
        let x = b.get(o..o + 2).map(|s| [s[0], s[1]]).unwrap_or([0, 0]);
        (if little { u16::from_le_bytes(x) } else { u16::from_be_bytes(x) }) as usize
    };
    let page_size = rd32(20) as usize;
    if !(512..=65536).contains(&page_size) {
        bail!("Packages: bad page size");
    }
    let last = rd32(32) as usize;
    let mut out = Vec::new();
    for pg in 1..=last {
        let p = pg * page_size;
        if p + page_size > b.len() {
            break;
        }
        // Page header: entries at +20, type at +25. 2 = unsorted hash, 13 = hash.
        let kind = b[p + 25];
        if kind != 2 && kind != 13 {
            continue;
        }
        let entries = rd16(p + 20);
        // Index entries come in key/data pairs; values are the odd ones.
        for i in (1..entries).step_by(2) {
            let off = rd16(p + 26 + 2 * i);
            let item = p + off;
            match b.get(item) {
                // H_OFFPAGE: type, 3 unused, pgno, total length.
                Some(3) => {
                    let (mut next, total) = (rd32(item + 4) as usize, rd32(item + 8) as usize);
                    let mut data = Vec::with_capacity(total);
                    let mut guard = 0;
                    while next != 0 && data.len() < total && guard < 1_000_000 {
                        let op = next * page_size;
                        if op + page_size > b.len() {
                            break;
                        }
                        // Overflow page: hf_offset (+22) holds the bytes used.
                        let used = rd16(op + 22);
                        data.extend_from_slice(&b[op + 26..op + 26 + used.min(page_size - 26)]);
                        next = rd32(op + 16) as usize;
                        guard += 1;
                    }
                    data.truncate(total);
                    out.push(data);
                }
                // H_KEYDATA: the value runs to the start of the previous item.
                Some(1) => {
                    let end = if i == 0 { page_size } else { rd16(p + 26 + 2 * (i - 1)) };
                    if end > off + 1 {
                        out.push(b[item + 1..p + end].to_vec());
                    }
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dumps every rpmdb under $MATSYA_RPMDB_DIRS (colon separated) for
    /// comparison with `rpm --dbpath`; run manually during development.
    #[test]
    #[ignore]
    fn dump_for_comparison() {
        for dir in std::env::var("MATSYA_RPMDB_DIRS").unwrap_or_default().split(':').filter(|s| !s.is_empty()) {
            let mut lines: Vec<String> = read_all(Path::new(dir))
                .unwrap()
                .iter()
                .filter(|h| h.string(NAME) != Some("gpg-pubkey"))
                .map(|h| {
                    format!(
                        "{}-{}:{}-{}.{} {} {} {}",
                        h.string(NAME).unwrap_or(""),
                        h.int(EPOCH).unwrap_or(0),
                        h.string(VERSION).unwrap_or(""),
                        h.string(RELEASE).unwrap_or(""),
                        h.string(ARCH).unwrap_or(""),
                        h.hex(PAYLOADDIGEST).unwrap_or_else(|| "(none)".into()),
                        h.hex(SIGMD5).unwrap_or_else(|| "(none)".into()),
                        h.string(LICENSE).unwrap_or("")
                    )
                })
                .collect();
            lines.sort();
            std::fs::write(format!("{dir}.matsya.txt"), lines.join("\n") + "\n").unwrap();
        }
    }
}
