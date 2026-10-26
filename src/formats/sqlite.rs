//! A small read-only SQLite reader: enough to scan rowid tables such as
//! rpm's `Packages` and dnf's history tables without linking SQLite or
//! running the `sqlite3` binary.
//!
//! Supported: table b-trees (interior and leaf pages), overflow chains,
//! record decoding, and the write-ahead log (committed frames in `-wal`
//! override pages of the main file, as the rpm and dnf databases are
//! usually left in WAL mode). Index b-trees, WITHOUT ROWID tables and
//! writing are out of scope.

use std::collections::HashMap;
use std::path::Path;

use crate::bail;
use crate::util::{Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Val {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_blob(&self) -> Option<&[u8]> {
        match self {
            Val::Blob(b) => Some(b),
            Val::Text(s) => Some(s.as_bytes()),
            _ => None,
        }
    }
}

/// One table row: rowid plus columns by name.
#[derive(Debug, Clone)]
pub struct Row {
    pub rowid: i64,
    pub cols: HashMap<String, Val>,
}

impl Row {
    pub fn get(&self, c: &str) -> &Val {
        self.cols.get(c).unwrap_or(&Val::Null)
    }
    pub fn str(&self, c: &str) -> &str {
        self.get(c).as_str().unwrap_or("")
    }
    pub fn int(&self, c: &str) -> i64 {
        self.get(c).as_i64().unwrap_or(0)
    }
}

pub struct Db {
    data: Vec<u8>,
    page_size: usize,
    usable: usize,
    /// Committed WAL pages that supersede the main file.
    wal: HashMap<u32, Vec<u8>>,
}

fn be16(b: &[u8], o: usize) -> usize {
    u16::from_be_bytes([b[o], b[o + 1]]) as usize
}
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn varint(b: &[u8], mut o: usize) -> Result<(i64, usize)> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let Some(&byte) = b.get(o) else { bail!("sqlite: truncated varint") };
        o += 1;
        if i == 8 {
            v = (v << 8) | byte as u64;
            return Ok((v as i64, o));
        }
        v = (v << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            return Ok((v as i64, o));
        }
    }
    unreachable!()
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Db> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|e| Error(format!("cannot read {}: {e}", path.display())))?;
        if data.len() < 100 || &data[..16] != b"SQLite format 3\0" {
            bail!("{} is not an SQLite database", path.display());
        }
        let ps = be16(&data, 16);
        let page_size = if ps == 1 { 65536 } else { ps };
        let usable = page_size - data[20] as usize;
        let mut db = Db { data, page_size, usable, wal: HashMap::new() };
        let wal_path = format!("{}-wal", path.display());
        if let Ok(wal) = std::fs::read(&wal_path) {
            db.wal = read_wal(&wal, page_size);
        }
        Ok(db)
    }

    fn page(&self, pgno: u32) -> Result<&[u8]> {
        if let Some(p) = self.wal.get(&pgno) {
            return Ok(p);
        }
        let start = (pgno as usize - 1) * self.page_size;
        match self.data.get(start..start + self.page_size) {
            Some(p) => Ok(p),
            None => bail!("sqlite: page {pgno} out of range"),
        }
    }

    /// Payload bytes of a cell, following overflow pages.
    fn payload(&self, page: &[u8], at: usize, total: usize) -> Result<Vec<u8>> {
        let u = self.usable;
        let x = u - 35;
        let local = if total <= x {
            total
        } else {
            let m = ((u - 12) * 32 / 255) - 23;
            let k = m + ((total - m) % (u - 4));
            if k <= x {
                k
            } else {
                m
            }
        };
        let Some(first) = page.get(at..at + local) else { bail!("sqlite: cell overruns page") };
        let mut out = first.to_vec();
        if local < total {
            let mut next = be32(page, at + local);
            while out.len() < total && next != 0 {
                let p = self.page(next)?;
                let take = (total - out.len()).min(u - 4);
                out.extend_from_slice(&p[4..4 + take]);
                next = be32(p, 0);
            }
        }
        if out.len() != total {
            bail!("sqlite: broken overflow chain");
        }
        Ok(out)
    }

    /// All (rowid, record) pairs of a table b-tree rooted at `root`.
    fn walk(&self, root: u32, out: &mut Vec<(i64, Vec<u8>)>, depth: usize) -> Result<()> {
        if depth > 64 {
            bail!("sqlite: b-tree too deep (corrupt?)");
        }
        let page = self.page(root)?;
        let hdr = if root == 1 { 100 } else { 0 };
        let kind = page[hdr];
        let ncells = be16(page, hdr + 3);
        let ptrs = hdr + if kind == 0x05 { 12 } else { 8 };
        match kind {
            0x05 => {
                for i in 0..ncells {
                    let off = be16(page, ptrs + 2 * i);
                    self.walk(be32(page, off), out, depth + 1)?;
                }
                self.walk(be32(page, hdr + 8), out, depth + 1)?;
            }
            0x0d => {
                for i in 0..ncells {
                    let off = be16(page, ptrs + 2 * i);
                    let (len, o) = varint(page, off)?;
                    let (rowid, o) = varint(page, o)?;
                    out.push((rowid, self.payload(page, o, len as usize)?));
                }
            }
            other => bail!("sqlite: unexpected page type {other:#x} in table b-tree"),
        }
        Ok(())
    }

    fn rows_at(&self, root: u32) -> Result<Vec<(i64, Vec<Val>)>> {
        let mut raw = Vec::new();
        self.walk(root, &mut raw, 0)?;
        raw.into_iter().map(|(id, rec)| Ok((id, decode_record(&rec)?))).collect()
    }

    /// Rows of a table, with columns named from its CREATE TABLE statement.
    /// An INTEGER PRIMARY KEY column (stored as NULL) takes the rowid.
    pub fn table(&self, name: &str) -> Result<Vec<Row>> {
        let master = self.rows_at(1)?;
        let entry = master.iter().find(|(_, r)| {
            r.first().and_then(Val::as_str) == Some("table")
                && r.get(1).and_then(Val::as_str).is_some_and(|n| n.eq_ignore_ascii_case(name))
        });
        let Some((_, r)) = entry else { bail!("sqlite: no table {name}") };
        let root = r.get(3).and_then(Val::as_i64).unwrap_or(0) as u32;
        let sql = r.get(4).and_then(Val::as_str).unwrap_or("");
        let cols = column_names(sql);
        let pk = cols.iter().position(|(_, ipk)| *ipk);
        Ok(self
            .rows_at(root)?
            .into_iter()
            .map(|(rowid, vals)| {
                let mut map = HashMap::new();
                for (i, (c, _)) in cols.iter().enumerate() {
                    let v = vals.get(i).cloned().unwrap_or(Val::Null);
                    let v = if Some(i) == pk && v == Val::Null { Val::Int(rowid) } else { v };
                    map.insert(c.clone(), v);
                }
                Row { rowid, cols: map }
            })
            .collect())
    }
}

/// Committed frames of a WAL file. Frames after the last commit, frames
/// from an older WAL generation (salt mismatch) and frames with a broken
/// checksum chain are ignored, exactly like SQLite does on recovery.
fn read_wal(wal: &[u8], page_size: usize) -> HashMap<u32, Vec<u8>> {
    let mut committed = HashMap::new();
    if wal.len() < 32 {
        return committed;
    }
    let magic = be32(wal, 0);
    if magic != 0x377f0682 && magic != 0x377f0683 || be32(wal, 8) as usize != page_size {
        return committed;
    }
    let big = magic & 1 == 1;
    let (salt1, salt2) = (be32(wal, 16), be32(wal, 20));
    let mut s = checksum(&wal[..24], big, (0, 0));
    if s != (be32(wal, 24), be32(wal, 28)) {
        return committed;
    }
    let mut pending: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut o = 32;
    while o + 24 + page_size <= wal.len() {
        let h = &wal[o..o + 24];
        if be32(h, 8) != salt1 || be32(h, 12) != salt2 {
            break;
        }
        s = checksum(&h[..8], big, s);
        s = checksum(&wal[o + 24..o + 24 + page_size], big, s);
        if s != (be32(h, 16), be32(h, 20)) {
            break;
        }
        pending.insert(be32(h, 0), wal[o + 24..o + 24 + page_size].to_vec());
        if be32(h, 4) != 0 {
            committed.extend(pending.drain());
        }
        o += 24 + page_size;
    }
    committed
}

fn checksum(data: &[u8], big: bool, (mut s0, mut s1): (u32, u32)) -> (u32, u32) {
    for w in data.chunks_exact(8) {
        let (a, b) = if big {
            (u32::from_be_bytes(w[0..4].try_into().unwrap()), u32::from_be_bytes(w[4..8].try_into().unwrap()))
        } else {
            (u32::from_le_bytes(w[0..4].try_into().unwrap()), u32::from_le_bytes(w[4..8].try_into().unwrap()))
        };
        s0 = s0.wrapping_add(a).wrapping_add(s1);
        s1 = s1.wrapping_add(b).wrapping_add(s0);
    }
    (s0, s1)
}

fn decode_record(rec: &[u8]) -> Result<Vec<Val>> {
    let (hlen, mut o) = varint(rec, 0)?;
    let mut types = Vec::new();
    while o < hlen as usize {
        let (t, n) = varint(rec, o)?;
        types.push(t);
        o = n;
    }
    let mut d = hlen as usize;
    let mut out = Vec::with_capacity(types.len());
    for t in types {
        let int = |n: usize, d: usize| -> Result<i64> {
            let Some(b) = rec.get(d..d + n) else { bail!("sqlite: truncated record") };
            let mut v: i64 = if b[0] & 0x80 != 0 { -1 } else { 0 };
            for x in b {
                v = (v << 8) | *x as i64;
            }
            Ok(v)
        };
        let (v, n) = match t {
            0 => (Val::Null, 0),
            1 => (Val::Int(int(1, d)?), 1),
            2 => (Val::Int(int(2, d)?), 2),
            3 => (Val::Int(int(3, d)?), 3),
            4 => (Val::Int(int(4, d)?), 4),
            5 => (Val::Int(int(6, d)?), 6),
            6 => (Val::Int(int(8, d)?), 8),
            7 => (Val::Real(f64::from_bits(int(8, d)? as u64)), 8),
            8 => (Val::Int(0), 0),
            9 => (Val::Int(1), 0),
            t if t >= 12 && t % 2 == 0 => {
                let n = ((t - 12) / 2) as usize;
                let Some(b) = rec.get(d..d + n) else { bail!("sqlite: truncated blob") };
                (Val::Blob(b.to_vec()), n)
            }
            t if t >= 13 => {
                let n = ((t - 13) / 2) as usize;
                let Some(b) = rec.get(d..d + n) else { bail!("sqlite: truncated text") };
                (Val::Text(String::from_utf8_lossy(b).into_owned()), n)
            }
            other => bail!("sqlite: reserved serial type {other}"),
        };
        out.push(v);
        d += n;
    }
    Ok(out)
}

/// Column names from a CREATE TABLE statement, flagging an INTEGER
/// PRIMARY KEY (rowid alias).
fn column_names(sql: &str) -> Vec<(String, bool)> {
    // Strip /* */ and -- comments.
    let mut clean = String::new();
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(c) = chars.next() {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else if c == '-' && chars.peek() == Some(&'-') {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
        } else {
            clean.push(c);
        }
    }
    let (Some(start), Some(end)) = (clean.find('('), clean.rfind(')')) else { return vec![] };
    let body = &clean[start + 1..end];
    let mut parts = Vec::new();
    let (mut depth, mut cur) = (0, String::new());
    for c in body.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    parts.push(cur);
    parts
        .iter()
        .filter_map(|p| {
            let p = p.trim();
            let first = p.split_whitespace().next()?;
            let kw = first.to_ascii_uppercase();
            if ["CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK"].contains(&kw.as_str()) {
                return None;
            }
            let name = first.trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == '[' || c == ']').to_string();
            let up = p.to_ascii_uppercase();
            let ipk = up.contains("INTEGER") && up.contains("PRIMARY KEY");
            Some((name, ipk))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x7f], 0).unwrap(), (127, 1));
        assert_eq!(varint(&[0x81, 0x00], 0).unwrap(), (128, 2));
    }

    /// The fixture's rows exist only in the uncheckpointed WAL; without
    /// WAL support the table would look empty.
    #[test]
    fn wal_frames_are_applied() {
        let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dnf-history.sqlite");
        assert!(std::path::Path::new(&format!("{fx}-wal")).exists(), "WAL fixture missing");
        assert_eq!(Db::open(fx).unwrap().table("trans_item").unwrap().len(), 7);
        let dir = std::env::temp_dir().join(format!("matsya-nowal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main_only = dir.join("h.sqlite");
        std::fs::copy(fx, &main_only).unwrap();
        assert_eq!(Db::open(&main_only).unwrap().table("trans_item").unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn schema_columns() {
        let sql = "CREATE TABLE rpm (\n item_id INTEGER UNIQUE NOT NULL,\n name TEXT NOT NULL, /* c */\n epoch INTEGER NOT NULL,\n FOREIGN KEY(item_id) REFERENCES item(id),\n CONSTRAINT u UNIQUE (name, epoch))";
        let c: Vec<String> = column_names(sql).into_iter().map(|x| x.0).collect();
        assert_eq!(c, vec!["item_id", "name", "epoch"]);
        assert_eq!(
            column_names("CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL)")[0],
            ("hnum".into(), true)
        );
    }
}
