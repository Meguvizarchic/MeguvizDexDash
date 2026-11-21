//! Optional column-major binary batch codec (`mdd.columns-v1`) with strict fail-closed decoding.

use crate::error::{WireResult, malformed};

pub const COLUMNS_V1_MAGIC: &[u8; 8] = b"MDDCOL1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ColumnsV1Cell {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64Bits(u64),
    Bytes(Vec<u8>),
    DexMutf8 { bytes: Vec<u8>, utf16_units: u64 },
    Utf8Text(String),
    Utf16UnitsText(Vec<u16>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnsV1Batch {
    pub sequence: u64,
    pub first_row: u64,
    pub columns: Vec<String>,
    /// Column-major storage: `column_data.len() == columns.len()`, each inner Vec has `row_count` elements.
    pub column_data: Vec<Vec<ColumnsV1Cell>>,
}

impl ColumnsV1Batch {
    pub fn row_count(&self) -> usize {
        self.column_data.first().map_or(0, Vec::len)
    }

    pub fn encode(&self) -> WireResult<Vec<u8>> {
        let rows = self.row_count();
        for col in &self.column_data {
            if col.len() != rows {
                return Err(malformed("ragged columns-v1 batch"));
            }
        }
        if self.column_data.len() != self.columns.len() {
            return Err(malformed("columns-v1 column name/data arity mismatch"));
        }
        let mut out =
            Vec::with_capacity(64 + self.columns.len() * 16 + rows * self.columns.len() * 12);
        out.extend_from_slice(COLUMNS_V1_MAGIC);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.first_row.to_le_bytes());
        out.extend_from_slice(&(self.columns.len() as u32).to_le_bytes());
        out.extend_from_slice(&(rows as u32).to_le_bytes());
        for name in &self.columns {
            let len = u32::try_from(name.len()).map_err(|_| malformed("column name too long"))?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        for col in &self.column_data {
            for cell in col {
                match cell {
                    ColumnsV1Cell::Null => out.push(0),
                    ColumnsV1Cell::Bool(b) => {
                        out.push(1);
                        out.push(u8::from(*b));
                    }
                    ColumnsV1Cell::I64(v) => {
                        out.push(2);
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                    ColumnsV1Cell::U64(v) => {
                        out.push(3);
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                    ColumnsV1Cell::F64Bits(bits) => {
                        out.push(4);
                        out.extend_from_slice(&bits.to_le_bytes());
                    }
                    ColumnsV1Cell::Bytes(bytes) => {
                        out.push(5);
                        let len =
                            u32::try_from(bytes.len()).map_err(|_| malformed("bytes too large"))?;
                        out.extend_from_slice(&len.to_le_bytes());
                        out.extend_from_slice(bytes);
                    }
                    ColumnsV1Cell::DexMutf8 { bytes, utf16_units } => {
                        out.push(6);
                        out.extend_from_slice(&utf16_units.to_le_bytes());
                        let len =
                            u32::try_from(bytes.len()).map_err(|_| malformed("mutf8 too large"))?;
                        out.extend_from_slice(&len.to_le_bytes());
                        out.extend_from_slice(bytes);
                    }
                    ColumnsV1Cell::Utf8Text(s) => {
                        out.push(7);
                        let len =
                            u32::try_from(s.len()).map_err(|_| malformed("utf8 too large"))?;
                        out.extend_from_slice(&len.to_le_bytes());
                        out.extend_from_slice(s.as_bytes());
                    }
                    ColumnsV1Cell::Utf16UnitsText(units) => {
                        out.push(8);
                        let len =
                            u32::try_from(units.len()).map_err(|_| malformed("utf16 too large"))?;
                        out.extend_from_slice(&len.to_le_bytes());
                        for u in units {
                            out.extend_from_slice(&u.to_le_bytes());
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> WireResult<Self> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> WireResult<&'a [u8]> {
            if cur.len() < n {
                return Err(malformed("truncated columns-v1 frame"));
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cursor = bytes;
        let magic = take(&mut cursor, 8)?;
        if magic != COLUMNS_V1_MAGIC {
            return Err(malformed("invalid columns-v1 magic"));
        }
        let sequence = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().unwrap());
        let first_row = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().unwrap());
        let col_count = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().unwrap()) as usize;
        let row_count = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().unwrap()) as usize;
        if col_count > 10_000 || row_count > 10_000_000 {
            return Err(malformed("columns-v1 dimensions exceed sanity bound"));
        }
        let mut columns = Vec::with_capacity(col_count);
        for _ in 0..col_count {
            let len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().unwrap()) as usize;
            let raw = take(&mut cursor, len)?;
            let name = std::str::from_utf8(raw)
                .map_err(|_| malformed("non-utf8 columns-v1 column name"))?
                .to_owned();
            columns.push(name);
        }
        let mut column_data = Vec::with_capacity(col_count);
        for _ in 0..col_count {
            let mut col = Vec::with_capacity(row_count);
            for _ in 0..row_count {
                let tag = take(&mut cursor, 1)?[0];
                let cell = match tag {
                    0 => ColumnsV1Cell::Null,
                    1 => {
                        let v = take(&mut cursor, 1)?[0];
                        match v {
                            0 => ColumnsV1Cell::Bool(false),
                            1 => ColumnsV1Cell::Bool(true),
                            _ => return Err(malformed("invalid columns-v1 bool")),
                        }
                    }
                    2 => ColumnsV1Cell::I64(i64::from_le_bytes(
                        take(&mut cursor, 8)?.try_into().unwrap(),
                    )),
                    3 => ColumnsV1Cell::U64(u64::from_le_bytes(
                        take(&mut cursor, 8)?.try_into().unwrap(),
                    )),
                    4 => ColumnsV1Cell::F64Bits(u64::from_le_bytes(
                        take(&mut cursor, 8)?.try_into().unwrap(),
                    )),
                    5 => {
                        let len =
                            u32::from_le_bytes(take(&mut cursor, 4)?.try_into().unwrap()) as usize;
                        ColumnsV1Cell::Bytes(take(&mut cursor, len)?.to_vec())
                    }
                    6 => {
                        let utf16_units =
                            u64::from_le_bytes(take(&mut cursor, 8)?.try_into().unwrap());
                        let len =
                            u32::from_le_bytes(take(&mut cursor, 4)?.try_into().unwrap()) as usize;
                        ColumnsV1Cell::DexMutf8 {
                            bytes: take(&mut cursor, len)?.to_vec(),
                            utf16_units,
                        }
                    }
                    7 => {
                        let len =
                            u32::from_le_bytes(take(&mut cursor, 4)?.try_into().unwrap()) as usize;
                        let s = std::str::from_utf8(take(&mut cursor, len)?)
                            .map_err(|_| malformed("non-utf8 columns-v1 text"))?
                            .to_owned();
                        ColumnsV1Cell::Utf8Text(s)
                    }
                    8 => {
                        let len =
                            u32::from_le_bytes(take(&mut cursor, 4)?.try_into().unwrap()) as usize;
                        let byte_len = len
                            .checked_mul(2)
                            .ok_or_else(|| malformed("columns-v1 utf16 overflow"))?;
                        let raw = take(&mut cursor, byte_len)?;
                        let units = raw
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .copied()
                            .map(u16::from_le_bytes)
                            .collect();
                        ColumnsV1Cell::Utf16UnitsText(units)
                    }
                    _ => return Err(malformed("unknown columns-v1 cell tag")),
                };
                col.push(cell);
            }
            column_data.push(col);
        }
        if !cursor.is_empty() {
            return Err(malformed("trailing bytes in columns-v1 frame"));
        }
        Ok(Self {
            sequence,
            first_row,
            columns,
            column_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_malformed_rejection() {
        let batch = ColumnsV1Batch {
            sequence: 7,
            first_row: 900,
            columns: vec!["a".to_owned(), "b".to_owned()],
            column_data: vec![
                vec![
                    ColumnsV1Cell::Null,
                    ColumnsV1Cell::Bool(true),
                    ColumnsV1Cell::U64(u64::MAX),
                ],
                vec![
                    ColumnsV1Cell::I64(i64::MIN),
                    ColumnsV1Cell::DexMutf8 {
                        bytes: vec![0xc0, 0x80],
                        utf16_units: 1,
                    },
                    ColumnsV1Cell::Utf16UnitsText(vec![0xd800, 0x41]),
                ],
            ],
        };
        let encoded = batch.encode().unwrap();
        let decoded = ColumnsV1Batch::decode(&encoded).unwrap();
        assert_eq!(decoded, batch);
        assert!(ColumnsV1Batch::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert!(ColumnsV1Batch::decode(&bad_magic).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(ColumnsV1Batch::decode(&trailing).is_err());
    }
}
