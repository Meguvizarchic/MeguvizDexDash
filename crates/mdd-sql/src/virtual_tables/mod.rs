//! Owned, forward-only vtable cursors over one immutable provider generation.
use crate::{
    control::SqlControl,
    provider::{SqlBinding, SqlFactCursor, SqlFactProvider, SqlRelation, SqlRow, validate_row},
    values::SqlType,
};
use rusqlite::{
    Connection, Result, ffi,
    vtab::{Context, Filters, IndexInfo, Module, VTab, VTabConnection, VTabCursor},
};
use std::{
    borrow::Cow,
    ffi::{CStr, CString, c_int},
    sync::Arc,
};
#[cfg(test)]
thread_local! {
    pub(crate) static TEST_CONNECTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static TEST_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Values actually handed to SQLite by `xBestIndex`, recorded so tests can
    /// assert the callback's report instead of re-reading `VTB_POLICY`.
    pub(crate) static TEST_BEST_INDEX: std::cell::RefCell<Vec<BestIndexReport>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
/// One constraint usage reported by a real `xBestIndex` call.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BestIndexReport {
    pub omit: bool,
    pub argv_index: c_int,
}
#[cfg(test)]
pub(crate) fn record_best_index(report: BestIndexReport) {
    TEST_BEST_INDEX.with(|slot| slot.borrow_mut().push(report));
}
#[cfg(test)]
pub(crate) fn best_index_reports() -> Vec<BestIndexReport> {
    TEST_BEST_INDEX.with(|slot| slot.borrow().clone())
}
#[cfg(test)]
pub(crate) fn clear_best_index_reports() {
    TEST_BEST_INDEX.with(|slot| slot.borrow_mut().clear());
}

pub(crate) struct Source {
    pub provider: Arc<dyn SqlFactProvider>,
    pub relation: SqlRelation,
    pub binding: SqlBinding,
    pub control: SqlControl,
}
/// Pushdown behaviour shared by the fact vtab and the bridge's reported policy.
/// `omit` and `order_by_consumed` are the two fields this vtab actually reports
/// through `sqlite3_index_info`. `limit_offset_pushdown` and `in_pushdown` are
/// **not wired**: `best_index` never sets `omit`/`argv_index` for the
/// `SQLITE_INDEX_CONSTRAINT_LIMIT`/`OFFSET` constraints SQLite 3.38+ does hand
/// over (this build links SQLite 3.53.2), and it never calls
/// `sqlite3_vtab_in()` to request IN pushdown. Those two fields therefore
/// record an intent SQLite was never told about; the constant is informational
/// for them and enforces nothing. `argv_index` is hard-coded to 0 in
/// `best_index` (no constraint reaches `xFilter`), so `omit` must stay false:
/// claiming a handled constraint without passing it would let SQLite skip its
/// own check and change results. The constant alone cannot stop a future edit
/// that flips `omit` without also changing `filter`; tests additionally record
/// what `best_index` actually reports and compare filtered rows against SQLite.
pub(crate) struct VtabPolicy {
    pub omit: bool,
    pub order_by_consumed: bool,
    pub limit_offset_pushdown: bool,
    pub in_pushdown: bool,
}
pub(crate) const VTB_POLICY: VtabPolicy = VtabPolicy {
    omit: false,
    order_by_consumed: false,
    limit_offset_pushdown: false,
    in_pushdown: false,
};
fn error(error: mdd_types::MddError) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(error))
}
fn check(source: &Source) -> Result<()> {
    if source.provider.binding() != &source.binding {
        return Err(error(
            source
                .control
                .fail(crate::invalid("PROVIDER_GENERATION_CHANGED")),
        ));
    }
    source.control.checkpoint(1, false).map_err(error)
}
fn identifier(value: &str) -> Result<String> {
    if value.is_empty() || value.contains('\0') {
        return Err(error(crate::invalid("INVALID_SQL_IDENTIFIER")));
    }
    Ok(format!("\"{}\"", value.replace('"', "\"\"")))
}

#[repr(C)]
struct FactTable {
    base: ffi::sqlite3_vtab,
    source: Arc<Source>,
}
// SAFETY: SQLite's base is the first repr(C) field. Source owns its provider,
// schema and control; no borrowed fact iterator is stored across callbacks.
unsafe impl<'vtab> VTab<'vtab> for FactTable {
    type Aux = Arc<Source>;
    type Cursor = Cursor;
    fn connect(
        _: &mut VTabConnection,
        aux: Option<&Self::Aux>,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[&[u8]],
    ) -> Result<(Cow<'static, CStr>, Self)> {
        #[cfg(test)]
        TEST_CONNECTS.with(|count| count.set(count.get() + 1));
        let source = Arc::clone(aux.ok_or_else(|| error(crate::invalid("MISSING_FACT_PROVIDER")))?);
        let columns = source
            .relation
            .columns
            .iter()
            .map(|c| {
                Ok(format!(
                    "{} {}",
                    identifier(&c.name)?,
                    match c.data_type {
                        SqlType::Bool | SqlType::I64 => "INTEGER",
                        _ => "BLOB",
                    }
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let schema = CString::new(format!("CREATE TABLE x({})", columns.join(",")))
            .map_err(|_| error(crate::invalid("INVALID_SCHEMA")))?;
        Ok((
            Cow::Owned(schema),
            Self {
                base: ffi::sqlite3_vtab::default(),
                source,
            },
        ))
    }
    fn best_index(&self, info: &mut IndexInfo) -> Result<bool> {
        // Metadata only: opening/building facts here changes optimizer semantics.
        info.set_estimated_cost(
            self.source
                .relation
                .estimated_rows
                .map_or(1000.0, |n| n.0 as f64)
                + 1.0,
        );
        info.set_order_by_consumed(VTB_POLICY.order_by_consumed);
        let omit = VTB_POLICY.omit;
        let argv_index = 0;
        for (_, mut usage) in info.constraints_and_usages() {
            usage.set_omit(omit);
            usage.set_argv_index(argv_index);
            #[cfg(test)]
            record_best_index(BestIndexReport { omit, argv_index });
        }
        Ok(true)
    }
    fn open(&mut self) -> Result<Cursor> {
        #[cfg(test)]
        TEST_OPENS.with(|count| count.set(count.get() + 1));
        let lease = self.source.control.reserve_cursor().map_err(error)?;
        Ok(Cursor {
            base: ffi::sqlite3_vtab_cursor::default(),
            source: Arc::clone(&self.source),
            cursor: None,
            row: None,
            ordinal: 0,
            _lease: lease,
        })
    }
}
#[repr(C)]
struct Cursor {
    base: ffi::sqlite3_vtab_cursor,
    source: Arc<Source>,
    cursor: Option<Box<dyn SqlFactCursor>>,
    row: Option<SqlRow>,
    ordinal: i64,
    _lease: Option<mdd_query::budget::Reservation>,
}
impl Cursor {
    fn advance(&mut self) -> Result<()> {
        check(&self.source)?;
        self.source.control.checkpoint(1, false).map_err(error)?;
        let row = self
            .cursor
            .as_mut()
            .ok_or_else(|| error(crate::invalid("CURSOR_NOT_FILTERED")))?
            .next_row()
            .map_err(|e| error(self.source.control.fail(e)))?;
        if let Some(row) = &row {
            self.source.control.checkpoint(0, true).map_err(error)?;
            validate_row(row, &self.source.relation.columns)
                .map_err(|e| error(self.source.control.fail(e)))?;
            for value in row {
                if value.byte_size() > self.source.control.inner.limits.max_cell_bytes {
                    return Err(error(
                        self.source
                            .control
                            .fail(crate::quota("SQL_PROVIDER_CELL_BYTES")),
                    ));
                }
            }
            self.ordinal = self.ordinal.checked_add(1).ok_or_else(|| {
                error(self.source.control.fail(crate::quota("SQL_ROWID_OVERFLOW")))
            })?;
        }
        self.row = row;
        Ok(())
    }
}
// SAFETY: first repr(C) field is SQLite's cursor base. Every column access is
// bounds checked; cursor's provider Arc outlives all returned temporary cells.
unsafe impl VTabCursor for Cursor {
    fn filter(&mut self, _: c_int, _: Option<&str>, _: &Filters<'_>) -> Result<()> {
        check(&self.source)?;
        self.cursor = Some(
            Arc::clone(&self.source.provider)
                .open_cursor(&self.source.relation.name, self.source.control.clone())
                .map_err(|e| error(self.source.control.fail(e)))?,
        );
        self.ordinal = 0;
        self.advance()
    }
    fn next(&mut self) -> Result<()> {
        self.advance()
    }
    fn eof(&self) -> bool {
        self.row.is_none()
    }
    fn column(&self, context: &mut Context, column: c_int) -> Result<()> {
        check(&self.source)?;
        let value = usize::try_from(column)
            .ok()
            .and_then(|i| self.row.as_ref()?.get(i))
            .ok_or_else(|| {
                error(
                    self.source
                        .control
                        .fail(crate::invalid("CURSOR_COORDINATE")),
                )
            })?;
        context.set_result(
            &value
                .sqlite(self.source.control.inner.limits.max_cell_bytes)
                .map_err(|e| error(self.source.control.fail(e)))?,
        )
    }
    fn rowid(&self) -> Result<i64> {
        Ok(self.ordinal)
    }
}
pub(crate) fn register(db: &Connection, source: Arc<Source>) -> Result<()> {
    const MODULE: Module<FactTable> = Module::eponymous_only_module();
    let name = CString::new(source.relation.name.as_str())
        .map_err(|_| error(crate::invalid("INVALID_RELATION_NAME")))?;
    db.create_module(name.as_c_str(), &MODULE, Some(source))
}
