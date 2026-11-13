//! Byte and batch credit: the consumer's backpressure on the producer.
//!
//! A producer may send a batch only against granted credit in *both* dimensions.
//! When the consumer stops reading or granting, the producer waits for a bounded
//! time and then gives up; it never keeps accumulating output in memory.
use crate::error::{WireError, WireErrorKind, WireResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Credit {
    pub bytes: u64,
    pub batches: u64,
}

/// Pure credit arithmetic, shared by the consumer's check and the producer's gate.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreditLedger {
    remaining: Credit,
}

impl CreditLedger {
    pub fn remaining(&self) -> Credit {
        self.remaining
    }

    pub fn grant(&mut self, credit: Credit) -> WireResult<()> {
        let bytes = self.remaining.bytes.checked_add(credit.bytes);
        let batches = self.remaining.batches.checked_add(credit.batches);
        match (bytes, batches) {
            (Some(bytes), Some(batches)) => {
                self.remaining = Credit { bytes, batches };
                Ok(())
            }
            _ => Err(WireError::new(
                WireErrorKind::CreditExceeded,
                "credit grant overflows",
            )),
        }
    }

    /// Spend one batch of `bytes`. Fails without spending anything.
    pub fn take(&mut self, bytes: u64) -> WireResult<()> {
        if self.remaining.batches == 0 || self.remaining.bytes < bytes {
            return Err(WireError::new(
                WireErrorKind::CreditExceeded,
                format!(
                    "a batch of {bytes} bytes exceeds the remaining credit of {} bytes / {} batches",
                    self.remaining.bytes, self.remaining.batches
                ),
            ));
        }
        self.remaining.bytes -= bytes;
        self.remaining.batches -= 1;
        Ok(())
    }
}

/// The producer's side: block, boundedly, until credit exists.
#[derive(Default)]
pub struct CreditGate {
    ledger: Mutex<CreditLedger>,
    changed: Condvar,
}

impl CreditGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&self, credit: Credit) -> WireResult<()> {
        let mut ledger = self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
        ledger.grant(credit)?;
        self.changed.notify_all();
        Ok(())
    }

    pub fn remaining(&self) -> Credit {
        self.ledger
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remaining()
    }

    /// Wake waiters so they notice `cancel`.
    pub fn wake(&self) {
        self.changed.notify_all();
    }

    /// Wait up to `wait` for credit for one batch of `bytes`. Returns `Cancelled`
    /// as soon as `cancel` is set and `DeadlineExceeded` when the consumer did not
    /// grant credit in time; in both cases nothing was spent.
    pub fn reserve(&self, bytes: u64, wait: Duration, cancel: &AtomicBool) -> WireResult<()> {
        let deadline = Instant::now() + wait;
        let mut ledger = self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(WireError::new(
                    WireErrorKind::Cancelled,
                    "cancelled while waiting for credit",
                ));
            }
            if ledger.take(bytes).is_ok() {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(WireError::new(
                    WireErrorKind::DeadlineExceeded,
                    "the consumer granted no credit in time",
                ));
            }
            let slice = (deadline - now).min(Duration::from_millis(10));
            ledger = self
                .changed
                .wait_timeout(ledger, slice)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}
