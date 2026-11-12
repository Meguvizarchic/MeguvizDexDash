//! Worker-count detection that respects the CPU lease.
//!
//! `std::thread::available_parallelism()` is documented to **overcount** on
//! Windows when the process is limited by an affinity mask or a job object, and
//! on Linux by cgroup quotas when `sched_getaffinity` cannot be queried. That
//! matters here: spawning more workers than the lease allows makes the run
//! *slower* (measured: 24 workers on a 4-CPU lease took 182 s and peaked at
//! 16.4 GB, versus 18.3 s serial) and can exhaust the memory ceiling.
//!
//! The detection is best-effort: any failure falls back to the portable
//! `available_parallelism`, and callers can always set `PipelineConfig::threads`
//! or `MDD_FACTS_THREADS` explicitly.
//!
//! Efficiency-class (P-core vs E-core) detection is deliberately **not** done
//! here. Windows exposes it, but only through a large `unsafe` struct layout,
//! and the scheduler already places latency-sensitive threads with the help of
//! Intel Thread Director. Pinning workers to P-cores is a follow-up that needs
//! its own measurement.

/// Logical CPUs this process may actually use, honouring the affinity mask.
#[cfg(windows)]
pub fn leased_cpu_count() -> Option<usize> {
    use std::os::raw::{c_int, c_void};
    type Handle = *mut c_void;
    // kernel32: both are available on every supported Windows version.
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn GetProcessAffinityMask(
            hprocess: Handle,
            lpmask: *mut usize,
            lpsystemmask: *mut usize,
        ) -> c_int;
    }
    // On Windows the affinity mask covers the process's processor group only;
    // multi-group (>64 CPU) hosts need per-group enumeration, which this
    // single-mask probe cannot see. That case falls back to the portable count.
    unsafe {
        let process = GetCurrentProcess();
        let mut process_mask: usize = 0;
        let mut system_mask: usize = 0;
        if GetProcessAffinityMask(process, &mut process_mask, &mut system_mask) != 0 {
            let count = process_mask.count_ones() as usize;
            if count > 0 {
                return Some(count);
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
pub fn leased_cpu_count() -> Option<usize> {
    unsafe extern "system" {
        fn sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> i32;
    }
    // CPU_SETSIZE is 1024 on the Linux kernels this project targets.
    const CPU_SETSIZE_BYTES: usize = 1024 / 8;
    let mut mask = [0u8; CPU_SETSIZE_BYTES];
    unsafe {
        if sched_getaffinity(0, CPU_SETSIZE_BYTES, mask.as_mut_ptr()) == 0 {
            let count: u32 = mask.iter().map(|byte| byte.count_ones()).sum();
            if count > 0 {
                return Some(count as usize);
            }
        }
        None
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn leased_cpu_count() -> Option<usize> {
    None
}

/// Workers to use when the caller did not choose one.
///
/// Two independent reasons to stay well below the full core count:
/// * the measured optimum on a 4-CPU lease was 3 workers — a fourth made the
///   run 30% slower because per-DEX `Vec`/`String` allocation dominates and
///   extra threads only add heap contention;
/// * each worker keeps a whole DEX fact set resident, so the window is also a
///   memory bound.
pub const DEFAULT_MAX_THREADS: usize = 4;

/// Reserve one logical CPU for the calling thread, which does the delivery and
/// the failure accounting, and for the OS. On a 4-CPU lease this yields the
/// measured optimum of 3 rather than 4.
fn workers_for(available: usize) -> usize {
    available.saturating_sub(1).clamp(1, DEFAULT_MAX_THREADS)
}

/// Effective worker count for a run, honouring an explicit override first.
///
/// Priority: `MDD_FACTS_THREADS` (when it parses to a positive integer) >
/// [`leased_cpu_count`] > `available_parallelism`, capped at
/// [`DEFAULT_MAX_THREADS`].
pub fn default_threads() -> usize {
    if let Some(value) = std::env::var_os("MDD_FACTS_THREADS")
        && let Some(text) = value.to_str()
        && let Ok(requested) = text.trim().parse::<usize>()
        && requested > 0
    {
        return requested;
    }
    let leased = leased_cpu_count().unwrap_or(0);
    let available = if leased > 0 {
        leased
    } else {
        std::thread::available_parallelism().map_or(1, |value| value.get())
    };
    workers_for(available)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MDD_FACTS_THREADS` and the process affinity mask are process-global, so
    /// every test that reads the resolved worker count must serialise against
    /// the ones that mutate them.
    static THREADS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn leased_count_is_at_least_one_and_reports_no_more_than_the_portable_api() {
        let _guard = THREADS_LOCK.lock().unwrap();
        let leased = leased_cpu_count();
        let portable = std::thread::available_parallelism().map_or(1, |value| value.get());
        // An affinity mask can only restrict, never extend, what the portable
        // API reports (that API already honours affinity on Linux).
        if let Some(leased) = leased {
            assert!(leased >= 1, "affinity mask must name at least one CPU");
            assert!(
                leased <= portable,
                "leased {leased} exceeds portable {portable}"
            );
        }
        let resolved = default_threads();
        assert!(resolved >= 1);
        assert!(resolved <= DEFAULT_MAX_THREADS);
        // One logical CPU is reserved for the coordinator, so the resolved count
        // never exceeds the lease minus one.
        let effective = leased.unwrap_or(portable);
        assert!(resolved <= effective.saturating_sub(1).max(1));
    }

    #[cfg(windows)]
    #[test]
    fn affinity_mask_bounds_the_detected_thread_count() {
        let _guard = THREADS_LOCK.lock().unwrap();
        use std::os::raw::{c_int, c_void};
        type Handle = *mut c_void;
        unsafe extern "system" {
            fn GetCurrentProcess() -> Handle;
            fn SetProcessAffinityMask(h: Handle, mask: usize) -> c_int;
            fn GetProcessAffinityMask(h: Handle, pm: *mut usize, sm: *mut usize) -> c_int;
        }
        unsafe {
            let process = GetCurrentProcess();
            let mut original: usize = 0;
            let mut system: usize = 0;
            assert_ne!(
                GetProcessAffinityMask(process, &mut original, &mut system),
                0,
                "failed to read the current affinity mask"
            );
            // Restrict to the first four logical CPUs, then verify the detector
            // follows the lease instead of the machine's full core count.
            let four = original & 0x0000_0000_0000_000F;
            assert_ne!(four, 0, "host exposes no CPU in the low nibble");
            assert_ne!(
                SetProcessAffinityMask(process, four),
                0,
                "failed to set affinity"
            );
            let detected = leased_cpu_count();
            let resolved = default_threads();
            assert_ne!(
                SetProcessAffinityMask(process, original),
                0,
                "failed to restore affinity"
            );
            assert_eq!(
                detected,
                Some(four.count_ones() as usize),
                "detector must follow the affinity mask"
            );
            let leased = four.count_ones() as usize;
            assert_eq!(
                resolved,
                leased.saturating_sub(1).clamp(1, DEFAULT_MAX_THREADS),
                "resolved threads must follow the affinity mask"
            );
        }
    }

    #[test]
    fn env_override_is_honoured_and_invalid_values_fall_back() {
        let _guard = THREADS_LOCK.lock().unwrap();
        // SAFETY: the test process is single-threaded with respect to this
        // variable; `set_var` became unsafe in edition 2024.
        unsafe {
            std::env::set_var("MDD_FACTS_THREADS", "2");
        }
        assert_eq!(default_threads(), 2);
        unsafe {
            std::env::set_var("MDD_FACTS_THREADS", "0");
        }
        assert!(default_threads() >= 1, "zero must be rejected");
        unsafe {
            std::env::set_var("MDD_FACTS_THREADS", "not-a-number");
        }
        assert!(default_threads() >= 1, "garbage must be rejected");
        unsafe {
            std::env::set_var("MDD_FACTS_THREADS", "16");
        }
        assert_eq!(default_threads(), 16, "an explicit override is not capped");
        unsafe {
            std::env::remove_var("MDD_FACTS_THREADS");
        }
    }
}
