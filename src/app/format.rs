//! Text and number formatting helpers.

use std::time::Duration;

use super::App;

impl App {
    // ── Status bar ────────────────────────────────────────────────────────────

    /// One-line status string shown in the toolbar.
    pub(in crate::app) fn summary_text(&self) -> String {
        if self.discovering {
            "Scanning drives...".to_string()
        } else if self.verifying {
            format!(
                "Verifying {}/{} checks | Data: {} / {} est. | Passed: {} | Failed: {} | Workers: {}",
                self.done,
                self.total,
                human_bytes(self.processed_bytes),
                human_bytes(self.planned_bytes),
                self.valid,
                self.invalid,
                self.effective_workers
            )
        } else if self.total > 0 {
            format!(
                "Done. {}/{} checks | Data: {} | Passed: {} | Failed: {}",
                self.done,
                self.total,
                human_bytes(self.processed_bytes),
                self.valid,
                self.invalid
            )
        } else if self.drives.is_empty() {
            "No drives discovered.".to_string()
        } else {
            format!(
                "{} drive(s) discovered, {} selected.",
                self.drives.len(),
                self.selected_count()
            )
        }
    }

    // ── Progress bar label ────────────────────────────────────────────────────

    /// Verbose timing/throughput string shown below the progress bar.
    pub(in crate::app) fn progress_text(&self) -> String {
        let total_result_secs = self.results.iter().map(|r| r.elapsed_secs).sum::<f64>();
        let avg_secs = if self.done > 0 {
            total_result_secs / self.done as f64
        } else {
            0.0
        };

        let total_elapsed_secs = self.total_elapsed().map(|d| d.as_secs_f64()).unwrap_or(0.0);

        let live_throughput = if total_elapsed_secs > 0.0 {
            self.processed_bytes as f64 / total_elapsed_secs
        } else {
            0.0
        };

        let completed_throughput = if total_result_secs > 0.0 {
            self.processed_bytes as f64 / total_result_secs
        } else {
            0.0
        };

        if self.verifying {
            format!(
                "{} of {} checks complete | {} of {} est. processed | \
                 Total elapsed {:.1}s | Avg/check {:.2}s | Throughput {}/s",
                self.done,
                self.total,
                human_bytes(self.processed_bytes),
                human_bytes(self.planned_bytes),
                total_elapsed_secs,
                avg_secs,
                human_bytes(live_throughput as u64)
            )
        } else if self.total > 0 {
            format!(
                "{} checks complete | {} processed | \
                 Total elapsed {:.1}s | Avg/check {:.2}s | Throughput {}/s",
                self.done,
                human_bytes(self.processed_bytes),
                total_elapsed_secs,
                avg_secs,
                human_bytes(completed_throughput as u64)
            )
        } else {
            "No verification in progress.".to_string()
        }
    }

    // ── Timing ────────────────────────────────────────────────────────────────

    /// Elapsed time since verification started, or `None` if never started.
    pub(in crate::app) fn total_elapsed(&self) -> Option<Duration> {
        let started = self.verification_started_at?;
        let end = self
            .verification_finished_at
            .unwrap_or_else(std::time::Instant::now);
        Some(end.saturating_duration_since(started))
    }

    // ── Per-drive result counts ───────────────────────────────────────────────

    /// Count passing / failing verification results for one named drive.
    pub(in crate::app) fn drive_result_counts(&self, drive_name: &str) -> (usize, usize) {
        let mut passed = 0usize;
        let mut failed = 0usize;
        for result in self.results.iter().filter(|r| r.drive_name == drive_name) {
            if result.ok {
                passed += 1;
            } else {
                failed += 1;
            }
        }
        (passed, failed)
    }

    // ── Result detail parsing ─────────────────────────────────────────────────

    /// Strip the full detail string down to its most important first line.
    pub(in crate::app) fn main_result_summary(detail: &str) -> &str {
        let first_line = detail.lines().next().unwrap_or(detail);
        if first_line.starts_with("SHA-256 valid") {
            "SHA-256 valid"
        } else if first_line.starts_with("SHA-256 mismatch") {
            "SHA-256 mismatch"
        } else if first_line.starts_with("ISOB3 valid") {
            "ISOB3 valid"
        } else if first_line.starts_with("ISOB3 mismatch") {
            "ISOB3 mismatch"
        } else {
            first_line
        }
    }

    /// Map a raw check-name to its display abbreviation, or `None` to skip it
    /// in the results grid (sub-checks that belong to a parent entry).
    pub(in crate::app) fn main_result_check_name(check_name: &str) -> Option<&str> {
        if check_name.contains("ISOMD5") {
            Some("ISOMD5")
        } else if check_name.contains("ISOB3") {
            Some("ISOB3")
        } else {
            None
        }
    }

    /// Return the most relevant summary line from a multi-line detail string.
    pub(in crate::app) fn main_result_detail(detail: &str) -> &str {
        for line in detail.lines() {
            if line.starts_with("ISOB3 ") || line.starts_with("ISOMD5 ") {
                return Self::main_result_summary(line);
            }
        }
        Self::main_result_summary(detail)
    }
}

// ── Public free function ───────────────────────────────────────────────────────

/// Format a raw byte count as a human-readable string (e.g. `"3.14 MiB"`).
pub fn human_bytes(num_bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = num_bytes as f64;
    for unit in units {
        if value < 1024.0 || unit == "TiB" {
            return format!("{value:.2} {unit}");
        }
        value /= 1024.0;
    }
    format!("{num_bytes} B")
}
