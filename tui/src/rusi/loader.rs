/// A loaded rusi analysis report, backed by the shared [`LoadedReport`].
///
/// This re-exports [`crate::shared::LoadedReport`] so existing call sites
/// (`rusi::loader::LoadedReport::from_file(…)`) continue to work unchanged.
pub use crate::shared::LoadedReport;
