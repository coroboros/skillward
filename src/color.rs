//! The void-tinted color layer.
//!
//! Styles are defined once as [`anstyle::Style`] constants. All output goes
//! through `anstream`, which strips ANSI when stdout/stderr is not a terminal
//! or when `NO_COLOR` is set, and forces color on `CLICOLOR_FORCE=1`. [`init`]
//! adds one rule on top: the `--no-color` flag forces plain output globally.

use anstyle::{Ansi256Color, AnsiColor, Color, Effects, Style};

/// Red, bold — error lines and CRITICAL findings.
pub const ERROR: Style = Style::new()
    .fg_color(Some(Color::Ansi(AnsiColor::Red)))
    .effects(Effects::BOLD);

/// Yellow — warnings, tool-error notes, and MEDIUM findings.
pub const WARN: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));

/// Green — PASS verdicts and success.
pub const SUCCESS: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));

/// Dimmed — secondary detail.
pub const DIM: Style = Style::new().effects(Effects::DIMMED);

/// Void violet — the brand accent for headings.
pub const ACCENT: Style = Style::new()
    .fg_color(Some(Color::Ansi256(Ansi256Color(141))))
    .effects(Effects::BOLD);

/// Apply `--no-color`. Without it, `anstream`'s auto-detection (TTY, `NO_COLOR`,
/// `CLICOLOR_FORCE`) decides; with it, color is forced off process-wide.
pub fn init(no_color: bool) {
    if no_color {
        anstream::ColorChoice::Never.write_global();
    }
}

/// Wrap `text` in `style`'s SGR sequences. `anstream` strips them when color is
/// disabled, so callers always paint and let the stream decide.
pub fn paint(style: Style, text: &str) -> String {
    format!("{}{text}{}", style.render(), style.render_reset())
}

/// Remove every ANSI escape sequence from `text`. A report written to a file goes
/// through `std::fs::write`, which bypasses `anstream`'s stream-level stripping, so
/// `paint`'s SGR codes would otherwise land in the file; this keeps a file report
/// plain regardless of format.
pub fn strip(text: &str) -> String {
    anstream::adapter::strip_str(text).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_ansi_that_anstream_would_not_on_a_file_write() {
        init(true);
        let painted = paint(ACCENT, "skillward");
        assert!(
            painted.contains('\u{1b}'),
            "paint emits SGR unconditionally"
        );
        let plain = strip(&painted);
        assert!(!plain.contains('\u{1b}'), "strip removes every escape");
        assert_eq!(plain, "skillward");
    }
}
