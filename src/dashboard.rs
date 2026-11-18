//! Terminal presentation for `check`: status icons, color, and tables.
//!
//! Output degrades to plain text when stdout is not a terminal or `--ci-mode` is
//! set: no emoji, no color, and `[ok]` / `[warn]` / `[fail]` in place of icons.
//! Setting `NO_COLOR` turns off color but keeps the emoji.

use std::io::{IsTerminal, stdout};

use comfy_table::Table;
use owo_colors::OwoColorize;

/// How bad a section of the dashboard is. Ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

/// Which decorations to use when rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    pub color: bool,
    pub emoji: bool,
}

impl Style {
    /// Decorated output only for an interactive terminal outside CI mode.
    pub fn detect(ci_mode: bool) -> Self {
        let interactive = !ci_mode && stdout().is_terminal();
        Self {
            color: interactive && std::env::var_os("NO_COLOR").is_none(),
            emoji: interactive,
        }
    }

    /// Plain text: no emoji and no color. Used by tests.
    #[cfg(test)]
    pub fn plain() -> Self {
        Self {
            color: false,
            emoji: false,
        }
    }

    /// The icon for a status, as an emoji or as a bracketed word.
    pub fn icon(self, status: Status) -> &'static str {
        match (self.emoji, status) {
            (true, Status::Pass) => "✅",
            (true, Status::Warn) => "⚠️ ",
            (true, Status::Fail) => "❌",
            (false, Status::Pass) => "[ok]",
            (false, Status::Warn) => "[warn]",
            (false, Status::Fail) => "[fail]",
        }
    }

    /// `text` colored by status, when color is enabled.
    pub fn paint(self, text: &str, status: Status) -> String {
        if !self.color {
            return text.to_owned();
        }
        match status {
            Status::Pass => text.green().to_string(),
            Status::Warn => text.yellow().to_string(),
            Status::Fail => text.red().bold().to_string(),
        }
    }

    /// `text` in bold, when color is enabled.
    pub fn bold(self, text: &str) -> String {
        if self.color {
            text.bold().to_string()
        } else {
            text.to_owned()
        }
    }

    /// One line of the status tree: `prefix` (tree branch), an icon, a label, and detail.
    pub fn line(self, prefix: &str, status: Status, label: &str, detail: &str) -> String {
        let text = format!("{label}: {detail}");
        format!(
            "{prefix} {} {}",
            self.icon(status),
            self.paint(&text, status)
        )
    }
}

/// A plain-text table with a header row. Not colored, so it reads the same everywhere.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut table = Table::new();
    table.set_header(headers.to_vec());
    for row in rows {
        table.add_row(row.clone());
    }
    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_style_has_no_emoji_or_color() {
        let style = Style::plain();
        assert_eq!(style.icon(Status::Fail), "[fail]");
        assert_eq!(style.paint("x", Status::Fail), "x");
        assert_eq!(
            style.line("└─", Status::Pass, "Bloat", "Low"),
            "└─ [ok] Bloat: Low"
        );
    }

    #[test]
    fn worst_status_is_the_greatest() {
        let worst = [Status::Pass, Status::Fail, Status::Warn]
            .into_iter()
            .max()
            .unwrap();
        assert_eq!(worst, Status::Fail);
    }

    #[test]
    fn colored_line_wraps_text_in_ansi() {
        let style = Style {
            color: true,
            emoji: true,
        };
        let line = style.line("├─", Status::Pass, "Security", "0 vulnerabilities");
        assert!(line.contains('\u{1b}'), "{line:?}");
        assert!(line.contains("Security: 0 vulnerabilities"));
    }
}
