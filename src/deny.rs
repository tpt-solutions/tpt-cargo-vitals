//! Reads the advisories a project accepts in its `deny.toml`.
//!
//! `cargo deny` ignores each advisory listed under `[advisories] ignore`. Vitals
//! reads the same list, so its vulnerability count agrees with cargo-deny. An
//! accepted advisory is reported separately and does not fail `--ci-mode`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Advisory IDs the project accepts, each with the reason it gave (empty when none).
pub type Accepted = BTreeMap<String, String>;

/// Reads `[advisories] ignore` from the `deny.toml` at `path`. A missing file means
/// nothing is accepted. A file that does not parse is an error, so a broken policy
/// cannot silently accept everything.
pub fn accepted_advisories(path: &Path) -> Result<Accepted, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Accepted::new());
        }
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    parse(&text).map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

/// Parses the text of a `deny.toml`. Entries may be a bare ID string or a table with
/// an `id` and an optional `reason`, as cargo-deny accepts both.
pub fn parse(text: &str) -> Result<Accepted, String> {
    let value: toml::Table = text
        .parse()
        .map_err(|error: toml::de::Error| error.to_string())?;
    let Some(advisories) = value.get("advisories") else {
        return Ok(Accepted::new());
    };
    let Some(ignore) = advisories.get("ignore") else {
        return Ok(Accepted::new());
    };
    let entries = ignore
        .as_array()
        .ok_or("[advisories] ignore must be an array")?;

    let mut accepted = Accepted::new();
    for entry in entries {
        let (id, reason) = match entry {
            toml::Value::String(id) => (id.as_str(), ""),
            toml::Value::Table(table) => {
                let id = table
                    .get("id")
                    .and_then(toml::Value::as_str)
                    .ok_or("an [advisories] ignore entry has no id")?;
                let reason = table
                    .get("reason")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("");
                (id, reason)
            }
            _ => return Err("an [advisories] ignore entry must be a string or a table".into()),
        };
        accepted.insert(id.to_owned(), reason.to_owned());
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_table_and_bare_string_entries() {
        let text = r#"
            [advisories]
            ignore = [
                { id = "RUSTSEC-2023-0071", reason = "rsa verification only" },
                "RUSTSEC-2024-0436",
            ]
        "#;
        let accepted = parse(text).unwrap();
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted["RUSTSEC-2023-0071"], "rsa verification only");
        assert_eq!(accepted["RUSTSEC-2024-0436"], "");
    }

    #[test]
    fn no_advisories_section_accepts_nothing() {
        assert!(parse("[licenses]\nallow = [\"MIT\"]\n").unwrap().is_empty());
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn malformed_entries_are_errors_not_silent_acceptance() {
        assert!(parse("[advisories]\nignore = [ { reason = \"no id\" } ]\n").is_err());
        assert!(parse("[advisories]\nignore = 3\n").is_err());
        assert!(parse("[advisories\nignore = []\n").is_err());
    }

    #[test]
    fn missing_file_accepts_nothing() {
        let path = Path::new("definitely/not/here/deny.toml");
        assert!(accepted_advisories(path).unwrap().is_empty());
    }
}
