//! A RustSec advisory, parsed from its markdown source.
//!
//! Each advisory file opens with a fenced `toml` block (the front matter) and
//! then a markdown body whose first `# ` heading is the title. A version is
//! vulnerable unless a `patched` or `unaffected` requirement covers it.

use semver::{Version, VersionReq};
use toml::{Table, Value};

use crate::cache::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    /// The crate the advisory affects.
    pub package: String,
    pub title: String,
    /// Unmaintained, unsound, or notice advisories. These are not vulnerabilities.
    pub informational: bool,
    pub withdrawn: bool,
    /// Requirements that fix the problem, as written in the advisory.
    pub patched_text: Vec<String>,
    patched: Vec<VersionReq>,
    unaffected: Vec<VersionReq>,
}

impl Advisory {
    /// Parses an advisory file. Fails when the front matter, the `[advisory]`
    /// table, or the title heading is missing, or a version requirement is invalid.
    pub fn parse(source: &str) -> Result<Self, Error> {
        let (front_matter, body) =
            split_front_matter(source).ok_or("advisory has no ```toml front matter")?;
        let table: Table = front_matter.parse()?;

        let meta = table
            .get("advisory")
            .and_then(Value::as_table)
            .ok_or("front matter has no [advisory] table")?;
        let text = |key: &str| meta.get(key).and_then(Value::as_str).map(str::to_owned);
        let id = text("id").ok_or("advisory has no id")?;
        let package = text("package").ok_or("advisory has no package")?;

        let title = body
            .lines()
            .find_map(|line| line.strip_prefix("# "))
            .map(|title| title.trim().to_owned())
            .ok_or("advisory body has no `# ` title heading")?;

        let versions = table.get("versions").and_then(Value::as_table);
        let patched_text = requirements(versions, "patched")?;
        let unaffected_text = requirements(versions, "unaffected")?;

        Ok(Self {
            id,
            package,
            title,
            informational: meta.contains_key("informational"),
            withdrawn: meta.contains_key("withdrawn"),
            patched: parse_requirements(&patched_text)?,
            unaffected: parse_requirements(&unaffected_text)?,
            patched_text,
        })
    }

    /// Whether `version` is affected: no patched or unaffected requirement covers it.
    pub fn is_vulnerable(&self, version: &Version) -> bool {
        !self
            .patched
            .iter()
            .chain(&self.unaffected)
            .any(|req| req.matches(version))
    }
}

/// Splits `source` into the front matter inside the leading ```toml fence and the body after it.
fn split_front_matter(source: &str) -> Option<(&str, &str)> {
    let rest = source.strip_prefix("```toml")?.strip_prefix('\n')?;
    let end = rest.find("\n```")?;
    Some((&rest[..end], &rest[end + "\n```".len()..]))
}

/// The string entries of `versions.<key>`. A missing key means no requirements.
fn requirements(versions: Option<&Table>, key: &str) -> Result<Vec<String>, Error> {
    let Some(value) = versions.and_then(|table| table.get(key)) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| format!("versions.{key} must be an array"))?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("versions.{key} entries must be strings").into())
        })
        .collect()
}

fn parse_requirements(texts: &[String]) -> Result<Vec<VersionReq>, Error> {
    texts
        .iter()
        .map(|text| VersionReq::parse(text).map_err(Error::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "```toml\n\
        [advisory]\n\
        id = \"RUSTSEC-2024-0001\"\n\
        package = \"vuln-crate\"\n\
        date = \"2024-01-01\"\n\
        \n\
        [versions]\n\
        patched = [\">= 0.2.0\"]\n\
        ```\n\
        \n\
        # Something is broken\n\
        \n\
        Details.\n";

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn parses_front_matter_and_title() {
        let advisory = Advisory::parse(SOURCE).unwrap();

        assert_eq!(advisory.id, "RUSTSEC-2024-0001");
        assert_eq!(advisory.package, "vuln-crate");
        assert_eq!(advisory.title, "Something is broken");
        assert_eq!(advisory.patched_text, [">= 0.2.0"]);
        assert!(!advisory.informational);
        assert!(!advisory.withdrawn);
    }

    #[test]
    fn versions_below_patched_are_vulnerable() {
        let advisory = Advisory::parse(SOURCE).unwrap();

        assert!(advisory.is_vulnerable(&version("0.1.0")));
        assert!(!advisory.is_vulnerable(&version("0.2.0")));
        assert!(!advisory.is_vulnerable(&version("1.5.0")));
    }

    #[test]
    fn unaffected_ranges_are_not_vulnerable() {
        let source = SOURCE.replace(
            "patched = [\">= 0.2.0\"]",
            "patched = [\">= 0.2.0\"]\nunaffected = [\"< 0.1.0\"]",
        );
        let advisory = Advisory::parse(&source).unwrap();

        assert!(!advisory.is_vulnerable(&version("0.0.9")));
        assert!(advisory.is_vulnerable(&version("0.1.5")));
    }

    #[test]
    fn no_requirements_means_every_version_is_affected() {
        let source = SOURCE.replace("patched = [\">= 0.2.0\"]", "patched = []");
        let advisory = Advisory::parse(&source).unwrap();

        assert!(advisory.is_vulnerable(&version("9.9.9")));
    }

    #[test]
    fn flags_informational_and_withdrawn() {
        let source = SOURCE.replace(
            "date = \"2024-01-01\"",
            "date = \"2024-01-01\"\ninformational = \"unmaintained\"\nwithdrawn = \"2024-02-01\"",
        );
        let advisory = Advisory::parse(&source).unwrap();

        assert!(advisory.informational);
        assert!(advisory.withdrawn);
    }

    #[test]
    fn rejects_malformed_advisories() {
        assert!(Advisory::parse("# no front matter").is_err());
        assert!(Advisory::parse(&SOURCE.replace("id = \"RUSTSEC-2024-0001\"\n", "")).is_err());
        assert!(Advisory::parse(&SOURCE.replace("# Something is broken", "no heading")).is_err());
        assert!(Advisory::parse(&SOURCE.replace(">= 0.2.0", "not a version")).is_err());
    }
}
