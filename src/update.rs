//! Fetches the RustSec advisory database into the local cache.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::cache::{AdvisoryCache, Error};

/// Snapshot of RustSec's advisory-db `main` branch, as a gzipped tarball.
pub const ADVISORY_DB_URL: &str =
    "https://github.com/rustsec/advisory-db/archive/refs/heads/main.tar.gz";

/// Downloads the advisory database from `url` and replaces the cache's contents.
/// Returns the number of advisories stored.
///
/// The download runs through the system `curl`, which uses the OS trust store.
/// No HTTP or TLS crate is linked, so the dependency tree stays pure MIT.
pub fn fetch(cache: &mut AdvisoryCache, url: &str, now: i64) -> Result<usize, Error> {
    let mut child = Command::new("curl")
        .args(["--fail", "--location", "--silent", "--show-error", url])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| format!("could not run curl ({err}); install curl to run `update`"))?;

    let stdout = child.stdout.take().expect("stdout was piped");
    // Reading to the end (or failing) drops the pipe, so curl cannot block on a full buffer.
    let imported = import(cache, stdout, now);
    let status = child.wait()?;

    if !status.success() {
        return Err(format!("curl could not download {url} ({status})").into());
    }
    imported
}

/// Stores the advisories from a gzipped tarball of the advisory-db repository.
///
/// Streams the archive, so nothing is written to disk except the cache. Only
/// `crates/<package>/RUSTSEC-*.md` entries are kept; everything else is skipped.
pub fn import(cache: &mut AdvisoryCache, reader: impl Read, now: i64) -> Result<usize, Error> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(reader));

    let mut advisories = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let Some(package) = advisory_package(&path) else {
            continue;
        };
        let mut raw = String::new();
        entry.read_to_string(&mut raw)?;
        advisories.push((package, raw));
    }

    cache.replace_all(&advisories, now)
}

/// The crate an advisory file belongs to, for paths shaped like
/// `<repo>/crates/<package>/RUSTSEC-YYYY-NNNN.md`.
fn advisory_package(path: &Path) -> Option<String> {
    let parts: Vec<&str> = path.iter().filter_map(|part| part.to_str()).collect();
    match parts.as_slice() {
        [_, "crates", package, file] if file.starts_with("RUSTSEC-") && file.ends_with(".md") => {
            Some((*package).to_owned())
        }
        _ => None,
    }
}

/// Builds an in-memory `.tar.gz` from `(path, contents)` pairs, for tests.
#[cfg(test)]
pub fn test_archive(files: &[(&str, &str)]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, body) in files {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, body.as_bytes()).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_package_accepts_only_crate_advisories() {
        let ok = |p: &str| advisory_package(Path::new(p));
        assert_eq!(
            ok("advisory-db-main/crates/serde/RUSTSEC-2024-0001.md").as_deref(),
            Some("serde")
        );
        assert_eq!(ok("advisory-db-main/crates/serde/Cargo.toml"), None);
        assert_eq!(
            ok("advisory-db-main/collections/rust/RUSTSEC-2024-0002.md"),
            None
        );
        assert_eq!(ok("advisory-db-main/README.md"), None);
    }

    #[test]
    fn import_stores_only_crate_advisories() {
        let archive = test_archive(&[
            (
                "advisory-db-main/crates/vuln-crate/RUSTSEC-2024-0001.md",
                "advisory body",
            ),
            (
                "advisory-db-main/crates/vuln-crate/Cargo.toml",
                "not an advisory",
            ),
            ("advisory-db-main/README.md", "readme"),
        ]);
        let mut cache = AdvisoryCache::in_memory().unwrap();

        assert_eq!(import(&mut cache, archive.as_slice(), 42).unwrap(), 1);
        assert_eq!(
            cache.advisories_for(&["vuln-crate"]).unwrap(),
            ["advisory body"]
        );
        assert_eq!(cache.fetched_at().unwrap(), Some(42));
    }
}
