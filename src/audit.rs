//! Offline vulnerability audit: matches resolved packages against cached advisories.

use std::collections::HashMap;

use rayon::prelude::*;
use rustsec::Advisory;
use rustsec::semver::Version;

use crate::cache::{AdvisoryCache, Error};
use crate::graph::DependencyGraph;

/// One resolved package version that an advisory says is vulnerable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub advisory_id: String,
    pub title: String,
    pub package: String,
    pub version: String,
    /// Version requirements that fix the problem, as written in the advisory.
    pub patched: Vec<String>,
    /// True for unmaintained, unsound, or notice advisories. These are not
    /// vulnerabilities, so they are reported separately.
    pub informational: bool,
}

/// Returns every (package, advisory) pair in `graph` that the cache marks as
/// vulnerable, sorted by package then advisory ID. Makes no network calls.
pub fn find_vulnerabilities(
    graph: &DependencyGraph,
    cache: &AdvisoryCache,
) -> Result<Vec<Finding>, Error> {
    let mut names: Vec<&str> = graph
        .packages()
        .iter()
        .map(|pkg| pkg.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();

    // Only advisories for crates in the graph are fetched and parsed. Parsing
    // is the CPU-heavy step, so it runs in parallel.
    let advisories: Vec<Advisory> = cache
        .advisories_for(&names)?
        .par_iter()
        .filter_map(|raw| match raw.parse::<Advisory>() {
            Ok(advisory) => Some(advisory),
            Err(err) => {
                eprintln!("warning: skipping malformed advisory: {err}");
                None
            }
        })
        .filter(|advisory| !advisory.withdrawn())
        .collect();

    let mut by_package: HashMap<&str, Vec<&Advisory>> = HashMap::new();
    for advisory in &advisories {
        by_package
            .entry(advisory.metadata.package.as_str())
            .or_default()
            .push(advisory);
    }

    let mut findings: Vec<Finding> = graph
        .packages()
        .par_iter()
        .flat_map_iter(|pkg| {
            let version = Version::parse(&pkg.version);
            by_package
                .get(pkg.name.as_str())
                .into_iter()
                .flatten()
                .filter_map(move |advisory| {
                    let version = version.as_ref().ok()?;
                    advisory.versions.is_vulnerable(version).then(|| Finding {
                        advisory_id: advisory.id().to_string(),
                        title: advisory.title().to_owned(),
                        package: pkg.name.clone(),
                        version: pkg.version.clone(),
                        patched: advisory
                            .versions
                            .patched()
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                        informational: advisory.metadata.informational.is_some(),
                    })
                })
        })
        .collect();

    findings.sort_by(|a, b| {
        a.package
            .cmp(&b.package)
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
    });
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::update::{import, test_archive};

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulnerable/app")
    }

    /// An advisory for `vuln-crate` with the given `patched` requirement.
    fn advisory_archive(patched: &str) -> Vec<u8> {
        let body = format!(
            "```toml\n\
             [advisory]\n\
             id = \"RUSTSEC-2024-0001\"\n\
             package = \"vuln-crate\"\n\
             date = \"2024-01-01\"\n\
             \n\
             [versions]\n\
             patched = [\"{patched}\"]\n\
             ```\n\
             \n\
             # Test advisory for vuln-crate\n\
             \n\
             Synthetic advisory used by the audit tests.\n"
        );
        test_archive(&[(
            "advisory-db-main/crates/vuln-crate/RUSTSEC-2024-0001.md",
            body.as_str(),
        )])
    }

    fn cache_with(patched: &str) -> AdvisoryCache {
        let mut cache = AdvisoryCache::in_memory().unwrap();
        import(&mut cache, advisory_archive(patched).as_slice(), 0).unwrap();
        cache
    }

    #[test]
    fn flags_vulnerable_version_and_not_clean_crate() {
        let graph = DependencyGraph::load(&fixture()).unwrap();
        // The fixture's vuln-crate is 0.1.0, which is below the patched >= 0.2.0.
        let findings = find_vulnerabilities(&graph, &cache_with(">= 0.2.0")).unwrap();

        assert_eq!(
            findings,
            [Finding {
                advisory_id: "RUSTSEC-2024-0001".to_owned(),
                title: "Test advisory for vuln-crate".to_owned(),
                package: "vuln-crate".to_owned(),
                version: "0.1.0".to_owned(),
                patched: vec![">=0.2.0".to_owned()],
                informational: false,
            }]
        );
    }

    #[test]
    fn unmaintained_advisory_is_marked_informational() {
        let body = "```toml\n\
             [advisory]\n\
             id = \"RUSTSEC-2024-0002\"\n\
             package = \"vuln-crate\"\n\
             date = \"2024-01-01\"\n\
             informational = \"unmaintained\"\n\
             \n\
             [versions]\n\
             patched = []\n\
             ```\n\
             \n\
             # Unmaintained vuln-crate\n\
             \n\
             No longer maintained.\n";
        let archive = test_archive(&[(
            "advisory-db-main/crates/vuln-crate/RUSTSEC-2024-0002.md",
            body,
        )]);
        let mut cache = AdvisoryCache::in_memory().unwrap();
        import(&mut cache, archive.as_slice(), 0).unwrap();

        let graph = DependencyGraph::load(&fixture()).unwrap();
        let findings = find_vulnerabilities(&graph, &cache).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].informational);
    }

    #[test]
    fn no_finding_when_installed_version_is_patched() {
        let graph = DependencyGraph::load(&fixture()).unwrap();
        // 0.1.0 satisfies the patched requirement, so it is not vulnerable.
        let findings = find_vulnerabilities(&graph, &cache_with(">= 0.1.0")).unwrap();
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn empty_cache_reports_nothing() {
        let graph = DependencyGraph::load(&fixture()).unwrap();
        let cache = AdvisoryCache::in_memory().unwrap();
        assert!(find_vulnerabilities(&graph, &cache).unwrap().is_empty());
    }
}
