//! Bloat analysis: how deep the shipped dependency tree goes, and which crates
//! pull in a large number of transitive dependencies.
//!
//! Only the shipped build is measured (normal and build edges reached from the
//! project's own crates). Dev-only crates do not add to the user's compile or binary.

use std::collections::VecDeque;

use crate::graph::DependencyGraph;

/// Transitive-dependency count at or above which a crate is flagged as heavy.
pub const HEAVY_THRESHOLD: usize = 50;

/// A third-party crate that pulls in at least the threshold's worth of transitive dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeavyCrate {
    pub name: String,
    pub version: String,
    /// Distinct shipped packages reachable from this crate, not counting itself.
    pub transitive: usize,
    /// Fewest shipped edges from a project crate to this crate.
    pub depth: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BloatReport {
    /// Greatest shortest-path distance from a project crate to any shipped crate.
    pub max_depth: usize,
    /// Shipped third-party crates, excluding the project's own crates.
    pub total_crates: usize,
    /// Crates at or above the threshold, most transitive dependencies first.
    pub heavy: Vec<HeavyCrate>,
    pub threshold: usize,
}

impl BloatReport {
    /// `Low` when no crate is heavy, otherwise `High`.
    pub fn level(&self) -> &'static str {
        if self.heavy.is_empty() { "Low" } else { "High" }
    }
}

/// Measures the shipped tree of `graph`, flagging crates with `threshold` or more
/// transitive dependencies.
pub fn analyze(graph: &DependencyGraph, threshold: usize) -> BloatReport {
    let packages = graph.packages();
    let shipped: Vec<bool> = packages
        .iter()
        .map(|pkg| pkg.workspace || (!pkg.dev_only && !pkg.inactive))
        .collect();

    let depth = depths_from_workspace(graph, &shipped);
    let max_depth = depth.iter().flatten().copied().max().unwrap_or(0);

    let mut total_crates = 0;
    let mut heavy = Vec::new();
    for (ix, pkg) in packages.iter().enumerate() {
        if !shipped[ix] || pkg.workspace {
            continue;
        }
        total_crates += 1;

        let transitive = reachable_count(graph, ix, &shipped);
        if transitive >= threshold {
            heavy.push(HeavyCrate {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                transitive,
                depth: depth[ix].unwrap_or(0),
            });
        }
    }
    heavy.sort_by(|a, b| {
        b.transitive
            .cmp(&a.transitive)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });

    BloatReport {
        max_depth,
        total_crates,
        heavy,
        threshold,
    }
}

/// Shortest shipped-edge distance from any project crate, per package. `None` for
/// packages that are not shipped.
fn depths_from_workspace(graph: &DependencyGraph, shipped: &[bool]) -> Vec<Option<usize>> {
    let mut depth = vec![None; shipped.len()];
    let mut queue = VecDeque::new();
    for ix in graph.workspace_indices() {
        depth[ix] = Some(0);
        queue.push_back(ix);
    }
    while let Some(ix) = queue.pop_front() {
        let next_depth = depth[ix].expect("queued nodes have a depth") + 1;
        for &dep in graph.shipped_dependencies(ix) {
            if shipped[dep] && depth[dep].is_none() {
                depth[dep] = Some(next_depth);
                queue.push_back(dep);
            }
        }
    }
    depth
}

/// Number of distinct shipped packages reachable from `start`, not counting `start`.
fn reachable_count(graph: &DependencyGraph, start: usize, shipped: &[bool]) -> usize {
    let mut seen = vec![false; shipped.len()];
    seen[start] = true;
    let mut stack = vec![start];
    let mut count = 0;
    while let Some(ix) = stack.pop() {
        for &dep in graph.shipped_dependencies(ix) {
            if shipped[dep] && !seen[dep] {
                seen[dep] = true;
                count += 1;
                stack.push(dep);
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> DependencyGraph {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
            .join("app");
        DependencyGraph::load(&dir).unwrap()
    }

    #[test]
    fn small_diamond_depth_and_count() {
        // app -> a -> c and app -> b -> c: c is two edges from the project.
        let report = analyze(&fixture("small"), HEAVY_THRESHOLD);
        assert_eq!(report.max_depth, 2);
        assert_eq!(report.total_crates, 3);
        assert!(report.heavy.is_empty());
        assert_eq!(report.level(), "Low");
    }

    #[test]
    fn heavy_threshold_flags_crates_with_enough_transitive_deps() {
        // With a threshold of 1, every crate that pulls anything in is heavy.
        // In the diamond, a and b each reach c; c reaches nothing.
        let report = analyze(&fixture("small"), 1);
        let names: Vec<&str> = report.heavy.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["small-a", "small-b"]);
        assert_eq!(report.heavy[0].transitive, 1);
        assert_eq!(report.heavy[0].depth, 1);
        assert_eq!(report.level(), "High");
    }

    #[test]
    fn dev_only_crates_are_not_measured() {
        // medium's dev-only x must not count toward totals or depth.
        let report = analyze(&fixture("medium"), HEAVY_THRESHOLD);
        assert_eq!(report.total_crates, 5, "app's shipped deps, excluding x");
    }
}
