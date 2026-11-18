//! `why <crate>`: the shortest dependency path from a project crate to each
//! compiled version of the named crate.

use std::collections::VecDeque;

use crate::graph::DependencyGraph;

/// One shortest chain of packages from a project crate down to a matching package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// `name version` labels, from the project crate to the matched package.
    pub labels: Vec<String>,
    /// True when no shipped build reaches the matched package.
    pub dev_only: bool,
}

/// Finds the shortest chain to every compiled, non-project package named `name`.
///
/// Names match with `-` and `_` treated alike, as Cargo does. Packages listed by
/// `cargo metadata` but never compiled (inactive optional dependencies) are
/// reported as an error rather than as a path, because nothing requires them.
pub fn explain(graph: &DependencyGraph, name: &str) -> Result<Vec<Chain>, String> {
    let wanted = normalize(name);
    let packages = graph.packages();
    let matches: Vec<usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, pkg)| !pkg.workspace && normalize(&pkg.name) == wanted)
        .map(|(ix, _)| ix)
        .collect();
    if matches.is_empty() {
        return Err(format!("crate `{name}` is not in the dependency tree"));
    }

    let (parent, reached) = shortest_tree(graph);
    let compiled: Vec<usize> = matches.iter().copied().filter(|&ix| reached[ix]).collect();
    if compiled.is_empty() {
        return Err(format!(
            "crate `{name}` is listed by cargo metadata, but no enabled feature compiles it"
        ));
    }

    let mut chains: Vec<Chain> = compiled
        .into_iter()
        .map(|target| {
            let mut path = vec![target];
            let mut current = target;
            while let Some(prev) = parent[current] {
                path.push(prev);
                current = prev;
            }
            path.reverse();
            Chain {
                labels: path.iter().map(|&ix| packages[ix].label()).collect(),
                dev_only: packages[target].dev_only,
            }
        })
        .collect();
    chains.sort_by(|a, b| a.labels.cmp(&b.labels));
    Ok(chains)
}

/// Breadth-first search over compiled edges, started from every project crate at once.
/// Returns each package's predecessor on its shortest chain, and whether it is reached.
fn shortest_tree(graph: &DependencyGraph) -> (Vec<Option<usize>>, Vec<bool>) {
    let count = graph.package_count();
    let mut parent = vec![None; count];
    let mut reached = vec![false; count];
    let mut queue = VecDeque::new();
    for ix in graph.workspace_indices() {
        reached[ix] = true;
        queue.push_back(ix);
    }
    while let Some(ix) = queue.pop_front() {
        for &dep in graph.active_dependencies(ix) {
            if !reached[dep] {
                reached[dep] = true;
                parent[dep] = Some(ix);
                queue.push_back(dep);
            }
        }
    }
    (parent, reached)
}

fn normalize(name: &str) -> String {
    name.replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn load(fixture: &str) -> DependencyGraph {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture)
            .join("app");
        DependencyGraph::load(&dir).unwrap()
    }

    #[test]
    fn shared_crate_reports_one_shortest_chain() {
        // small: app -> a -> c and app -> b -> c. c is one package, so it gets one
        // chain. Both routes are equally short; the one through `a` wins because
        // its dependency list is sorted first.
        let chains = explain(&load("small"), "small-c").unwrap();
        assert_eq!(chains.len(), 1);
        assert_eq!(
            chains[0].labels,
            ["small-app 0.1.0", "small-a 0.1.0", "small-c 0.1.0"]
        );
        assert!(!chains[0].dev_only);
    }

    #[test]
    fn underscores_match_hyphens() {
        assert!(explain(&load("small"), "small_c").is_ok());
    }

    #[test]
    fn dev_only_crate_is_marked() {
        let chains = explain(&load("medium"), "medium-x").unwrap();
        assert_eq!(chains.len(), 1);
        assert!(chains[0].dev_only);
        assert_eq!(chains[0].labels.first().unwrap(), "medium-app 0.1.0");
    }

    #[test]
    fn unknown_crate_is_an_error() {
        let err = explain(&load("small"), "no-such-crate").unwrap_err();
        assert!(err.contains("not in the dependency tree"), "{err}");
    }
}
