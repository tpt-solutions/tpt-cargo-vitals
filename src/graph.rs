//! Dependency graph construction, built on `cargo_metadata`.
//!
//! `cargo metadata` does the resolution. We turn its resolve output into a plain
//! adjacency list so the audit passes can traverse it without re-running Cargo.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, PackageId};

/// Why a graph could not be built.
#[derive(Debug)]
pub enum GraphError {
    /// `cargo metadata` failed or its output could not be parsed.
    Metadata(cargo_metadata::Error),
    /// The metadata has no resolve section, so there are no dependency edges.
    NoResolve,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(err) => write!(f, "cargo metadata failed: {err}"),
            Self::NoResolve => write!(f, "cargo metadata returned no dependency resolution"),
        }
    }
}

impl std::error::Error for GraphError {}

/// An indexed view of a project's resolved dependency graph.
///
/// Nodes are labelled `name version`. Each node's edges point to its dependencies.
pub struct DependencyGraph {
    labels: Vec<String>,
    edges: Vec<Vec<usize>>,
    workspace: Vec<String>,
}

/// Targets whose dependencies are unioned into the graph, in addition to the host.
///
/// `cargo metadata` resolves only one target at a time, so a target-specific
/// dependency (e.g. `cfg(unix)`) is missing unless we ask for that target too.
/// Covers Linux, macOS, and Windows on x86_64 and aarch64.
pub const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

impl DependencyGraph {
    /// Resolves the project whose `Cargo.toml` lives in `project_dir`, unioned
    /// across the host and every target in [`TARGETS`].
    ///
    /// This runs `cargo metadata` once per target, so it is the only step that
    /// spawns Cargo. All features are enabled so optional dependencies appear.
    pub fn load(project_dir: &Path) -> Result<Self, GraphError> {
        let manifest = project_dir.join("Cargo.toml");

        // Host first (no filter), then each fixed target.
        let mut metadatas = vec![metadata_for(&manifest, None)?];
        for target in TARGETS {
            metadatas.push(metadata_for(&manifest, Some(target))?);
        }
        Self::from_metadatas(&metadatas)
    }

    /// Builds the graph from `cargo metadata --format-version 1` output.
    ///
    /// Test-only: the CLI always goes through `load`. The benchmark uses this to
    /// time the parse + build step without the `cargo metadata` subprocess.
    #[cfg(test)]
    pub fn from_json(json: &str) -> Result<Self, GraphError> {
        let metadata = MetadataCommand::parse(json).map_err(GraphError::Metadata)?;
        Self::from_metadatas(std::slice::from_ref(&metadata))
    }

    /// Merges the resolve output of several target-filtered runs into one graph.
    /// Packages are identified by `PackageId`, so a package seen on two targets
    /// appears once, and its edges are the union across targets.
    fn from_metadatas(metadatas: &[Metadata]) -> Result<Self, GraphError> {
        let mut graph = Self {
            labels: Vec::new(),
            edges: Vec::new(),
            workspace: Vec::new(),
        };
        let mut index: HashMap<PackageId, usize> = HashMap::new();

        for metadata in metadatas {
            let resolve = metadata.resolve.as_ref().ok_or(GraphError::NoResolve)?;

            for pkg in &metadata.packages {
                if !index.contains_key(&pkg.id) {
                    index.insert(pkg.id.clone(), graph.labels.len());
                    graph.labels.push(format!("{} {}", pkg.name, pkg.version));
                    graph.edges.push(Vec::new());
                }
            }

            for node in &resolve.nodes {
                let from = index[&node.id];
                for dep in &node.deps {
                    // A package can reach the same dependency under several names
                    // (renames, or normal + dev); keep one edge per pair.
                    let to = index[&dep.pkg];
                    if !graph.edges[from].contains(&to) {
                        graph.edges[from].push(to);
                    }
                }
            }
        }

        // Workspace membership is the same for every target, so read it from the first.
        if let Some(first) = metadatas.first() {
            graph.workspace = first
                .packages
                .iter()
                .filter(|pkg| first.workspace_members.contains(&pkg.id))
                .map(|pkg| pkg.name.to_string())
                .collect();
        }

        Ok(graph)
    }

    /// Number of resolved packages, including the project itself.
    pub fn package_count(&self) -> usize {
        self.labels.len()
    }

    /// Number of dependency edges between packages.
    pub fn link_count(&self) -> usize {
        self.edges.iter().map(Vec::len).sum()
    }

    /// Names of the workspace members, which are the project's own crates.
    pub fn workspace_members(&self) -> Vec<&str> {
        self.workspace.iter().map(String::as_str).collect()
    }

    /// Each dependency cycle, as sorted `name version` labels.
    ///
    /// Cycles can only appear through dev-dependencies, since Cargo rejects
    /// normal-dependency cycles. An empty result means the graph is acyclic.
    pub fn cycles(&self) -> Vec<Vec<String>> {
        let mut cycles: Vec<Vec<String>> = cyclic_components(&self.edges)
            .into_iter()
            .map(|component| {
                let mut labels: Vec<String> = component
                    .into_iter()
                    .map(|ix| self.labels[ix].clone())
                    .collect();
                labels.sort();
                labels
            })
            .collect();
        cycles.sort();
        cycles
    }
}

/// Runs `cargo metadata` for one target, or for the host when `target` is `None`.
fn metadata_for(manifest: &Path, target: Option<&str>) -> Result<Metadata, GraphError> {
    let mut command = MetadataCommand::new();
    command.manifest_path(manifest).features(CargoOpt::AllFeatures);
    if let Some(target) = target {
        command.other_options(["--filter-platform".to_owned(), target.to_owned()]);
    }
    command.exec().map_err(GraphError::Metadata)
}

/// Strongly connected components with more than one member, via Tarjan's algorithm.
///
/// Iterative rather than recursive, so a deep dependency chain cannot overflow
/// the stack.
fn cyclic_components(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    const UNVISITED: usize = usize::MAX;

    let n = adj.len();
    let mut index = vec![UNVISITED; n];
    let mut low = vec![0; n];
    let mut on_stack = vec![false; n];
    let mut stack = Vec::new();
    let mut next_index = 0;
    let mut components = Vec::new();

    for root in 0..n {
        if index[root] != UNVISITED {
            continue;
        }

        // Each frame is (node, position of the next neighbour to explore).
        let mut call = vec![(root, 0usize)];
        index[root] = next_index;
        low[root] = next_index;
        next_index += 1;
        stack.push(root);
        on_stack[root] = true;

        while let Some(frame) = call.last_mut() {
            let v = frame.0;
            if frame.1 < adj[v].len() {
                let w = adj[v][frame.1];
                frame.1 += 1;
                if index[w] == UNVISITED {
                    index[w] = next_index;
                    low[w] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    call.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
                continue;
            }

            // Every neighbour of v is done: pop v and close its component if it is a root.
            call.pop();
            if low[v] == index[v] {
                let mut component = Vec::new();
                loop {
                    let w = stack.pop().expect("v is still on the stack");
                    on_stack[w] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                if component.len() > 1 {
                    components.push(component);
                }
            }
            if let Some(&(parent, _)) = call.last() {
                low[parent] = low[parent].min(low[v]);
            }
        }
    }

    components
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Instant;

    use super::*;

    /// Project root of a path-only fixture: `tests/fixtures/<name>/app`.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
            .join("app")
    }

    #[test]
    fn small_diamond_has_expected_shape() {
        let graph = DependencyGraph::load(&fixture("small")).unwrap();

        // app, a, b, c; edges app->a, app->b, a->c, b->c.
        assert_eq!(graph.package_count(), 4);
        assert_eq!(graph.link_count(), 4);
        assert_eq!(graph.workspace_members(), ["small-app"]);
        assert!(graph.cycles().is_empty());
    }

    #[test]
    fn medium_detects_dev_dependency_cycle() {
        let graph = DependencyGraph::load(&fixture("medium")).unwrap();

        // app, core, net, util, proto, log, x; edges include the dev-only app -> x.
        assert_eq!(graph.package_count(), 7);
        assert_eq!(graph.link_count(), 9);

        let cycles = graph.cycles();
        assert_eq!(cycles.len(), 1, "expected exactly one cycle: {cycles:?}");
        assert_eq!(cycles[0], ["medium-app 0.1.0", "medium-x 0.1.0"]);
    }

    #[test]
    fn large_tree_builds_without_cycles() {
        let graph = DependencyGraph::load(&fixture("large")).unwrap();

        assert_eq!(graph.package_count(), 61);
        assert_eq!(graph.link_count(), 120);
        assert!(graph.cycles().is_empty());
    }

    #[test]
    fn target_specific_dependencies_are_unioned() {
        // On a Windows host, cfg(unix) is false, so only a multi-target union
        // can contain platform-unix. The host-only graph would have 3 packages.
        let graph = DependencyGraph::load(&fixture("platform")).unwrap();

        assert_eq!(graph.package_count(), 4);
        assert_eq!(graph.link_count(), 3);
    }

    #[test]
    fn tarjan_finds_separate_and_nested_cycles() {
        // 0 -> 1 -> 2 -> 0 is one cycle; 3 <-> 4 is another; 5 hangs off both.
        let adj = vec![vec![1], vec![2], vec![0], vec![4], vec![3], vec![0, 3]];
        let mut components: Vec<Vec<usize>> = cyclic_components(&adj)
            .into_iter()
            .map(|mut c| {
                c.sort();
                c
            })
            .collect();
        components.sort();
        assert_eq!(components, [vec![0, 1, 2], vec![3, 4]]);
    }

    #[test]
    fn tarjan_ignores_acyclic_graphs() {
        let adj = vec![vec![1, 2], vec![2], vec![]];
        assert!(cyclic_components(&adj).is_empty());
    }

    /// Parse + graph-build budget from spec §3 (< 100ms). `cargo metadata` itself
    /// is timed separately because it is outside the graph builder's control.
    ///
    /// Run with: `cargo test --release -- --ignored --nocapture parse_budget`
    #[test]
    #[ignore = "timing benchmark, run in release mode"]
    fn parse_budget() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

        let started = Instant::now();
        let output = Command::new(env!("CARGO"))
            .args(["metadata", "--format-version", "1", "--all-features", "--manifest-path"])
            .arg(&manifest)
            .output()
            .expect("cargo metadata runs");
        let cargo_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert!(output.status.success());
        let json = String::from_utf8(output.stdout).unwrap();

        // Best of several runs, to smooth out cold caches and allocator warm-up.
        let mut best = f64::MAX;
        let mut packages = 0;
        for _ in 0..10 {
            let started = Instant::now();
            let graph = DependencyGraph::from_json(&json).unwrap();
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            best = best.min(ms);
            packages = graph.package_count();
        }

        println!(
            "project packages: {packages}\ncargo metadata (subprocess): {cargo_ms:.1} ms\n\
             parse + graph build (best of 10): {best:.2} ms",
        );
        assert!(best < 100.0, "parse+build took {best:.2} ms, budget is 100 ms");
    }
}
