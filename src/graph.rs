//! Dependency graph construction, built on `cargo metadata`.
//!
//! `cargo metadata` does the resolution. We parse its JSON output and turn the
//! resolve section into a plain adjacency list so the audit passes can traverse
//! it without re-running Cargo.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::process::Command;

use json::JsonValue;

/// Why a graph could not be built.
#[derive(Debug)]
pub enum GraphError {
    /// `cargo metadata` failed, or its output was not the JSON we expected.
    Metadata(String),
    /// The metadata has no resolve section, so there are no dependency edges.
    NoResolve,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(message) => write!(f, "cargo metadata failed: {message}"),
            Self::NoResolve => write!(f, "cargo metadata returned no dependency resolution"),
        }
    }
}

impl std::error::Error for GraphError {}

/// A resolved package: one node in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// The SPDX license expression from the package's manifest, if it declares one.
    pub license: Option<String>,
    /// True for the project's own crates, as opposed to dependencies.
    pub workspace: bool,
    /// True when no build of the project ships this package: it is reached only
    /// through dev-dependencies, such as a test helper. Workspace crates are never
    /// dev-only.
    pub dev_only: bool,
    /// True when no enabled feature activates any path to this package. Such a
    /// package is listed by `cargo metadata` but is never compiled, for example an
    /// optional dependency whose feature is off. Workspace crates are never inactive.
    pub inactive: bool,
}

impl Package {
    /// `name version`, as shown in diagnostics.
    pub fn label(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// An indexed view of a project's resolved dependency graph.
///
/// Each node's edges point to its dependencies.
pub struct DependencyGraph {
    packages: Vec<Package>,
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

        // One run per target. An unfiltered `cargo metadata` resolves every target at
        // once and lists optional dependencies that no real build enables, so it
        // over-reports. The host is included even when it is not in TARGETS.
        let mut targets: Vec<String> = TARGETS.iter().map(|target| (*target).to_owned()).collect();
        let host = host_triple()?;
        if !targets.contains(&host) {
            targets.push(host);
        }

        let metadatas = targets
            .iter()
            .map(|target| metadata_for(&manifest, target))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_metadatas(&metadatas)
    }

    /// Builds the graph from `cargo metadata --format-version 1` output.
    ///
    /// Test-only: the CLI always goes through `load`. The benchmark uses this to
    /// time the parse + build step without the `cargo metadata` subprocess.
    #[cfg(test)]
    pub fn from_json(json: &str) -> Result<Self, GraphError> {
        let metadata = parse_metadata(json)?;
        Self::from_metadatas(std::slice::from_ref(&metadata))
    }

    /// Merges the resolve output of several target-filtered runs into one graph.
    /// Packages are identified by their `id`, so a package seen on two targets
    /// appears once, and its edges are the union across targets.
    fn from_metadatas(metadatas: &[JsonValue]) -> Result<Self, GraphError> {
        // Workspace membership is the same for every target, so read it from the first.
        let first = metadatas.first().ok_or(GraphError::NoResolve)?;
        let workspace_ids: HashSet<&str> =
            text_list(first, "workspace_members")?.into_iter().collect();

        let mut graph = Self {
            packages: Vec::new(),
            edges: Vec::new(),
            workspace: Vec::new(),
        };
        let mut index: HashMap<&str, usize> = HashMap::new();
        // Edges that a shipped build uses (a normal or build dependency that an enabled
        // feature activates), and edges that any build uses (including dev-dependencies).
        let mut shipped_edges: HashSet<(usize, usize)> = HashSet::new();
        let mut active_edges: HashSet<(usize, usize)> = HashSet::new();

        for metadata in metadatas {
            let resolve = &metadata["resolve"];
            if resolve.is_null() {
                return Err(GraphError::NoResolve);
            }

            for pkg in metadata["packages"].members() {
                let id = text(pkg, "id")?;
                if !index.contains_key(id) {
                    index.insert(id, graph.packages.len());
                    graph.packages.push(Package {
                        name: text(pkg, "name")?.to_owned(),
                        version: text(pkg, "version")?.to_owned(),
                        license: pkg["license"].as_str().map(str::to_owned),
                        workspace: workspace_ids.contains(id),
                        dev_only: false,
                        inactive: false,
                    });
                    graph.edges.push(Vec::new());
                }
            }

            // The declaration of each package, for checking which of its optional
            // dependencies an enabled feature turns on.
            let declared: HashMap<&str, &JsonValue> = metadata["packages"]
                .members()
                .filter_map(|pkg| pkg["id"].as_str().map(|id| (id, pkg)))
                .collect();

            for node in resolve["nodes"].members() {
                let node_id = text(node, "id")?;
                let from = lookup(&index, node_id)?;
                let owner = declared.get(node_id).copied();
                let enabled = text_list(node, "features")?;
                for dep in node["deps"].members() {
                    // A package can reach the same dependency under several names
                    // (renames, or normal + dev); keep one edge per pair.
                    let to = lookup(&index, text(dep, "pkg")?)?;
                    if !graph.edges[from].contains(&to) {
                        graph.edges[from].push(to);
                    }
                    let name = text(dep, "name")?;
                    for kind in dep_kinds(dep) {
                        if !edge_is_active(owner, &enabled, name, kind) {
                            continue;
                        }
                        active_edges.insert((from, to));
                        if kind != "dev" {
                            shipped_edges.insert((from, to));
                        }
                    }
                }
            }
        }

        graph.mark_build_membership(&shipped_edges, &active_edges);

        graph.workspace = graph
            .packages
            .iter()
            .filter(|pkg| pkg.workspace)
            .map(|pkg| pkg.name.clone())
            .collect();

        Ok(graph)
    }

    /// Sets `dev_only` and `inactive` from the edges that a build uses, reached from
    /// the workspace crates. A package reached by a shipped edge is shipped. A
    /// package reached only through dev edges is dev-only. A package reached by no
    /// active edge is inactive.
    fn mark_build_membership(
        &mut self,
        shipped_edges: &HashSet<(usize, usize)>,
        active_edges: &HashSet<(usize, usize)>,
    ) {
        let shipped = self.reachable_from_workspace(shipped_edges);
        let active = self.reachable_from_workspace(active_edges);
        for (ix, pkg) in self.packages.iter_mut().enumerate() {
            pkg.dev_only = !shipped[ix] && active[ix];
            pkg.inactive = !active[ix];
        }
    }

    /// For each package, whether it can be reached from a workspace crate over `edges`.
    fn reachable_from_workspace(&self, edges: &HashSet<(usize, usize)>) -> Vec<bool> {
        let count = self.packages.len();
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); count];
        for &(from, to) in edges {
            adjacency[from].push(to);
        }

        let mut reached = vec![false; count];
        let mut stack: Vec<usize> = Vec::new();
        for (ix, pkg) in self.packages.iter().enumerate() {
            if pkg.workspace {
                reached[ix] = true;
                stack.push(ix);
            }
        }
        while let Some(ix) = stack.pop() {
            for &next in &adjacency[ix] {
                if !reached[next] {
                    reached[next] = true;
                    stack.push(next);
                }
            }
        }
        reached
    }

    /// Every resolved package, including the project's own crates.
    pub fn packages(&self) -> &[Package] {
        &self.packages
    }

    /// Number of resolved packages, including the project itself.
    pub fn package_count(&self) -> usize {
        self.packages.len()
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
                    .map(|ix| self.packages[ix].label())
                    .collect();
                labels.sort();
                labels
            })
            .collect();
        cycles.sort();
        cycles
    }
}

/// The kinds a resolved dependency edge is used as: `"normal"`, `"dev"`, or `"build"`.
/// An edge with no kind information is a normal dependency.
fn dep_kinds(dep: &JsonValue) -> Vec<&str> {
    let kinds: Vec<&str> = dep["dep_kinds"]
        .members()
        .map(|info| info["kind"].as_str().unwrap_or("normal"))
        .collect();
    if kinds.is_empty() {
        vec!["normal"]
    } else {
        kinds
    }
}

/// The name a declared dependency is known by in the crate: its rename, or else its
/// package name.
fn declared_name(declared: &JsonValue) -> &str {
    declared["rename"]
        .as_str()
        .or_else(|| declared["name"].as_str())
        .unwrap_or_default()
}

/// Whether a dependency edge is active: its kind is used, and if the dependency is
/// optional, an enabled feature turns it on.
///
/// `cargo metadata` lists optional dependencies even when no feature enables them,
/// so the feature check is what separates a compiled edge from a listed one. An
/// optional dependency `key` is on when the enabled features include `key` itself,
/// or a feature that names `dep:key` or `key/...`. `key?/...` does not turn it on.
fn edge_is_active(owner: Option<&JsonValue>, enabled: &[&str], name: &str, kind: &str) -> bool {
    let Some(owner) = owner else {
        return true;
    };
    let wanted = name.replace('-', "_");
    let declared: Vec<&JsonValue> = owner["dependencies"]
        .members()
        .filter(|declared| {
            declared["kind"].as_str().unwrap_or("normal") == kind
                && declared_name(declared).replace('-', "_") == wanted
        })
        .collect();
    // No declaration to check against: treat the edge as active.
    if declared.is_empty() {
        return true;
    }
    declared.iter().any(|declared| {
        if !declared["optional"].as_bool().unwrap_or(false) {
            return true;
        }
        let key = declared_name(declared);
        let dep_feature = format!("dep:{key}");
        let slash = format!("{key}/");
        enabled.iter().any(|feature| {
            *feature == key
                || owner["features"][*feature].members().any(|entry| {
                    entry.as_str().is_some_and(|entry| {
                        entry == dep_feature || entry == key || entry.starts_with(slash.as_str())
                    })
                })
        })
    })
}

/// The host target triple, as reported by `rustc -vV`.
fn host_triple() -> Result<String, GraphError> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|err| GraphError::Metadata(format!("could not run rustc: {err}")))?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| GraphError::Metadata("rustc -vV reported no host triple".to_owned()))
}

/// Runs `cargo metadata` filtered to one target triple.
fn metadata_for(manifest: &Path, target: &str) -> Result<JsonValue, GraphError> {
    let mut command = Command::new("cargo");
    command
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--manifest-path",
        ])
        .arg(manifest)
        .args(["--filter-platform", target]);

    let output = command
        .output()
        .map_err(|err| GraphError::Metadata(format!("could not run cargo: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GraphError::Metadata(stderr.trim().to_owned()));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| GraphError::Metadata(format!("cargo output is not UTF-8: {err}")))?;
    parse_metadata(&stdout)
}

fn parse_metadata(json: &str) -> Result<JsonValue, GraphError> {
    json::parse(json).map_err(|err| GraphError::Metadata(format!("invalid JSON: {err}")))
}

/// A string field of a JSON object, or an error naming the missing field.
fn text<'a>(value: &'a JsonValue, key: &str) -> Result<&'a str, GraphError> {
    value[key]
        .as_str()
        .ok_or_else(|| GraphError::Metadata(format!("missing string field `{key}`")))
}

/// An array of string fields. A missing array is treated as empty.
fn text_list<'a>(value: &'a JsonValue, key: &str) -> Result<Vec<&'a str>, GraphError> {
    value[key]
        .members()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| GraphError::Metadata(format!("`{key}` entry is not a string")))
        })
        .collect()
}

/// Index of a package id, or an error if the resolve section names an unknown package.
fn lookup(index: &HashMap<&str, usize>, id: &str) -> Result<usize, GraphError> {
    index
        .get(id)
        .copied()
        .ok_or_else(|| GraphError::Metadata(format!("resolve refers to unknown package `{id}`")))
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
            .args([
                "metadata",
                "--format-version",
                "1",
                "--all-features",
                "--manifest-path",
            ])
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
        assert!(
            best < 100.0,
            "parse+build took {best:.2} ms, budget is 100 ms"
        );
    }
}
