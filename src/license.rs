//! License compliance: parses SPDX license expressions and checks dependencies
//! against an allow-list policy.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::DependencyGraph;

/// A parsed SPDX license expression.
///
/// `X WITH Y` is kept as one identifier, `"X WITH Y"`, so a policy can allow that
/// exact license (for example `Apache-2.0 WITH LLVM-exception`) without allowing
/// `X` alone.
#[derive(Debug, PartialEq, Eq)]
enum Expr {
    License(String),
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// Parses `text`, or returns `None` if it is not a valid expression.
    fn parse(text: &str) -> Option<Expr> {
        let mut parser = Parser {
            tokens: tokenize(text)?,
            pos: 0,
        };
        let expr = parser.or()?;
        (parser.pos == parser.tokens.len()).then_some(expr)
    }

    /// Whether the expression can be satisfied using only `allowed` licenses.
    /// An `OR` needs one satisfiable side, an `AND` needs both.
    fn satisfied_by(&self, allowed: &[String]) -> bool {
        match self {
            Expr::License(id) => allowed.iter().any(|a| a.eq_ignore_ascii_case(id)),
            Expr::Or(a, b) => a.satisfied_by(allowed) || b.satisfied_by(allowed),
            Expr::And(a, b) => a.satisfied_by(allowed) && b.satisfied_by(allowed),
        }
    }

    /// Adds every license identifier the expression names.
    fn collect_ids<'a>(&'a self, out: &mut BTreeSet<&'a str>) {
        match self {
            Expr::License(id) => {
                out.insert(id);
            }
            Expr::Or(a, b) | Expr::And(a, b) => {
                a.collect_ids(out);
                b.collect_ids(out);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Id(String),
    And,
    Or,
    With,
    Open,
    Close,
}

/// Splits an expression into tokens. `/` is the legacy spelling of `OR`.
/// Returns `None` for an empty expression.
fn tokenize(text: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut word = String::new();

    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if !word.is_empty() {
            tokens.push(match word.as_str() {
                "AND" => Token::And,
                "OR" => Token::Or,
                "WITH" => Token::With,
                _ => Token::Id(word.clone()),
            });
            word.clear();
        }
    };

    for ch in text.chars() {
        match ch {
            '(' | ')' | '/' | ' ' | '\t' => {
                flush(&mut word, &mut tokens);
                match ch {
                    '(' => tokens.push(Token::Open),
                    ')' => tokens.push(Token::Close),
                    '/' => tokens.push(Token::Or),
                    _ => {}
                }
            }
            _ => word.push(ch),
        }
    }
    flush(&mut word, &mut tokens);

    (!tokens.is_empty()).then_some(tokens)
}

/// Recursive-descent parser. `AND` binds tighter than `OR`.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn or(&mut self) -> Option<Expr> {
        let mut left = self.and()?;
        while self.take(&Token::Or) {
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn and(&mut self) -> Option<Expr> {
        let mut left = self.primary()?;
        while self.take(&Token::And) {
            let right = self.primary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn primary(&mut self) -> Option<Expr> {
        let token = self.next()?;
        match token {
            Token::Open => {
                let inner = self.or()?;
                self.take(&Token::Close).then_some(inner)
            }
            Token::Id(id) => {
                // `GPL-2.0 WITH Classpath-exception-2.0` is one license.
                if self.take(&Token::With) {
                    match self.next()? {
                        Token::Id(exception) => {
                            Some(Expr::License(format!("{id} WITH {exception}")))
                        }
                        _ => None,
                    }
                } else {
                    Some(Expr::License(id))
                }
            }
            _ => None,
        }
    }

    /// Consumes the next token if it equals `expected`.
    fn take(&mut self, expected: &Token) -> bool {
        if self.tokens.get(self.pos) == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos)?.clone();
        self.pos += 1;
        Some(token)
    }
}

/// Outcome of checking every dependency's license.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LicenseReport {
    /// Dependencies checked. The project's own crates are excluded.
    pub checked: usize,
    /// Dependencies that fail the policy, as `name version` and their declared license
    /// (`none` when no license is declared). Empty when no policy is given.
    pub violations: Vec<(String, String)>,
    /// Dependencies per license identifier. An expression counts toward every
    /// identifier it names, so `MIT OR Apache-2.0` counts once for each.
    pub counts: BTreeMap<String, usize>,
    /// Dependencies with no declared license, or one that does not parse.
    pub undeclared: usize,
    /// Dependencies that no build ships (reached only through dev-dependencies).
    /// Each is checked against the policy plus the dev allowance.
    pub dev_only: usize,
    /// Dependencies that no enabled feature turns on. They are listed by
    /// `cargo metadata` but never compiled, so they are not checked.
    pub inactive: usize,
}

impl LicenseReport {
    /// Dependencies that pass the policy.
    pub fn compliant(&self) -> usize {
        self.checked - self.violations.len()
    }
}

/// Checks every dependency in `graph`. With `allowed` set to `Some`, a dependency
/// is a violation unless its license can be satisfied with only those identifiers.
///
/// A dev-only dependency (see [`Package::dev_only`]) may also use the identifiers in
/// `dev_allowed`, since no build ships it. The policy uses this for `Apache-2.0`
/// alone, which is allowed in dev-dependencies only. Shipped dependencies never get
/// the dev allowance. The CLI always passes exceptions, so this form is for tests.
#[cfg(test)]
pub fn check(
    graph: &DependencyGraph,
    allowed: Option<&[String]>,
    dev_allowed: &[String],
) -> LicenseReport {
    check_with(graph, allowed, dev_allowed, &[])
}

/// [`check`] with per-crate exceptions. Each `(crate, license)` pair lets that one
/// crate use `license` in addition to the policy, and no other crate. The policy
/// records such exceptions with a reason and a scope, for example `webpki-roots`
/// with `CDLA-Permissive-2.0`.
pub fn check_with(
    graph: &DependencyGraph,
    allowed: Option<&[String]>,
    dev_allowed: &[String],
    exceptions: &[(String, String)],
) -> LicenseReport {
    let mut report = LicenseReport::default();

    for pkg in graph.packages().iter().filter(|pkg| !pkg.workspace) {
        if pkg.inactive {
            report.inactive += 1;
            continue;
        }
        report.checked += 1;
        if pkg.dev_only {
            report.dev_only += 1;
        }
        let expr = pkg.license.as_deref().and_then(Expr::parse);

        match &expr {
            None => report.undeclared += 1,
            Some(expr) => {
                let mut ids = BTreeSet::new();
                expr.collect_ids(&mut ids);
                for id in ids {
                    *report.counts.entry(id.to_owned()).or_default() += 1;
                }
            }
        }

        if let Some(allowed) = allowed {
            let mut extra: Vec<String> = if pkg.dev_only {
                allowed.iter().chain(dev_allowed).cloned().collect()
            } else {
                allowed.to_vec()
            };
            extra.extend(
                exceptions
                    .iter()
                    .filter(|(name, _)| *name == pkg.name)
                    .map(|(_, license)| license.clone()),
            );
            let passes = expr.as_ref().is_some_and(|expr| expr.satisfied_by(&extra));
            if !passes {
                let license = pkg.license.as_deref().unwrap_or("none");
                report.violations.push((pkg.label(), license.to_owned()));
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn allow(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    #[test]
    fn parses_operators_with_precedence() {
        // AND binds tighter than OR, so this is MIT OR (Apache-2.0 AND Unicode-3.0).
        let expr = Expr::parse("MIT OR Apache-2.0 AND Unicode-3.0").unwrap();
        assert!(expr.satisfied_by(&allow(&["MIT"])));
        assert!(!expr.satisfied_by(&allow(&["Apache-2.0"])));
        assert!(expr.satisfied_by(&allow(&["Apache-2.0", "Unicode-3.0"])));
    }

    #[test]
    fn slash_is_or_and_parentheses_group() {
        let expr = Expr::parse("(MIT/Apache-2.0) AND Unicode-3.0").unwrap();
        assert!(expr.satisfied_by(&allow(&["MIT", "Unicode-3.0"])));
        assert!(!expr.satisfied_by(&allow(&["MIT"])));
    }

    #[test]
    fn with_exception_is_one_license() {
        let expr = Expr::parse("GPL-2.0-only WITH Classpath-exception-2.0").unwrap();
        assert!(expr.satisfied_by(&allow(&["GPL-2.0-only WITH Classpath-exception-2.0"])));
        assert!(!expr.satisfied_by(&allow(&["GPL-2.0-only"])));
    }

    #[test]
    fn exception_is_matched_case_insensitively_as_a_whole() {
        let expr = Expr::parse("Apache-2.0 WITH LLVM-exception OR MIT").unwrap();
        assert!(expr.satisfied_by(&allow(&["apache-2.0 with llvm-exception"])));
        assert!(!expr.satisfied_by(&allow(&["Apache-2.0"])));
    }

    #[test]
    fn license_matching_ignores_case() {
        let expr = Expr::parse("MIT").unwrap();
        assert!(expr.satisfied_by(&allow(&["mit"])));
    }

    #[test]
    fn rejects_malformed_expressions() {
        for bad in [
            "",
            "MIT OR",
            "(MIT",
            "MIT)",
            "AND MIT",
            "GPL WITH",
            "MIT Apache-2.0",
        ] {
            assert_eq!(Expr::parse(bad), None, "{bad:?} should not parse");
        }
    }

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/licenses/app")
    }

    #[test]
    fn pure_mit_policy_flags_non_mit_and_undeclared_dependencies() {
        let graph = DependencyGraph::load(&fixture()).unwrap();
        let report = check(&graph, Some(&allow(&["MIT"])), &[]);

        // Six dependencies; the project's own crate is excluded.
        assert_eq!(report.checked, 6);
        assert_eq!(report.compliant(), 2); // lic-mit and lic-dual (MIT OR Apache-2.0)
        assert_eq!(
            report.violations,
            [
                (
                    "lic-and 0.1.0".to_owned(),
                    "(MIT OR Apache-2.0) AND Unicode-3.0".to_owned()
                ),
                ("lic-apache 0.1.0".to_owned(), "Apache-2.0".to_owned()),
                ("lic-gpl 0.1.0".to_owned(), "GPL-3.0-only".to_owned()),
                ("lic-none 0.1.0".to_owned(), "none".to_owned()),
            ]
        );
        assert_eq!(report.undeclared, 1);
    }

    #[test]
    fn policy_can_allow_several_licenses() {
        let graph = DependencyGraph::load(&fixture()).unwrap();
        let report = check(
            &graph,
            Some(&allow(&["MIT", "Apache-2.0", "Unicode-3.0"])),
            &[],
        );

        // Only the GPL crate and the undeclared one still fail.
        let failing: Vec<&str> = report
            .violations
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        assert_eq!(failing, ["lic-gpl 0.1.0", "lic-none 0.1.0"]);
    }

    #[test]
    fn counts_each_identifier_an_expression_names() {
        let graph = DependencyGraph::load(&fixture()).unwrap();
        let report = check(&graph, None, &[]);

        assert!(
            report.violations.is_empty(),
            "no policy means no violations"
        );
        assert_eq!(report.counts["MIT"], 3); // lic-mit, lic-dual, lic-and
        assert_eq!(report.counts["Apache-2.0"], 3); // lic-apache, lic-dual, lic-and
        assert_eq!(report.counts["GPL-3.0-only"], 1);
        assert_eq!(report.counts["Unicode-3.0"], 1);
    }

    #[test]
    fn dev_allowance_covers_only_dev_only_dependencies() {
        // lic-apache is a dev-dependency of the devonly fixture, so it is not shipped.
        let devonly = DependencyGraph::load(&devonly_fixture()).unwrap();
        let strict = check(&devonly, Some(&allow(&["MIT"])), &[]);
        // lic-mit ships and lic-apache is dev-only.
        assert_eq!(strict.checked, 2);
        assert_eq!(strict.dev_only, 1);
        assert_eq!(strict.inactive, 0);
        assert_eq!(
            strict.violations,
            [("lic-apache 0.1.0".to_owned(), "Apache-2.0".to_owned())]
        );
        let relaxed = check(&devonly, Some(&allow(&["MIT"])), &allow(&["Apache-2.0"]));
        assert!(relaxed.violations.is_empty(), "{:?}", relaxed.violations);

        // The same license in a shipped dependency is still a violation.
        let shipped = DependencyGraph::load(&fixture()).unwrap();
        let report = check(&shipped, Some(&allow(&["MIT"])), &allow(&["Apache-2.0"]));
        assert_eq!(report.dev_only, 0);
        assert!(
            report
                .violations
                .contains(&("lic-apache 0.1.0".to_owned(), "Apache-2.0".to_owned()))
        );
    }

    #[test]
    fn optional_dependency_that_no_feature_enables_is_not_checked() {
        // lic-wrap's optional lic-gpl is switched on only by its `gpl` feature, which
        // this workspace does not enable. cargo metadata still lists the edge.
        let graph = DependencyGraph::load(&inactive_fixture()).unwrap();
        let report = check(&graph, Some(&allow(&["MIT"])), &[]);
        assert_eq!(report.checked, 1); // lic-wrap only
        assert_eq!(report.inactive, 1); // lic-gpl
        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }

    #[test]
    fn exception_lets_one_crate_use_its_license_and_no_other() {
        let graph = DependencyGraph::load(&fixture()).unwrap();
        let exceptions = [("lic-apache".to_owned(), "Apache-2.0".to_owned())];
        let report = check_with(&graph, Some(&allow(&["MIT"])), &[], &exceptions);
        let failing: Vec<&str> = report
            .violations
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        // lic-apache is excepted; the GPL crate and the undeclared one still fail.
        assert_eq!(
            failing,
            ["lic-and 0.1.0", "lic-gpl 0.1.0", "lic-none 0.1.0"]
        );
    }

    fn inactive_fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/licenses/inactive")
    }

    fn devonly_fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/licenses/devonly")
    }
}
