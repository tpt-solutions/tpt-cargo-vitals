//! Local SQLite cache of the RustSec advisory database.
//!
//! The cache stores each advisory's raw source text, keyed by the crate it
//! affects. Parsing happens at audit time, and only for the crates in the graph.

use std::fs;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

/// Error type shared by the cache, updater, and audit. Boxed, since these
/// failures are reported to the user and not matched on.
pub type Error = Box<dyn std::error::Error>;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS advisories (
        package TEXT NOT NULL,
        raw     TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS advisories_by_package ON advisories (package);
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
";

/// A handle to the advisory cache file.
pub struct AdvisoryCache {
    conn: Connection,
}

impl AdvisoryCache {
    /// Opens the cache at `path`, creating the file and its parent directories.
    pub fn open(path: &Path) -> Result<Self, Error> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        Self::with_connection(Connection::open(path)?)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self, Error> {
        Self::with_connection(Connection::open_in_memory()?)
    }

    fn with_connection(conn: Connection) -> Result<Self, Error> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Unix time (seconds) of the last successful update, or `None` if the cache
    /// has never been filled.
    pub fn fetched_at(&self) -> Result<Option<i64>, Error> {
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'fetched_at'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.map(|v| v.parse()).transpose()?)
    }

    /// Replaces every stored advisory with `advisories` (`(package, raw text)`
    /// pairs) and records `fetched_at`. The swap is one transaction, so a failed
    /// update leaves the previous contents in place.
    pub fn replace_all(
        &mut self,
        advisories: &[(String, String)],
        fetched_at: i64,
    ) -> Result<usize, Error> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM advisories", [])?;
        {
            let mut insert = tx.prepare("INSERT INTO advisories (package, raw) VALUES (?1, ?2)")?;
            for (package, raw) in advisories {
                insert.execute(params![package, raw])?;
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('fetched_at', ?1)",
            params![fetched_at.to_string()],
        )?;
        tx.commit()?;
        Ok(advisories.len())
    }

    /// Raw source text of every advisory that names one of `packages`.
    pub fn advisories_for(&self, packages: &[&str]) -> Result<Vec<String>, Error> {
        let mut query = self
            .conn
            .prepare("SELECT raw FROM advisories WHERE package = ?1")?;
        let mut raws = Vec::new();
        for package in packages {
            let rows = query.query_map(params![package], |row| row.get::<_, String>(0))?;
            for raw in rows {
                raws.push(raw?);
            }
        }
        Ok(raws)
    }
}

/// Formats a Unix timestamp (seconds, UTC) as `YYYY-MM-DD`.
pub fn format_date(unix_secs: i64) -> String {
    // Howard Hinnant's civil-from-days algorithm: days since 1970-01-01 to a
    // proleptic Gregorian date, without pulling in a date/time crate.
    let z = unix_secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_all_round_trips_and_records_fetch_time() {
        let mut cache = AdvisoryCache::in_memory().unwrap();
        assert_eq!(cache.fetched_at().unwrap(), None);

        let rows = [
            ("serde".to_owned(), "raw serde".to_owned()),
            ("tokio".to_owned(), "raw tokio".to_owned()),
        ];
        assert_eq!(cache.replace_all(&rows, 1_700_000_000).unwrap(), 2);

        assert_eq!(cache.fetched_at().unwrap(), Some(1_700_000_000));
        assert_eq!(cache.advisories_for(&["serde"]).unwrap(), ["raw serde"]);
        assert!(cache.advisories_for(&["missing"]).unwrap().is_empty());

        // A second replace drops the old rows entirely.
        cache.replace_all(&[], 1_800_000_000).unwrap();
        assert!(cache.advisories_for(&["serde"]).unwrap().is_empty());
        assert_eq!(cache.fetched_at().unwrap(), Some(1_800_000_000));
    }

    #[test]
    fn format_date_matches_known_timestamps() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(951_782_400), "2000-02-29");
        assert_eq!(format_date(1_800_000_000), "2027-01-15");
    }
}
