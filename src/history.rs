use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use walkdir::WalkDir;

const COVERAGE_NOTE: &str = "Historique limité aux états observés depuis l'activation; le polling peut manquer des changements entre deux passages et une lecture n'est pas un instantané atomique.";
struct PreviousState {
    present: i64,
    sha256: Option<String>,
    size: Option<i64>,
    permissions: Option<String>,
    owner: Option<String>,
    modified_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub path: String,
    pub observed_at: String,
    pub sha256: Option<String>,
    pub size: Option<i64>,
    pub permissions: Option<String>,
    pub owner: Option<String>,
    pub modified_at: Option<String>,
    pub provenance: String,
    pub change: String,
    pub present: bool,
}

#[derive(Serialize)]
struct HistoryOutput {
    path: String,
    coverage: &'static str,
    observations: Vec<Observation>,
}

#[derive(Serialize)]
struct DiffOutput {
    since: String,
    coverage: &'static str,
    observations: Vec<Observation>,
}

pub fn watch(
    root: &Path,
    db_path: Option<&Path>,
    interval_secs: u64,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    if !root.exists() {
        return Err(format!("le chemin '{}' n'existe pas", root.display()).into());
    }
    if interval_secs == 0 {
        return Err("l'intervalle doit être supérieur à zéro".into());
    }

    let db_path = db_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_db_path);
    let connection = open_database(&db_path)?;
    let root = fs::canonicalize(root)?;
    let watch_single_file = root.is_file();
    let db_path = fs::canonicalize(db_path)?;

    eprintln!(
        "Surveillance par instantanés toutes les {interval_secs}s : {}",
        root.display()
    );
    eprintln!("{COVERAGE_NOTE}");
    eprintln!("Base locale : {}", db_path.display());

    let running = Arc::new(AtomicBool::new(true));
    let signal_running = Arc::clone(&running);
    ctrlc::set_handler(move || signal_running.store(false, Ordering::SeqCst))?;

    let mut initial_pass = true;
    while running.load(Ordering::SeqCst) {
        let (mut files, complete_scan) = collect_files(&root, watch_single_file);
        files.retain(|path| {
            let path = path.to_string_lossy();
            let database = db_path.to_string_lossy();
            path != database && !path.starts_with(&format!("{database}-"))
        });
        let seen: HashSet<String> = files
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();

        for path in files {
            let provenance = if initial_pass {
                "watch:baseline"
            } else {
                "watch:polling"
            };
            match observe_file(&connection, &path, provenance) {
                Ok(Some(observation)) => print_observation(&observation, json),
                Ok(None) => {}
                Err(error) => eprintln!("Avertissement : {} : {error}", path.display()),
            }
        }

        if complete_scan {
            for path in previously_observed_paths(&connection, &root)? {
                if !seen.contains(&path) {
                    if let Some(observation) = record_missing(&connection, &path)? {
                        print_observation(&observation, json);
                    }
                }
            }
        } else {
            eprintln!("Avertissement : parcours incomplet; les absences ne sont pas enregistrées.");
        }
        initial_pass = false;

        for _ in 0..interval_secs.saturating_mul(4) {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    eprintln!(
        "Surveillance arrêtée. Les états intermédiaires non échantillonnés restent inconnus."
    );
    Ok(())
}

pub fn show_history(path: &Path, db_path: Option<&Path>, json: bool) -> Result<(), Box<dyn Error>> {
    let db_path = db_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_db_path);
    let connection = open_database(&db_path)?;
    let path = normalized_path(path);
    let mut statement = connection.prepare(
        "SELECT path, observed_at, sha256, size, permissions, owner, modified_at, provenance, change_summary, present
         FROM observations WHERE path = ?1 ORDER BY observed_at ASC, id ASC",
    )?;
    let observations = statement
        .query_map([path.to_string_lossy().as_ref()], row_to_observation)?
        .collect::<Result<Vec<_>, _>>()?;
    let output = HistoryOutput {
        path: path.display().to_string(),
        coverage: COVERAGE_NOTE,
        observations,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Historique observé : {}", output.path);
        println!("Couverture : {}", output.coverage);
        print_observations(&output.observations);
    }
    Ok(())
}

pub fn recorded_observations(
    path: &Path,
    db_path: Option<&Path>,
) -> Result<Vec<Observation>, Box<dyn Error>> {
    let db_path = db_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_db_path);
    let connection = open_database(&db_path)?;
    let path = normalized_path(path);
    let mut statement = connection.prepare(
        "SELECT path, observed_at, sha256, size, permissions, owner, modified_at, provenance, change_summary, present
         FROM observations WHERE path = ?1 ORDER BY observed_at ASC, id ASC",
    )?;
    let observations = statement
        .query_map([path.to_string_lossy().as_ref()], row_to_observation)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(observations)
}

pub fn show_diff(since: &str, db_path: Option<&Path>, json: bool) -> Result<(), Box<dyn Error>> {
    let age = parse_duration(since)?;
    let db_path = db_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_db_path);
    let connection = open_database(&db_path)?;
    let age_millis = i64::try_from(age.as_millis()).map_err(|_| "durée trop longue")?;
    let cutoff = Utc::now()
        .timestamp_millis()
        .checked_sub(age_millis)
        .ok_or("durée trop longue")?;
    let mut statement = connection.prepare(
        "SELECT path, observed_at, sha256, size, permissions, owner, modified_at, provenance, change_summary, present
         FROM observations WHERE observed_at >= ?1 AND change_summary != 'baseline' ORDER BY observed_at ASC, id ASC",
    )?;
    let observations = statement
        .query_map([cutoff], row_to_observation)?
        .collect::<Result<Vec<_>, _>>()?;
    let output = DiffOutput {
        since: since.to_string(),
        coverage: COVERAGE_NOTE,
        observations,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Changements observés depuis {since}");
        println!("Couverture : {}", output.coverage);
        print_observations(&output.observations);
    }
    Ok(())
}

pub(crate) fn open_database(path: &Path) -> Result<Connection, Box<dyn Error>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    if !path.exists() {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);
    }
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            observed_at INTEGER NOT NULL,
            sha256 TEXT,
            size INTEGER,
            permissions TEXT,
            owner TEXT,
            modified_at INTEGER,
            provenance TEXT NOT NULL,
            change_summary TEXT NOT NULL,
            present INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS observations_path_time ON observations(path, observed_at);
        CREATE INDEX IF NOT EXISTS observations_time ON observations(observed_at);",
    )?;
    let has_modified_at: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('observations') WHERE name = 'modified_at')",
        [],
        |row| row.get(0),
    )?;
    if !has_modified_at {
        connection.execute(
            "ALTER TABLE observations ADD COLUMN modified_at INTEGER",
            [],
        )?;
    }
    Ok(connection)
}

pub(crate) fn observe_file(
    connection: &Connection,
    path: &Path,
    provenance: &str,
) -> Result<Option<Observation>, Box<dyn Error>> {
    let path = normalized_path(path);
    let mut file = fs::File::open(&path)?;
    let metadata = file.metadata()?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let final_metadata = file.metadata()?;
    if metadata.len() != final_metadata.len()
        || metadata.modified().ok() != final_metadata.modified().ok()
    {
        return Err("fichier modifié pendant le calcul de l'empreinte; observation ignorée".into());
    }
    let sha256 = format!("{:x}", digest.finalize());
    let size = i64::try_from(metadata.len()).map_err(|_| "taille du fichier hors limites")?;
    let permissions = permissions(&metadata);
    let owner = owner(&metadata);
    let modified_at = metadata.modified().ok().and_then(system_time_millis);
    let path = path.to_string_lossy().into_owned();
    let previous: Option<PreviousState> = connection
        .query_row(
            "SELECT present, sha256, size, permissions, owner, modified_at FROM observations
                 WHERE path = ?1 ORDER BY observed_at DESC, id DESC LIMIT 1",
            [&path],
            |row| {
                Ok(PreviousState {
                    present: row.get(0)?,
                    sha256: row.get(1)?,
                    size: row.get(2)?,
                    permissions: row.get(3)?,
                    owner: row.get(4)?,
                    modified_at: row.get(5)?,
                })
            },
        )
        .optional()?;

    let change = match previous {
        None if provenance == "watch:polling" => "apparition observée au polling".to_string(),
        None => "baseline".to_string(),
        Some(PreviousState { present: 0, .. }) => "réapparition constatée".to_string(),
        Some(previous) => {
            let mut changes = Vec::new();
            if previous.sha256.as_deref() != Some(&sha256) {
                changes.push("contenu (SHA-256)");
            }
            if previous.size != Some(size) {
                changes.push("taille");
            }
            if previous.permissions != permissions {
                changes.push("permissions");
            }
            if previous.owner != owner {
                changes.push("propriétaire");
            }
            if previous.modified_at != modified_at {
                changes.push("date de modification");
            }
            if changes.is_empty() {
                return Ok(None);
            }
            format!("modification : {}", changes.join(", "))
        }
    };

    let timestamp = Utc::now().timestamp_millis();
    connection.execute(
        "INSERT INTO observations(path, observed_at, sha256, size, permissions, owner, modified_at, provenance, change_summary, present)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)",
        params![path, timestamp, sha256, size, permissions, owner, modified_at, provenance, change],
    )?;
    Ok(Some(Observation {
        path,
        observed_at: format_time(timestamp),
        sha256: Some(sha256),
        size: Some(size),
        permissions,
        owner,
        modified_at: modified_at.map(format_time),
        provenance: provenance.to_string(),
        change,
        present: true,
    }))
}

fn record_missing(
    connection: &Connection,
    path: &str,
) -> Result<Option<Observation>, Box<dyn Error>> {
    let normalized = normalized_path(Path::new(path));
    let path = normalized.to_string_lossy();
    let previous: Option<i64> = connection
        .query_row(
            "SELECT present FROM observations WHERE path = ?1 ORDER BY observed_at DESC, id DESC LIMIT 1",
            [path.as_ref()],
            |row| row.get(0),
        )
        .optional()?;
    if previous != Some(1) {
        return Ok(None);
    }
    let timestamp = Utc::now().timestamp_millis();
    let change =
        "absence constatée au polling; suppression et inaccessibilité ne sont pas distinguées";
    connection.execute(
        "INSERT INTO observations(path, observed_at, provenance, change_summary, present)
         VALUES (?1, ?2, 'polling', ?3, 0)",
        params![path.as_ref(), timestamp, change],
    )?;
    Ok(Some(Observation {
        path: path.into_owned(),
        observed_at: format_time(timestamp),
        sha256: None,
        size: None,
        permissions: None,
        owner: None,
        modified_at: None,
        provenance: "polling".to_string(),
        change: change.to_string(),
        present: false,
    }))
}

fn previously_observed_paths(
    connection: &Connection,
    root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut statement = connection.prepare(
        "SELECT DISTINCT path FROM observations WHERE path = ?1 OR substr(path, 1, length(?2)) = ?2",
    )?;
    let root = root.to_string_lossy();
    let prefix = if root.ends_with(std::path::MAIN_SEPARATOR) {
        root.to_string()
    } else {
        format!("{root}{}", std::path::MAIN_SEPARATOR)
    };
    let candidates = statement
        .query_map(params![root.as_ref(), prefix], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    candidates
        .into_iter()
        .filter_map(|path| {
            let present: Result<i64, _> = connection.query_row(
                "SELECT present FROM observations WHERE path = ?1 ORDER BY observed_at DESC, id DESC LIMIT 1",
                [&path],
                |row| row.get(0),
            );
            match present {
                Ok(1) => Some(Ok(path)),
                Ok(_) => None,
                Err(error) => Some(Err(error.into())),
            }
        })
        .collect()
}

fn collect_files(root: &Path, watch_single_file: bool) -> (Vec<PathBuf>, bool) {
    if watch_single_file {
        return if root.is_file() {
            (vec![root.to_path_buf()], true)
        } else {
            (Vec::new(), true)
        };
    }
    if !root.is_dir() {
        return (Vec::new(), false);
    }
    let mut files = Vec::new();
    let mut complete = true;
    for entry in WalkDir::new(root).follow_links(false) {
        match entry {
            Ok(entry) if entry.file_type().is_file() => files.push(entry.into_path()),
            Ok(_) => {}
            Err(_) => complete = false,
        }
    }
    (files, complete)
}

fn row_to_observation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Observation> {
    let timestamp: i64 = row.get(1)?;
    let modified_at: Option<i64> = row.get(6)?;
    Ok(Observation {
        path: row.get(0)?,
        observed_at: format_time(timestamp),
        sha256: row.get(2)?,
        size: row.get(3)?,
        permissions: row.get(4)?,
        owner: row.get(5)?,
        modified_at: modified_at.map(format_time),
        provenance: row.get(7)?,
        change: row.get(8)?,
        present: row.get::<_, i64>(9)? != 0,
    })
}

fn print_observation(observation: &Observation, json: bool) {
    if json {
        match serde_json::to_string(observation) {
            Ok(line) => println!("{line}"),
            Err(error) => eprintln!("Erreur de sérialisation : {error}"),
        }
    } else {
        println!(
            "{} | {} | {}",
            observation.observed_at, observation.change, observation.path
        );
    }
}

fn print_observations(observations: &[Observation]) {
    if observations.is_empty() {
        println!("Aucune observation enregistrée.");
        return;
    }
    for observation in observations {
        println!(
            "{} | {} | {} | sha256={} taille={} permissions={} propriétaire={} modifié={} provenance={}",
            observation.observed_at,
            observation.change,
            observation.path,
            observation.sha256.as_deref().unwrap_or("indisponible"),
            observation
                .size
                .map_or_else(|| "indisponible".to_string(), |v| v.to_string()),
            observation
                .permissions
                .as_deref()
                .unwrap_or("indisponibles"),
            observation.owner.as_deref().unwrap_or("indisponible"),
            observation.modified_at.as_deref().unwrap_or("indisponible"),
            observation.provenance,
        );
    }
}

fn permissions(metadata: &fs::Metadata) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(format!("{:o}", metadata.permissions().mode() & 0o7777))
    }
    #[cfg(windows)]
    {
        Some(format!("readonly={}", metadata.permissions().readonly()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        None
    }
}

fn owner(metadata: &fs::Metadata) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(format!("uid:{} gid:{}", metadata.uid(), metadata.gid()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn default_db_path() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));

    base.unwrap_or_else(|| PathBuf::from("."))
        .join("mach")
        .join("history.sqlite3")
}

fn normalized_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    if let Ok(canonical) = fs::canonicalize(&absolute) {
        return canonical;
    }
    match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(file_name)) => fs::canonicalize(parent)
            .unwrap_or_else(|_| parent.to_path_buf())
            .join(file_name),
        _ => absolute,
    }
}

fn parse_duration(input: &str) -> Result<Duration, Box<dyn Error>> {
    let (number, unit) = input.split_at(
        input
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(input.len()),
    );
    let amount: u64 = number
        .parse()
        .map_err(|_| "durée invalide, exemple attendu : 24h")?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err("unité invalide; utilise s, m, h ou d (ex. 24h)".into()),
    };
    let seconds = amount
        .checked_mul(multiplier)
        .filter(|seconds| *seconds > 0)
        .ok_or("durée hors limites ou nulle")?;
    Ok(Duration::from_secs(seconds))
}

fn format_time(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(timestamp)
        .map(|time| time.to_rfc3339())
        .unwrap_or_else(|| timestamp.to_string())
}

fn system_time_millis(time: std::time::SystemTime) -> Option<i64> {
    i64::try_from(time.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::{observe_file, open_database, parse_duration, record_missing};
    use rusqlite::Connection;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_since_duration_units() {
        assert_eq!(parse_duration("24h").unwrap().as_secs(), 86_400);
        assert_eq!(parse_duration("7d").unwrap().as_secs(), 604_800);
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("3weeks").is_err());
    }

    #[test]
    fn records_baseline_and_content_change() {
        let directory =
            std::env::temp_dir().join(format!("mach-history-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("sample.txt");
        fs::write(&file, "first").unwrap();
        let connection = open_database(&directory.join("history.sqlite3")).unwrap();

        let baseline = observe_file(&connection, &file, "test").unwrap().unwrap();
        assert_eq!(baseline.change, "baseline");
        assert_eq!(baseline.sha256.as_deref().unwrap().len(), 64);
        assert!(observe_file(&connection, &file, "test").unwrap().is_none());

        fs::write(&file, "second content").unwrap();
        let change = observe_file(&connection, &file, "test").unwrap().unwrap();
        assert!(change.change.contains("contenu (SHA-256)"));

        drop(connection);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn records_observed_absence_and_reappearance() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "mach-history-missing-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("sample.txt");
        fs::write(&file, "first").unwrap();
        let connection = open_database(&directory.join("history.sqlite3")).unwrap();
        observe_file(&connection, &file, "test").unwrap();

        fs::remove_file(&file).unwrap();
        let missing = record_missing(&connection, file.to_str().unwrap())
            .unwrap()
            .unwrap();
        assert!(!missing.present);
        assert!(record_missing(&connection, file.to_str().unwrap())
            .unwrap()
            .is_none());

        fs::write(&file, "restored").unwrap();
        let restored = observe_file(&connection, &file, "test").unwrap().unwrap();
        assert_eq!(restored.change, "réapparition constatée");

        drop(connection);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn distinguishes_initial_baseline_from_later_first_observation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "mach-watch-appearance-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("arrived.conf");
        fs::write(&file, "arrived").unwrap();
        let connection = open_database(&directory.join("history.sqlite3")).unwrap();

        let baseline = observe_file(&connection, &file, "watch:baseline")
            .unwrap()
            .unwrap();
        assert_eq!(baseline.change, "baseline");
        fs::remove_file(&file).unwrap();
        let appearance = directory.join("new.conf");
        fs::write(&appearance, "new").unwrap();
        let observed = observe_file(&connection, &appearance, "watch:polling")
            .unwrap()
            .unwrap();
        assert_eq!(observed.change, "apparition observée au polling");

        drop(connection);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn migrates_an_existing_database_without_modified_timestamp_column() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "mach-history-migration-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let database = directory.join("history.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE observations (
                    id INTEGER PRIMARY KEY,
                    path TEXT NOT NULL,
                    observed_at INTEGER NOT NULL,
                    sha256 TEXT,
                    size INTEGER,
                    permissions TEXT,
                    owner TEXT,
                    provenance TEXT NOT NULL,
                    change_summary TEXT NOT NULL,
                    present INTEGER NOT NULL
                );",
            )
            .unwrap();
        drop(connection);

        let migrated = open_database(&database).unwrap();
        let has_modified_at: bool = migrated
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('observations') WHERE name = 'modified_at')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_modified_at);
        drop(migrated);
        fs::remove_dir_all(directory).unwrap();
    }
}
