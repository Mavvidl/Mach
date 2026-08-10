use crate::process_info::ProcessEntry;
use chrono::{DateTime, Local};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UsageInfo {
    pub last_accessed: Option<String>,
    pub last_modified: Option<String>,
    pub currently_in_use: bool,
    pub description: String,
}

pub fn analyze(path: &Path, related_processes: &[ProcessEntry]) -> UsageInfo {
    let metadata = fs::metadata(path).ok();

    let last_accessed = metadata
        .as_ref()
        .and_then(|m| m.accessed().ok())
        .map(|t| format_time(t));

    let last_modified = metadata
        .as_ref()
        .and_then(|m| m.modified().ok())
        .map(|t| format_time(t));

    let currently_in_use = is_currently_in_use(path, related_processes);

    let description = describe(related_processes, currently_in_use);

    UsageInfo {
        last_accessed,
        last_modified,
        currently_in_use,
        description,
    }
}

fn format_time(t: std::time::SystemTime) -> String {
    let dt: DateTime<Local> = t.into();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Détermine si le fichier semble activement utilisé.
///
/// - Si on a au moins un processus "confirmé" (fd ouvert, Linux) -> oui, certain.
/// - Sinon (Windows, ou pas de fd trouvé) -> on tente d'ouvrir le fichier en accès
///   exclusif ; si ça échoue avec un verrou/partage refusé, un autre processus le
///   tient probablement ouvert. C'est un indice, pas une certitude absolue.
fn is_currently_in_use(_path: &Path, related_processes: &[ProcessEntry]) -> bool {
    if related_processes.iter().any(|p| p.confirmed) {
        return true;
    }

    #[cfg(target_os = "windows")]
    {
        use std::fs::OpenOptions;
        // Sur Windows, tenter une ouverture qui échoue si un autre process
        // a le fichier verrouillé en écriture exclusive.
        return OpenOptions::new().write(true).open(path).is_err()
            && path.exists();
    }

    #[cfg(not(target_os = "windows"))]
    {
        !related_processes.is_empty()
    }
}

fn describe(related_processes: &[ProcessEntry], in_use: bool) -> String {
    if !in_use {
        return "Pas d'utilisation active détectée".to_string();
    }

    if let Some(p) = related_processes.iter().find(|p| p.confirmed) {
        format!("Actuellement utilisé par le processus {} (pid {})", p.user, p.pid)
    } else if let Some(p) = related_processes.first() {
        format!(
            "Probablement utilisé par {} (pid {}) — indice non confirmé",
            p.user, p.pid
        )
    } else {
        "Le fichier semble verrouillé/en cours d'utilisation par un processus non identifié"
            .to_string()
    }
}
