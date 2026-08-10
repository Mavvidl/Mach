use chrono::{Local, TimeZone};
use serde::Serialize;
use std::path::Path;
use sysinfo::{Pid, System, Users};

#[derive(Debug, Clone, Serialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub user: String,
    pub status: String,
    pub last_used: String,
    /// true si on a une preuve directe (fd ouvert), false si c'est une heuristique
    /// (match sur nom/ligne de commande, utilisé en repli sur Windows)
    pub confirmed: bool,
}

/// Retourne la liste des processus liés au fichier `path`.
///
/// Sur Linux : lecture de `/proc/[pid]/fd/*` -> preuve directe qu'un processus
/// a le fichier ouvert (équivalent maison de `lsof`).
///
/// Sur Windows : il n'existe pas d'API simple/stable équivalente sans handles
/// natifs (NtQuerySystemInformation etc.), donc on retombe sur une heuristique :
/// on regarde si le nom du fichier apparaît dans le nom du process ou sa ligne
/// de commande. Ce n'est PAS une preuve d'ouverture réelle, juste un indice.
pub fn find_related_processes(path: &Path) -> Vec<ProcessEntry> {
    let mut system = System::new_all();
    system.refresh_all();
    let users = Users::new_with_refreshed_list();

    #[cfg(target_os = "linux")]
    {
        linux_fd_scan(path, &system, &users)
    }

    #[cfg(not(target_os = "linux"))]
    {
        heuristic_scan(path, &system, &users)
    }
}

#[cfg(target_os = "linux")]
fn linux_fd_scan(path: &Path, system: &System, users: &Users) -> Vec<ProcessEntry> {
    use std::fs;

    let canonical_target = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => path.to_path_buf(),
    };

    let mut results = Vec::new();

    let proc_entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let pid_str = match file_name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let pid_num: u32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue, // pas un dossier PID
        };

        let fd_dir = entry.path().join("fd");
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(e) => e,
            Err(_) => continue, // pas les droits, ou processus disparu
        };

        let mut matched = false;
        for fd in fd_entries.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if target == canonical_target {
                    matched = true;
                    break;
                }
            }
        }

        if matched {
            if let Some(entry) = build_entry(pid_num, system, users, true) {
                results.push(entry);
            }
        }
    }

    results
}

#[cfg(not(target_os = "linux"))]
fn heuristic_scan(path: &Path, system: &System, users: &Users) -> Vec<ProcessEntry> {
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if file_name.is_empty() {
        return Vec::new();
    }

    let mut results = Vec::new();

    for (pid, process) in system.processes() {
        let name_match = process.name().to_string_lossy().to_lowercase().contains(&file_name);
        let cmd_match = process
            .cmd()
            .iter()
            .any(|arg| arg.to_string_lossy().to_lowercase().contains(&file_name));

        if name_match || cmd_match {
            if let Some(entry) = build_entry(pid.as_u32(), system, users, false) {
                results.push(entry);
            }
        }
    }

    results
}

fn build_entry(
    pid_num: u32,
    system: &System,
    users: &Users,
    confirmed: bool,
) -> Option<ProcessEntry> {
    let pid = Pid::from_u32(pid_num);
    let process = system.process(pid)?;

    let user = process
        .user_id()
        .and_then(|uid| users.get_user_by_id(uid))
        .map(|u| u.name().to_string())
        .unwrap_or_else(|| "?".to_string());

    let status = process.status().to_string();

    let last_used = Local
        .timestamp_opt(process.start_time() as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "inconnu".to_string());

    Some(ProcessEntry {
        pid: pid_num,
        user,
        status,
        last_used,
        confirmed,
    })
}
