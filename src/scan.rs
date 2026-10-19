use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Taille max de fichier lue pendant le scan (évite de charger des gros binaires/logs en RAM)
const MAX_SCAN_BYTES: u64 = 5 * 1024 * 1024; // 5 Mo

#[derive(Debug, Clone)]
pub struct ReferenceEvidence {
    pub source: String,
    pub line: usize,
    pub excerpt: String,
    pub exact_path: bool,
}

/// Parcourt `dirs` à la recherche de fichiers texte qui mentionnent `file_name`
/// (nom du fichier cible, éventuellement son chemin complet).
///
/// Retourne la liste des chemins des fichiers qui en font référence — typiquement
/// des fichiers de config (`sshd_config`), des logs (`auth.log`), des scripts, etc.
pub fn find_references(dirs: &[String], target: &Path) -> Vec<String> {
    let file_name = match target.file_name().map(|f| f.to_string_lossy().to_string()) {
        Some(n) if !n.is_empty() => n,
        _ => return Vec::new(),
    };

    // Échappe le nom pour l'utiliser tel quel dans une regex (les noms de
    // fichiers contiennent souvent des `.` qui ne doivent pas être des jokers)
    let pattern = regex::escape(&file_name);
    let re = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut matches = Vec::new();

    for dir in dirs {
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            // Ne pas se re-signaler soi-même si le fichier cible est dans le
            // répertoire scanné
            if entry.path() == target {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > MAX_SCAN_BYTES {
                continue;
            }

            if let Ok(content) = fs::read_to_string(entry.path()) {
                if re.is_match(&content) {
                    matches.push(entry.path().display().to_string());
                }
            }
            // Les fichiers non-UTF8 (binaires) sont silencieusement ignorés :
            // on cherche des références textuelles (config, logs, scripts).
        }
    }

    matches
}

/// Retourne des références textuelles avec leur ligne et leur niveau de précision.
/// Une mention textuelle est un indice, pas une preuve de dépendance à l'exécution.
pub fn find_reference_evidence(dirs: &[PathBuf], target: &Path) -> Vec<ReferenceEvidence> {
    let canonical_target = target.canonicalize().ok();
    let target_path = match target.canonicalize() {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => target.to_string_lossy().into_owned(),
    };
    let file_name = match target
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
    {
        Some(name) if !name.is_empty() => name,
        _ => return Vec::new(),
    };
    let target_path_normalized = target_path.replace('\\', "/");
    let mut matches = Vec::new();

    for dir in dirs {
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let is_target = canonical_target.as_ref().is_some_and(|target| {
                entry
                    .path()
                    .canonicalize()
                    .map(|entry_path| &entry_path == target)
                    .unwrap_or(false)
            });
            if !entry.file_type().is_file() || is_target {
                continue;
            }
            if entry
                .metadata()
                .map(|metadata| metadata.len() > MAX_SCAN_BYTES)
                .unwrap_or(true)
            {
                continue;
            }
            let content = match fs::read_to_string(entry.path()) {
                Ok(content) => content,
                Err(_) => continue,
            };
            for (index, line) in content.lines().enumerate() {
                let normalized_line = line.replace('\\', "/");
                let exact_path = normalized_line.contains(&target_path_normalized);
                if exact_path || line.contains(&file_name) {
                    let excerpt = line.trim().chars().take(240).collect::<String>();
                    matches.push(ReferenceEvidence {
                        source: entry.path().display().to_string(),
                        line: index + 1,
                        excerpt,
                        exact_path,
                    });
                }
            }
        }
    }
    matches
}
