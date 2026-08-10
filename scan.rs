use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Taille max de fichier lue pendant le scan (évite de charger des gros binaires/logs en RAM)
const MAX_SCAN_BYTES: u64 = 5 * 1024 * 1024; // 5 Mo

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
