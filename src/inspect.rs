use crate::anomaly::{self, AnomalyReport};
use crate::file_info;
use crate::graph::{self, GraphReport};
use crate::history::{self, Observation};
use crate::process_info::{self, ProcessEntry};
use crate::scan::{self, ReferenceEvidence};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct TypeSummary {
    extension: Option<String>,
    description: String,
    mime: Option<String>,
}

#[derive(Serialize)]
struct MetadataSummary {
    size: u64,
    permissions: Option<String>,
    owner: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct SourcedValue {
    value: String,
    source: &'static str,
    limitation: &'static str,
}

#[derive(Serialize)]
struct InspectionReport {
    target: String,
    scan_roots: Vec<String>,
    skipped_scan_roots: Vec<String>,
    file_type: TypeSummary,
    metadata: MetadataSummary,
    sha256: String,
    processes: Vec<ProcessEntry>,
    references: Vec<ReferenceEvidence>,
    last_accessed: Option<SourcedValue>,
    changes: Vec<Observation>,
    anomalies: AnomalyReport,
    graph: GraphReport,
    limitations: Vec<&'static str>,
}

pub fn analyze(
    path: &Path,
    scan_dirs: &[PathBuf],
    db_path: Option<&Path>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    if !path.is_file() {
        return Err(format!(
            "la cible '{}' n'est pas un fichier accessible",
            path.display()
        )
        .into());
    }
    let path = path.canonicalize()?;
    let scan_roots = if scan_dirs.is_empty() {
        vec![std::env::current_dir()?]
    } else {
        scan_dirs.to_vec()
    };
    let skipped_scan_roots: Vec<String> = scan_roots
        .iter()
        .filter(|root| !root.is_dir())
        .map(|root| root.display().to_string())
        .collect();
    let existing_scan_roots: Vec<_> = scan_roots
        .iter()
        .filter(|root| root.is_dir())
        .cloned()
        .collect();
    let info = file_info::analyze(&path)?;
    let metadata = fs::metadata(&path)?;
    let sha256 = fingerprint(&path)?;
    let processes = process_info::find_related_processes(&path);
    let references = scan::find_reference_evidence(&existing_scan_roots, &path);
    let changes = history::recorded_observations(&path, db_path)?;
    let anomalies = anomaly::create_report(&path, db_path)?;
    let graph = graph::build(&path, &scan_roots, db_path)?;
    let last_accessed = metadata.accessed().ok().map(|time| SourcedValue {
        value: chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339(),
        source: "métadonnée du système de fichiers",
        limitation: "Disponibilité et sémantique dépendantes du système de fichiers; ce n'est pas une preuve d'utilisation par un processus.",
    });
    let report = InspectionReport {
        target: path.display().to_string(),
        scan_roots: existing_scan_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        skipped_scan_roots,
        file_type: TypeSummary {
            extension: info.extension,
            description: info.description,
            mime: info.mime,
        },
        metadata: MetadataSummary {
            size: metadata.len(),
            permissions: permissions(&metadata),
            owner: owner(&metadata),
            modified_at: metadata
                .modified()
                .ok()
                .map(|time| chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339()),
        },
        sha256,
        processes,
        references,
        last_accessed,
        changes,
        anomalies,
        graph,
        limitations: vec![
            "Une inspection décrit un état ponctuel; les processus ou fichiers peuvent changer pendant la collecte.",
            "Les relations textuelles sont des indices et ne prouvent pas une dépendance effective.",
            "L'historique et les anomalies comparatives dépendent des observations locales déjà enregistrées.",
        ],
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Inspection : {}", report.target);
        println!(
            "Type : {} ({})",
            report.file_type.description,
            report
                .file_type
                .mime
                .as_deref()
                .unwrap_or("MIME indisponible")
        );
        println!("SHA-256 : {}", report.sha256);
        println!("Taille : {} octets", report.metadata.size);
        println!(
            "Permissions : {}",
            report
                .metadata
                .permissions
                .as_deref()
                .unwrap_or("indisponibles")
        );
        println!(
            "Propriétaire : {}",
            report.metadata.owner.as_deref().unwrap_or("indisponible")
        );
        println!("Processus associés : {}", report.processes.len());
        for process in &report.processes {
            println!(
                "- pid {} {} [{}]",
                process.pid,
                process.user,
                if process.confirmed {
                    "ouverture observée"
                } else {
                    "indice heuristique"
                }
            );
        }
        println!("Références : {}", report.references.len());
        for reference in &report.references {
            println!(
                "- {}:{} : {}",
                reference.source, reference.line, reference.excerpt
            );
        }
        println!("Racines analysées : {}", report.scan_roots.join(", "));
        for change in report
            .changes
            .iter()
            .filter(|change| change.change != "baseline")
        {
            println!(
                "Changement observé : {} | {}",
                change.observed_at, change.change
            );
        }
        if report.changes.is_empty() {
            println!("Historique : aucune observation disponible");
        }
        println!("Indicateurs d'anomalie :");
        for indicator in &report.anomalies.indicators {
            println!(
                "- [{}] {} : {}",
                indicator.status, indicator.category, indicator.evidence
            );
        }
        println!("Relations du graphe :");
        for relation in &report.graph.relations {
            println!(
                "- {} [{}; confiance {}] — {}",
                relation.kind, relation.nature, relation.confidence, relation.source
            );
        }
        if !report.skipped_scan_roots.is_empty() {
            println!(
                "Répertoires de scan ignorés : {}",
                report.skipped_scan_roots.join(", ")
            );
        }
        if let Some(last_accessed) = report.last_accessed {
            println!(
                "Dernier accès FS : {} ({})",
                last_accessed.value, last_accessed.source
            );
        } else {
            println!("Dernier accès FS : indisponible");
        }
        for limitation in report.limitations {
            println!("Limite : {limitation}");
        }
        for criterion in report.anomalies.unavailable_criteria {
            println!("Critère d'anomalie non évalué : {criterion}");
        }
    }
    Ok(())
}

fn fingerprint(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = fs::File::open(path)?;
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
        return Err("fichier modifié pendant le calcul de l'empreinte".into());
    }
    Ok(format!("{:x}", digest.finalize()))
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
