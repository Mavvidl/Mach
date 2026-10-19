use crate::history::{self, Observation};
use crate::process_info;
use crate::scan::{self, ReferenceEvidence};
use chrono::Utc;
use serde::Serialize;
use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

const LIMITATIONS: &[&str] = &[
    "Les références textuelles ne prouvent pas l'utilisation effective d'un fichier.",
    "Les événements reflètent uniquement les instantanés conservés localement depuis l'activation de watch.",
    "Les relations aux processus dépendent des permissions et du mécanisme disponible sur l'OS.",
];

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Relation {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub source: String,
    pub observed_at: String,
    pub confidence: &'static str,
    pub nature: &'static str,
    pub limitation: String,
}

#[derive(Debug, Serialize)]
pub struct GraphReport {
    pub target: String,
    pub scan_roots: Vec<String>,
    pub skipped_scan_roots: Vec<String>,
    pub nodes: Vec<Node>,
    pub relations: Vec<Relation>,
    pub limitations: Vec<&'static str>,
}

pub fn build(
    path: &Path,
    scan_roots: &[PathBuf],
    db_path: Option<&Path>,
) -> Result<GraphReport, Box<dyn Error>> {
    if !path.is_file() {
        return Err(format!(
            "la cible '{}' n'est pas un fichier accessible",
            path.display()
        )
        .into());
    }
    let target = path.canonicalize()?;
    let skipped_scan_roots: Vec<String> = scan_roots
        .iter()
        .filter(|root| !root.is_dir())
        .map(|root| root.display().to_string())
        .collect();
    let existing_roots: Vec<PathBuf> = scan_roots
        .iter()
        .filter(|root| root.is_dir())
        .cloned()
        .collect();
    let target_id = target.to_string_lossy().into_owned();
    let now = Utc::now().to_rfc3339();
    let mut nodes = BTreeMap::new();
    let mut relations = Vec::new();
    insert_node(&mut nodes, &target_id, "fichier", &target_id);

    for process in process_info::find_related_processes(&target) {
        let process_id = format!("process:{}", process.pid);
        insert_node(
            &mut nodes,
            &process_id,
            "processus",
            &format!("{} (pid {})", process.user, process.pid),
        );
        relations.push(Relation {
            from: target_id.clone(),
            to: process_id,
            kind: "ouvert par".to_string(),
            source: if process.confirmed {
                "descripteur observé dans /proc".to_string()
            } else {
                "correspondance heuristique du nom ou de la commande".to_string()
            },
            observed_at: now.clone(),
            confidence: if process.confirmed { "élevé" } else { "faible" },
            nature: if process.confirmed { "directe" } else { "déduite" },
            limitation: if process.confirmed {
                "Le descripteur prouve une ouverture au moment du contrôle, pas une dépendance permanente.".to_string()
            } else {
                "La correspondance n'établit pas que le processus a ouvert le fichier.".to_string()
            },
        });
    }

    for reference in scan::find_reference_evidence(&existing_roots, &target) {
        add_reference(&mut nodes, &mut relations, &target_id, reference, &now);
    }

    for observation in history::recorded_observations(&target, db_path)? {
        if observation.change == "baseline" {
            continue;
        }
        add_event(&mut nodes, &mut relations, &target_id, observation);
    }

    Ok(GraphReport {
        target: target_id,
        scan_roots: existing_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        skipped_scan_roots,
        nodes: nodes.into_values().collect(),
        relations,
        limitations: LIMITATIONS.to_vec(),
    })
}

pub fn analyze(
    path: &Path,
    scan_roots: &[PathBuf],
    db_path: Option<&Path>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let report = build(path, scan_roots, db_path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Graphe de relations : {}", report.target);
        println!("Racines analysées : {}", report.scan_roots.join(", "));
        if !report.skipped_scan_roots.is_empty() {
            println!(
                "Racines ignorées : {}",
                report.skipped_scan_roots.join(", ")
            );
        }
        for relation in &report.relations {
            println!(
                "- {} {} [{}; confiance {}]",
                relation.from, relation.kind, relation.to, relation.confidence
            );
            println!(
                "  Source : {} ({}, {})",
                relation.source, relation.nature, relation.observed_at
            );
            println!("  Limite : {}", relation.limitation);
        }
        if report.relations.is_empty() {
            println!("Aucune relation observable avec les sources sélectionnées.");
        }
        println!("Limites : {}", report.limitations.join(" "));
    }
    Ok(())
}

fn insert_node(nodes: &mut BTreeMap<String, Node>, id: &str, kind: &str, label: &str) {
    nodes.entry(id.to_string()).or_insert_with(|| Node {
        id: id.to_string(),
        kind: kind.to_string(),
        label: label.to_string(),
    });
}

fn add_reference(
    nodes: &mut BTreeMap<String, Node>,
    relations: &mut Vec<Relation>,
    target_id: &str,
    reference: ReferenceEvidence,
    observed_at: &str,
) {
    let source_path = Path::new(&reference.source);
    let extension = source_path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let (node_kind, relation_kind) = if extension == "service" {
        ("service candidat", "mentionné dans")
    } else if matches!(extension.as_str(), "log" | "journal") {
        ("journal", "mentionné dans")
    } else if matches!(
        extension.as_str(),
        "sh" | "bash" | "zsh" | "py" | "rb" | "pl" | "ps1"
    ) {
        ("script", "référencé dans")
    } else {
        ("configuration ou texte", "référencé dans")
    };
    let source_id = format!("source:{}", reference.source);
    insert_node(nodes, &source_id, node_kind, &reference.source);
    let exact = reference.exact_path;
    relations.push(Relation {
        from: target_id.to_string(),
        to: source_id,
        kind: relation_kind.to_string(),
        source: format!("{} ligne {} : {}", reference.source, reference.line, reference.excerpt),
        observed_at: observed_at.to_string(),
        confidence: if exact { "modéré" } else { "faible" },
        nature: "déduite",
        limitation: if extension == "service" {
            "Une mention dans une unité ne prouve ni son chargement ni une dépendance active.".to_string()
        } else if exact {
            "La ligne contient le chemin littéral, sans preuve que l'application consomme cette valeur.".to_string()
        } else {
            "Seul le nom du fichier correspond; la mention peut être fortuite.".to_string()
        },
    });
}

fn add_event(
    nodes: &mut BTreeMap<String, Node>,
    relations: &mut Vec<Relation>,
    target_id: &str,
    observation: Observation,
) {
    let event_id = format!("event:{}@{}", observation.path, observation.observed_at);
    let event_label = format!("{} : {}", observation.change, observation.observed_at);
    insert_node(nodes, &event_id, "événement observé", &event_label);
    relations.push(Relation {
        from: target_id.to_string(),
        to: event_id,
        kind: "modifié lors de".to_string(),
        source: format!("base SQLite locale ({})", observation.provenance),
        observed_at: observation.observed_at,
        confidence: "élevé",
        nature: "directe",
        limitation: "L'événement marque deux états observés; l'heure et la cause exactes du changement entre eux sont inconnues.".to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::{add_event, add_reference, GraphReport};
    use crate::history::Observation;
    use crate::scan::ReferenceEvidence;
    use std::collections::BTreeMap;

    #[test]
    fn labels_service_links_as_inferred_with_a_limit() {
        let mut nodes = BTreeMap::new();
        let mut relations = Vec::new();
        add_reference(
            &mut nodes,
            &mut relations,
            "/etc/ssh/sshd_config",
            ReferenceEvidence {
                source: "/etc/systemd/system/sshd.service".to_string(),
                line: 5,
                excerpt: "ExecStart=/usr/sbin/sshd -f /etc/ssh/sshd_config".to_string(),
                exact_path: true,
            },
            "2026-10-19T00:00:00Z",
        );
        assert_eq!(relations[0].nature, "déduite");
        assert_eq!(relations[0].confidence, "modéré");
        assert!(relations[0].limitation.contains("ne prouve"));
    }

    #[test]
    fn graph_report_has_a_serializable_shape() {
        let report = GraphReport {
            target: "/tmp/a".to_string(),
            scan_roots: Vec::new(),
            skipped_scan_roots: Vec::new(),
            nodes: Vec::new(),
            relations: Vec::new(),
            limitations: vec!["limit"],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("limitations"));
    }

    #[test]
    fn history_event_is_direct_and_keeps_its_provenance() {
        let observation = Observation {
            path: "/etc/example.conf".to_string(),
            observed_at: "2026-10-19T12:00:00+00:00".to_string(),
            sha256: Some("abc".to_string()),
            size: Some(3),
            permissions: Some("644".to_string()),
            owner: Some("uid:1000 gid:1000".to_string()),
            modified_at: None,
            provenance: "watch:polling".to_string(),
            change: "modification : contenu (SHA-256)".to_string(),
            present: true,
        };
        let mut nodes = BTreeMap::new();
        let mut relations = Vec::new();
        add_event(&mut nodes, &mut relations, "/etc/example.conf", observation);
        assert_eq!(relations[0].nature, "directe");
        assert_eq!(relations[0].confidence, "élevé");
        assert!(relations[0].source.contains("watch:polling"));
        assert!(relations[0]
            .limitation
            .contains("heure et la cause exactes"));
    }
}
