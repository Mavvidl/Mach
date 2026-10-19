use crate::process_info;
use crate::scan::{self, ReferenceEvidence};
use serde::Serialize;
use std::error::Error;
use std::path::{Path, PathBuf};

const CAVEAT: &str =
    "Une référence textuelle ou un nom de service candidat ne prouve pas une dépendance effective.";

#[derive(Debug, Serialize)]
struct Finding {
    kind: String,
    subject: String,
    evidence: String,
    confidence: &'static str,
    interpretation: String,
}

#[derive(Serialize)]
struct Consequence {
    scenario: String,
    assessment: String,
    confidence: &'static str,
}

#[derive(Serialize)]
struct ImpactReport {
    target: String,
    scan_roots: Vec<String>,
    skipped_scan_roots: Vec<String>,
    caveat: &'static str,
    findings: Vec<Finding>,
    possible_consequences: Vec<Consequence>,
}

pub fn analyze(path: &Path, scan_roots: &[PathBuf], json: bool) -> Result<(), Box<dyn Error>> {
    if !path.is_file() {
        return Err(format!(
            "la cible '{}' n'est pas un fichier accessible",
            path.display()
        )
        .into());
    }
    let target = path.canonicalize()?;
    let roots = if scan_roots.is_empty() {
        default_scan_roots()
    } else {
        scan_roots.to_vec()
    };
    let skipped_scan_roots: Vec<String> = roots
        .iter()
        .filter(|root| !root.is_dir())
        .map(|root| root.display().to_string())
        .collect();
    let existing_roots: Vec<PathBuf> = roots.iter().filter(|root| root.is_dir()).cloned().collect();
    let mut findings = Vec::new();

    for process in process_info::find_related_processes(&target) {
        let (confidence, evidence, interpretation) = if process.confirmed {
            (
                "élevé",
                format!("descripteur de fichier observé pour PID {}", process.pid),
                "Le processus avait le fichier ouvert au moment du contrôle.".to_string(),
            )
        } else {
            (
                "faible",
                format!(
                    "nom ou ligne de commande correspondant au nom du fichier (PID {})",
                    process.pid
                ),
                "Correspondance heuristique uniquement; aucune ouverture du fichier n'est prouvée."
                    .to_string(),
            )
        };
        findings.push(Finding {
            kind: "processus actif".to_string(),
            subject: format!("{} (pid {})", process.user, process.pid),
            evidence,
            confidence,
            interpretation,
        });
    }

    let references = scan::find_reference_evidence(&existing_roots, &target);
    for reference in references {
        findings.push(reference_finding(reference));
    }

    let consequences = vec![Consequence {
        scenario: "Modification, déplacement ou suppression".to_string(),
        assessment: if findings.is_empty() {
            "Aucune relation observable n'a été trouvée dans les processus contrôlés et les répertoires analysés. Cela ne prouve pas l'absence de consommateurs.".to_string()
        } else {
            "Un consommateur peut être affecté si la relation observée est effective; valider le comportement du consommateur avant toute modification.".to_string()
        },
        confidence: "faible; conséquences conditionnelles, aucune dépendance indispensable établie",
    }];
    let report = ImpactReport {
        target: target.display().to_string(),
        scan_roots: existing_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        skipped_scan_roots,
        caveat: CAVEAT,
        findings,
        possible_consequences: consequences,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Analyse d'impact : {}", report.target);
        println!(
            "Répertoires analysés : {}",
            if report.scan_roots.is_empty() {
                "aucun".to_string()
            } else {
                report.scan_roots.join(", ")
            }
        );
        if !report.skipped_scan_roots.is_empty() {
            println!(
                "Répertoires ignorés (absents ou inaccessibles) : {}",
                report.skipped_scan_roots.join(", ")
            );
        }
        println!("Précaution : {}", report.caveat);
        if report.findings.is_empty() {
            println!("Aucune relation observable trouvée.");
        }
        for finding in &report.findings {
            println!(
                "- [{}] {} — {} ({})",
                finding.kind, finding.subject, finding.evidence, finding.confidence
            );
            println!("  {}", finding.interpretation);
        }
        for consequence in &report.possible_consequences {
            println!(
                "Conséquence possible : {}. {} [{}]",
                consequence.scenario, consequence.assessment, consequence.confidence
            );
        }
    }
    Ok(())
}

fn reference_finding(reference: ReferenceEvidence) -> Finding {
    let extension = Path::new(&reference.source)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let (kind, confidence, interpretation) = if extension == "service" {
        (
            "service candidat",
            "faible",
            "Le fichier d'unité contient une mention; cela ne confirme ni chargement ni dépendance active." ,
        )
    } else if matches!(
        extension.as_str(),
        "sh" | "bash" | "zsh" | "py" | "rb" | "pl" | "ps1"
    ) {
        (
            "référence de script",
            if reference.exact_path { "modéré" } else { "faible" },
            "Le texte du script contient ce chemin ou ce nom; l'exécution de cette branche n'est pas prouvée." ,
        )
    } else if matches!(
        extension.as_str(),
        "conf" | "cfg" | "ini" | "yaml" | "yml" | "toml" | "json" | "xml"
    ) {
        (
            "référence de configuration",
            if reference.exact_path { "modéré" } else { "faible" },
            "Le texte de configuration contient ce chemin ou ce nom; cela ne prouve pas que l'application le consomme." ,
        )
    } else if reference.exact_path {
        (
            "référence de chemin",
            "modéré",
            "Le chemin littéral apparaît dans un fichier texte; une référence seule ne prouve pas l'usage." ,
        )
    } else {
        (
            "mention de nom",
            "faible",
            "Le nom apparaît dans un fichier texte; il peut s'agir d'une mention sans lien fonctionnel." ,
        )
    };
    Finding {
        kind: kind.to_string(),
        subject: reference.source,
        evidence: format!("ligne {} : {}", reference.line, reference.excerpt),
        confidence,
        interpretation: interpretation.to_string(),
    }
}

fn default_scan_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        [
            "/etc",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/usr/local/etc",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("ProgramData")
            .map(|path| vec![PathBuf::from(path)])
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::reference_finding;
    use crate::scan::ReferenceEvidence;

    #[test]
    fn service_mentions_are_never_reported_as_confirmed_dependencies() {
        let finding = reference_finding(ReferenceEvidence {
            source: "/etc/systemd/system/example.service".to_string(),
            line: 4,
            excerpt: "ExecStart=/usr/bin/example".to_string(),
            exact_path: true,
        });
        assert_eq!(finding.kind, "service candidat");
        assert_eq!(finding.confidence, "faible");
        assert!(finding.interpretation.contains("ne confirme"));
    }

    #[test]
    fn configuration_references_are_not_called_dependencies() {
        let finding = reference_finding(ReferenceEvidence {
            source: "/etc/example.conf".to_string(),
            line: 2,
            excerpt: "file=/var/lib/example.db".to_string(),
            exact_path: true,
        });
        assert_eq!(finding.kind, "référence de configuration");
        assert_eq!(finding.confidence, "modéré");
        assert!(finding.interpretation.contains("ne prouve pas"));
    }
}
