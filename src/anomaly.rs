use crate::history::{self, Observation};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::Path;

const LIMITATION: &str = "Une anomalie est un écart vérifiable, pas une preuve d'activité malveillante. La comparaison ne couvre que les observations locales conservées.";

#[derive(Debug, Serialize)]
pub struct Indicator {
    pub category: String,
    pub status: &'static str,
    pub evidence: String,
    pub observed_at: Option<String>,
    pub confidence: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AnomalyReport {
    pub target: String,
    pub baseline: Option<Observation>,
    pub indicators: Vec<Indicator>,
    pub assessment: &'static str,
    pub limitation: &'static str,
    pub unavailable_criteria: Vec<&'static str>,
}

pub fn create_report(path: &Path, db_path: Option<&Path>) -> Result<AnomalyReport, Box<dyn Error>> {
    if !path.is_file() {
        return Err(format!(
            "la cible '{}' n'est pas un fichier accessible",
            path.display()
        )
        .into());
    }
    let path = path.canonicalize()?;
    let observations = history::recorded_observations(&path, db_path)?;
    let baseline = observations
        .iter()
        .rev()
        .find(|observation| observation.present)
        .cloned();
    let mut indicators = Vec::new();

    if let Some(baseline) = &baseline {
        let (current_hash, metadata) = fingerprint(&path)?;
        compare_value(
            &mut indicators,
            "empreinte SHA-256",
            baseline.sha256.as_deref(),
            Some(&current_hash),
            baseline,
        );
        compare_value(
            &mut indicators,
            "taille",
            baseline.size.map(|size| size.to_string()).as_deref(),
            Some(&metadata.len().to_string()),
            baseline,
        );
        compare_value(
            &mut indicators,
            "permissions",
            baseline.permissions.as_deref(),
            permissions(&metadata).as_deref(),
            baseline,
        );
        compare_value(
            &mut indicators,
            "propriétaire",
            baseline.owner.as_deref(),
            owner(&metadata).as_deref(),
            baseline,
        );
        compare_value(
            &mut indicators,
            "date de modification",
            baseline.modified_at.as_deref(),
            modified_at(&metadata).as_deref(),
            baseline,
        );
        if baseline.change == "apparition observée au polling" {
            indicators.push(Indicator {
                category: "nouvelle apparition dans la zone surveillée".to_string(),
                status: "fait observé",
                evidence: "fichier vu pour la première fois lors d'un passage après l'instantané initial; la date de création n'est pas connue".to_string(),
                observed_at: Some(baseline.observed_at.clone()),
                confidence: "élevé",
            });
        }
        if let Some(absence) = observations
            .last()
            .filter(|observation| !observation.present)
        {
            indicators.push(Indicator {
                category: "réapparition après absence observée".to_string(),
                status: "fait observé",
                evidence: format!(
                    "fichier de nouveau accessible; absence observée le {}",
                    absence.observed_at
                ),
                observed_at: Some(absence.observed_at.clone()),
                confidence: "élevé",
            });
        }
    } else {
        indicators.push(Indicator {
            category: "référence historique absente".to_string(),
            status: "limite de collecte",
            evidence: "aucun instantané antérieur disponible; aucune comparaison de changement n'est possible".to_string(),
            observed_at: None,
            confidence: "élevé",
        });
    }

    if executable_in_volatile_location(&path) {
        indicators.push(Indicator {
            category: "emplacement d'exécutable inhabituel".to_string(),
            status: "hypothèse à examiner",
            evidence: format!(
                "fichier exécutable situé dans un emplacement volatil : {}",
                path.display()
            ),
            observed_at: None,
            confidence: "faible",
        });
    }

    if indicators.is_empty() {
        indicators.push(Indicator {
            category: "aucun écart détecté".to_string(),
            status: "observation limitée",
            evidence:
                "aucun des critères implémentés ne diffère de la dernière référence enregistrée"
                    .to_string(),
            observed_at: baseline
                .as_ref()
                .map(|observation| observation.observed_at.clone()),
            confidence: "modéré",
        });
    }

    Ok(AnomalyReport {
        target: path.display().to_string(),
        baseline,
        indicators,
        assessment: "Aucun verdict de compromission n'est émis; examiner chaque indicateur dans son contexte.",
        limitation: LIMITATION,
        unavailable_criteria: vec![
            "Les relations aux processus, scripts et configurations ne sont pas évaluées comme inhabituelles : aucune référence comportementale approuvée n'est définie.",
            "L'indicateur d'emplacement exécutable est une heuristique limitée aux emplacements volatils connus sous Unix.",
        ],
    })
}

pub fn analyze(path: &Path, db_path: Option<&Path>, json: bool) -> Result<(), Box<dyn Error>> {
    let report = create_report(path, db_path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Analyse d'anomalies : {}", report.target);
        println!("Limite : {}", report.limitation);
        for indicator in report.indicators {
            println!(
                "- [{}] {} ({})",
                indicator.status, indicator.category, indicator.confidence
            );
            println!("  {}", indicator.evidence);
            if let Some(observed_at) = indicator.observed_at {
                println!("  Référence observée : {observed_at}");
            }
        }
        println!("Évaluation : {}", report.assessment);
    }
    Ok(())
}

fn compare_value(
    indicators: &mut Vec<Indicator>,
    category: &str,
    baseline: Option<&str>,
    current: Option<&str>,
    observation: &Observation,
) {
    match (baseline, current) {
        (Some(baseline), Some(current)) if baseline == current => {}
        (Some(baseline), Some(current)) => indicators.push(Indicator {
            category: category.to_string(),
            status: "fait observé",
            evidence: format!("référence : {baseline}; valeur actuelle : {current}"),
            observed_at: Some(observation.observed_at.clone()),
            confidence: "élevé",
        }),
        _ => indicators.push(Indicator {
            category: category.to_string(),
            status: "limite de collecte",
            evidence:
                "comparaison impossible : valeur de référence ou valeur actuelle indisponible"
                    .to_string(),
            observed_at: Some(observation.observed_at.clone()),
            confidence: "élevé",
        }),
    }
}

fn modified_at(metadata: &fs::Metadata) -> Option<String> {
    let duration = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let milliseconds = i64::try_from(duration.as_millis()).ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(milliseconds)
        .map(|time| time.to_rfc3339())
}

fn fingerprint(path: &Path) -> Result<(String, fs::Metadata), Box<dyn Error>> {
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
    Ok((format!("{:x}", digest.finalize()), metadata))
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

fn executable_in_volatile_location(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let is_executable = fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
        let path = path.to_string_lossy();
        let volatile_location = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"]
            .iter()
            .any(|prefix| path.starts_with(prefix));
        is_executable && volatile_location
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{create_report, AnomalyReport};
    use crate::history::{observe_file, open_database};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn reports_hash_divergence_against_recorded_baseline() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("mach-anomaly-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("sample.txt");
        let db = directory.join("history.sqlite3");
        fs::write(&path, "known content").unwrap();
        let connection = open_database(&db).unwrap();
        observe_file(&connection, &path, "test").unwrap();
        drop(connection);

        fs::write(&path, "changed content").unwrap();
        let report: AnomalyReport = create_report(&path, Some(&db)).unwrap();
        assert!(report.indicators.iter().any(|indicator| {
            indicator.category == "empreinte SHA-256" && indicator.status == "fait observé"
        }));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn does_not_claim_to_compare_without_a_baseline() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("mach-no-baseline-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("sample.txt");
        fs::write(&path, "unknown history").unwrap();
        let report = create_report(&path, Some(&directory.join("empty.sqlite3"))).unwrap();
        assert!(report
            .indicators
            .iter()
            .any(|indicator| indicator.status == "limite de collecte"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reports_only_observed_appearance_without_claiming_creation_time() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("mach-appearance-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("new.conf");
        let db = directory.join("history.sqlite3");
        fs::write(&path, "new file").unwrap();
        let connection = open_database(&db).unwrap();
        observe_file(&connection, &path, "watch:polling").unwrap();
        drop(connection);

        let report = create_report(&path, Some(&db)).unwrap();
        let indicator = report
            .indicators
            .iter()
            .find(|indicator| indicator.category == "nouvelle apparition dans la zone surveillée")
            .unwrap();
        assert_eq!(indicator.status, "fait observé");
        assert!(indicator
            .evidence
            .contains("date de création n'est pas connue"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reports_permission_divergence_separately_from_content() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("mach-permissions-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("mode.conf");
        let db = directory.join("history.sqlite3");
        fs::write(&path, "same content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let connection = open_database(&db).unwrap();
        observe_file(&connection, &path, "test").unwrap();
        drop(connection);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let report = create_report(&path, Some(&db)).unwrap();
        assert!(report.indicators.iter().any(|indicator| {
            indicator.category == "permissions" && indicator.status == "fait observé"
        }));
        assert!(!report
            .indicators
            .iter()
            .any(|indicator| { indicator.category == "empreinte SHA-256" }));

        fs::remove_dir_all(directory).unwrap();
    }
}
