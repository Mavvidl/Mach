use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn run_mach(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mach"))
        .args(args)
        .output()
        .expect("impossible de lancer le binaire mach")
}

fn unique_temp_file() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("l'horloge système doit être après l'époque Unix")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mach-integration-{}-{nonce}.txt",
        std::process::id()
    ))
}

#[test]
fn help_displays_cli_options() {
    let output = run_mach(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--file"), "Sortie observée : {stdout}");
    assert!(stdout.contains("--type"), "Sortie observée : {stdout}");
}

#[test]
fn missing_file_returns_an_error() {
    let missing_file = unique_temp_file();
    let path = missing_file.to_string_lossy();
    let output = run_mach(&[path.as_ref()]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("n'existe pas"),
        "Sortie observée : {stderr}"
    );
}

#[test]
fn existing_file_returns_type_as_json() {
    let file = unique_temp_file();
    fs::write(&file, "integration test content")
        .expect("impossible de créer le fichier temporaire");

    let path = file.to_string_lossy();
    let output = run_mach(&["--type", "--json", path.as_ref()]);
    fs::remove_file(&file).expect("impossible de supprimer le fichier temporaire");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout.find('{').expect("JSON absent de la sortie");
    let result: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("sortie JSON invalide");

    assert_eq!(result["file"], path.as_ref());
    assert_eq!(result["extension"], "txt");
    assert!(result["type"].as_str().is_some());
}

#[test]
fn text_source_file_uses_specific_extension_type() {
    let file = unique_temp_file().with_extension("rs");
    fs::write(&file, "fn main() {}").expect("impossible de créer le fichier temporaire");

    let path = file.to_string_lossy();
    let output = run_mach(&["--type", "--json", path.as_ref()]);
    fs::remove_file(&file).expect("impossible de supprimer le fichier temporaire");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout.find('{').expect("JSON absent de la sortie");
    let result: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("sortie JSON invalide");

    assert_eq!(result["type"], "fichier source Rust");
    assert_eq!(result["mime"], "text/plain");
}

#[test]
fn impact_reports_line_evidence_and_cautious_service_candidates() {
    let directory = unique_temp_file().with_extension("impact");
    fs::create_dir_all(&directory).expect("impossible de créer le répertoire temporaire");
    let target = directory.join("target.conf");
    let config = directory.join("app.conf");
    let service = directory.join("app.service");
    fs::write(&target, "target data").unwrap();
    fs::write(&config, format!("data_file={}\n", target.display())).unwrap();
    fs::write(&service, format!("ExecStart={}\n", target.display())).unwrap();

    let target_arg = target.to_string_lossy();
    let directory_arg = directory.to_string_lossy();
    let output = run_mach(&[
        "impact",
        target_arg.as_ref(),
        "--scan",
        directory_arg.as_ref(),
        "--json",
    ]);
    fs::remove_dir_all(&directory).expect("impossible de supprimer le répertoire temporaire");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout.find('{').expect("JSON absent de la sortie");
    let result: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("sortie JSON invalide");
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| {
            finding["kind"] == "référence de configuration"
                && finding["evidence"].as_str().unwrap().contains("ligne 1")
        }));
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| {
            finding["kind"] == "service candidat"
                && finding["confidence"] == "faible"
                && finding["interpretation"]
                    .as_str()
                    .unwrap()
                    .contains("ne confirme")
        }));
}

#[test]
fn history_command_discloses_observation_coverage() {
    let base = unique_temp_file().with_extension("history");
    fs::create_dir_all(&base).expect("impossible de créer le répertoire temporaire");
    let target = base.join("target.conf");
    let database = base.join("history.sqlite3");
    fs::write(&target, "history target").unwrap();

    let target_arg = target.to_string_lossy();
    let database_arg = database.to_string_lossy();
    let output = run_mach(&[
        "history",
        target_arg.as_ref(),
        "--db",
        database_arg.as_ref(),
        "--json",
    ]);
    fs::remove_dir_all(&base).expect("impossible de supprimer le répertoire temporaire");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout.find('{').expect("JSON absent de la sortie");
    let result: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("sortie JSON invalide");
    assert!(result["coverage"]
        .as_str()
        .unwrap()
        .contains("depuis l'activation"));
    assert_eq!(result["observations"].as_array().unwrap().len(), 0);
}
