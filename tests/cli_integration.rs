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

#[test]
fn inspect_combines_sources_and_discloses_missing_anomaly_baseline() {
    let directory = unique_temp_file().with_extension("inspect");
    fs::create_dir_all(&directory).expect("impossible de créer le répertoire temporaire");
    let target = directory.join("settings.ini");
    let reference = directory.join("application.conf");
    let database = directory.join("history.sqlite3");
    fs::write(&target, "enabled=true\n").unwrap();
    fs::write(&reference, format!("config_path={}\n", target.display())).unwrap();

    let target_arg = target.to_string_lossy();
    let directory_arg = directory.to_string_lossy();
    let database_arg = database.to_string_lossy();
    let missing_scan_arg = directory
        .join("missing-scan-root")
        .to_string_lossy()
        .into_owned();
    let output = run_mach(&[
        "inspect",
        target_arg.as_ref(),
        "--scan",
        directory_arg.as_ref(),
        &missing_scan_arg,
        "--db",
        database_arg.as_ref(),
        "--json",
    ]);
    fs::remove_dir_all(&directory).expect("impossible de supprimer le répertoire temporaire");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout.find('{').expect("JSON absent de la sortie");
    let result: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("sortie JSON invalide");
    assert_eq!(result["file_type"]["extension"], "ini");
    assert_eq!(result["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(result["references"].as_array().unwrap().len(), 1);
    assert_eq!(result["skipped_scan_roots"][0], missing_scan_arg.as_str());
    assert_eq!(
        result["graph"]["skipped_scan_roots"][0],
        missing_scan_arg.as_str()
    );
    assert!(result["graph"]["relations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|relation| {
            relation["kind"] == "référencé dans" && relation["nature"] == "déduite"
        }));
    assert!(result["anomalies"]["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .any(|indicator| { indicator["status"] == "limite de collecte" }));
    assert!(!result["limitations"].as_array().unwrap().is_empty());
}

#[test]
fn anomaly_command_without_history_does_not_infer_a_change() {
    let directory = unique_temp_file().with_extension("anomaly");
    fs::create_dir_all(&directory).expect("impossible de créer le répertoire temporaire");
    let target = directory.join("new-file.conf");
    let database = directory.join("history.sqlite3");
    fs::write(&target, "new file\n").unwrap();

    let target_arg = target.to_string_lossy();
    let database_arg = database.to_string_lossy();
    let output = run_mach(&[
        "anomaly",
        target_arg.as_ref(),
        "--db",
        database_arg.as_ref(),
        "--json",
    ]);
    fs::remove_dir_all(&directory).expect("impossible de supprimer le répertoire temporaire");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout.find('{').expect("JSON absent de la sortie");
    let result: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("sortie JSON invalide");
    assert!(result["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .any(|indicator| { indicator["category"] == "référence historique absente" }));
    assert!(result["assessment"]
        .as_str()
        .unwrap()
        .contains("Aucun verdict"));
}

#[test]
fn who_refs_and_graph_commands_return_structured_results() {
    let directory = unique_temp_file().with_extension("relations");
    fs::create_dir_all(&directory).expect("impossible de créer le répertoire temporaire");
    let target = directory.join("agent.conf");
    let reference = directory.join("service.conf");
    let database = directory.join("history.sqlite3");
    fs::write(&target, "agent\n").unwrap();
    fs::write(&reference, format!("agent_path={}\n", target.display())).unwrap();
    let target_arg = target.to_string_lossy();
    let directory_arg = directory.to_string_lossy();
    let database_arg = database.to_string_lossy();

    let who = run_mach(&["who", target_arg.as_ref(), "--json"]);
    assert!(who.status.success());
    let who_json = String::from_utf8_lossy(&who.stdout);
    assert!(serde_json::from_str::<serde_json::Value>(&who_json)
        .expect("JSON who invalide")
        .is_array());

    let refs = run_mach(&[
        "refs",
        target_arg.as_ref(),
        "--scan",
        directory_arg.as_ref(),
        "--json",
    ]);
    assert!(refs.status.success());
    let refs_json = String::from_utf8_lossy(&refs.stdout);
    let refs: serde_json::Value = serde_json::from_str(&refs_json).expect("JSON refs invalide");
    assert_eq!(refs["references"].as_array().unwrap().len(), 1);

    let graph = run_mach(&[
        "graph",
        target_arg.as_ref(),
        "--scan",
        directory_arg.as_ref(),
        "--db",
        database_arg.as_ref(),
        "--json",
    ]);
    fs::remove_dir_all(&directory).expect("impossible de supprimer le répertoire temporaire");
    assert!(graph.status.success());
    let graph_json = String::from_utf8_lossy(&graph.stdout);
    let graph: serde_json::Value = serde_json::from_str(&graph_json).expect("JSON graph invalide");
    assert!(graph["relations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|relation| {
            relation["kind"] == "référencé dans"
                && relation["source"].as_str().unwrap().contains("ligne 1")
        }));
}
