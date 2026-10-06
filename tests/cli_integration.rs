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
