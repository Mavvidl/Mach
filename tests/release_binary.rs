use std::path::Path;
use std::process::Command;

#[test]
fn release_binary_should_exist_and_run() {
    let path = if cfg!(windows) {
        Path::new("target/release/mach.exe")
    } else {
        Path::new("target/release/mach")
    };

    assert!(
        path.exists(),
        "Le binaire release doit exister à {:?}",
        path
    );

    let output = Command::new(path)
        .output()
        .expect("impossible d’exécuter le binaire release");

    assert!(
        !output.status.success(),
        "Le lancement sans fichier doit échouer, mais il doit afficher le logo ASCII avant l’erreur"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("MACH"),
        "Le binaire doit afficher le logo ASCII au lancement. Sortie observée : {}",
        stdout
    );
}
