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
        .arg("--help")
        .output()
        .expect("impossible d’exécuter le binaire release");

    assert!(
        output.status.success(),
        "Le binaire release ne s’exécute pas correctement : {:?}",
        output
    );
}
