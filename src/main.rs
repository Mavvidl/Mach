mod anomaly;
mod cli;
mod file_info;
mod graph;
mod history;
mod impact;
mod inspect;
mod output;
mod process_info;
mod scan;
mod usage;

use clap::Parser;
use cli::Cli;
use output::MachOutput;
use std::path::Path;
use std::process::ExitCode;

const ASCII_ART: &str = r#"
███╗   ███╗ █████╗  ██████╗██╗  ██╗
████╗ ████║██╔══██╗██╔════╝██║  ██║
██╔████╔██║███████║██║     ███████║
██║╚██╔╝██║██╔══██║██║     ██╔══██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
"#;

fn print_ascii_art() {
    println!("{ASCII_ART}\n");
    println!("By Maverick, 2024. Licensed under MIT.");
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.command.is_none() && !cli.json {
        print_ascii_art();
    }

    if let Some(command) = cli.command {
        return match command {
            cli::Commands::Inspect {
                path,
                scan_dirs,
                db,
                json,
            } => run_command(inspect::analyze(&path, &scan_dirs, db.as_deref(), json)),
            cli::Commands::Who { path, json } => run_command(run_who(&path, json)),
            cli::Commands::Refs {
                path,
                scan_dirs,
                json,
            } => run_command(run_refs(&path, &scan_dirs, json)),
            cli::Commands::Anomaly { path, db, json } => {
                run_command(anomaly::analyze(&path, db.as_deref(), json))
            }
            cli::Commands::Graph {
                path,
                scan_dirs,
                db,
                json,
            } => run_command(graph::analyze(&path, &scan_dirs, db.as_deref(), json)),
            cli::Commands::Watch {
                path,
                interval,
                db,
                json,
            } => run_command(history::watch(&path, db.as_deref(), interval, json)),
            cli::Commands::History { path, db, json } => {
                run_command(history::show_history(&path, db.as_deref(), json))
            }
            cli::Commands::Diff { since, db, json } => {
                run_command(history::show_diff(&since, db.as_deref(), json))
            }
            cli::Commands::Impact {
                path,
                scan_dirs,
                json,
            } => run_command(impact::analyze(&path, &scan_dirs, json)),
        };
    }

    let file_path = match cli.target_file() {
        Some(f) => f,
        None => {
            eprintln!(
                "Erreur : aucun fichier spécifié. Utilise `mach <fichier>` ou `-f <fichier>`."
            );
            return ExitCode::FAILURE;
        }
    };

    let path = Path::new(&file_path);
    if !path.exists() {
        eprintln!("Erreur : le fichier '{file_path}' n'existe pas.");
        return ExitCode::FAILURE;
    }

    let (want_type, want_process, want_usage, want_calls) = cli.effective_flags();

    let mut out = MachOutput {
        file: file_path.clone(),
        ..Default::default()
    };

    // --type
    if want_type {
        match file_info::analyze(path) {
            Ok(info) => {
                out.extension = info.extension;
                out.extension_description = info.extension_description;
                out.file_type = Some(info.description);
                out.mime = info.mime;
            }
            Err(e) => eprintln!("Avertissement : analyse du type impossible ({e})"),
        }
    }

    // --process (nécessaire aussi pour --usage, qui s'en sert pour décrire l'usage)
    let related_processes = if want_process || want_usage {
        process_info::find_related_processes(path)
    } else {
        Vec::new()
    };

    if want_process {
        out.processes = Some(related_processes.clone());
    }

    // --usage
    if want_usage {
        let u = usage::analyze(path, &related_processes);
        out.usage = Some(u.description);
        out.last_accessed = u.last_accessed;
        out.last_modified = u.last_modified;
        out.currently_in_use = Some(u.currently_in_use);
    }

    // --call (implique un scan des répertoires fournis via -s/--scan ;
    // si aucun n'est fourni, on scanne le répertoire courant par défaut)
    if want_calls {
        let dirs = if cli.scan_dirs.is_empty() {
            vec![".".to_string()]
        } else {
            cli.scan_dirs.clone()
        };
        out.calls = Some(scan::find_references(&dirs, path));
    } else if !cli.scan_dirs.is_empty() {
        // -s fourni sans -c : on scanne quand même et on l'affiche sous "calls"
        out.calls = Some(scan::find_references(&cli.scan_dirs, path));
    }

    out.print(cli.json);

    ExitCode::SUCCESS
}

fn run_command(result: Result<(), Box<dyn std::error::Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Erreur : {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_who(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Err(format!(
            "la cible '{}' n'est pas un fichier accessible",
            path.display()
        )
        .into());
    }
    let processes = process_info::find_related_processes(path);
    if json {
        println!("{}", serde_json::to_string_pretty(&processes)?);
    } else if processes.is_empty() {
        println!("Aucun processus associé observé.");
    } else {
        for process in processes {
            println!(
                "pid {} {} {} [{}]",
                process.pid,
                process.user,
                process.status,
                if process.confirmed {
                    "descripteur observé"
                } else {
                    "indice heuristique"
                }
            );
        }
    }
    Ok(())
}

fn run_refs(
    path: &Path,
    scan_dirs: &[std::path::PathBuf],
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Err(format!(
            "la cible '{}' n'est pas un fichier accessible",
            path.display()
        )
        .into());
    }
    let roots = if scan_dirs.is_empty() {
        vec![std::env::current_dir()?]
    } else {
        scan_dirs.to_vec()
    };
    let skipped: Vec<_> = roots.iter().filter(|root| !root.is_dir()).collect();
    let existing: Vec<_> = roots.iter().filter(|root| root.is_dir()).cloned().collect();
    let references = scan::find_reference_evidence(&existing, path);
    #[derive(serde::Serialize)]
    struct ReferencesReport {
        target: String,
        scan_roots: Vec<String>,
        skipped_scan_roots: Vec<String>,
        references: Vec<scan::ReferenceEvidence>,
        limitation: &'static str,
    }
    let report = ReferencesReport {
        target: path.canonicalize()?.display().to_string(),
        scan_roots: existing
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        skipped_scan_roots: skipped
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        references,
        limitation: "Une mention textuelle ne prouve pas l'utilisation effective du fichier.",
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for reference in &report.references {
            println!(
                "{}:{} : {}",
                reference.source, reference.line, reference.excerpt
            );
        }
        if report.references.is_empty() {
            println!("Aucune référence observée.");
        }
        println!("Limite : {}", report.limitation);
    }
    Ok(())
}
