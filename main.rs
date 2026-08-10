mod cli;
mod file_info;
mod output;
mod process_info;
mod scan;
mod usage;

use clap::Parser;
use cli::Cli;
use output::MachOutput;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let file_path = match cli.target_file() {
        Some(f) => f,
        None => {
            eprintln!("Erreur : aucun fichier spécifié. Utilise `mach <fichier>` ou `-f <fichier>`.");
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
