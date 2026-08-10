use clap::Parser;

/// mach — comme `file`, mais qui te dit aussi qui touche à ton fichier.
#[derive(Parser, Debug)]
#[command(
    name = "mach",
    author,
    version,
    about = "Détermine le type d'un fichier et les processus/programmes qui l'utilisent",
    long_about = None
)]
pub struct Cli {
    /// Fichier cible (forme positionnelle : `mach id_ed25519 ...`)
    #[arg(value_name = "FILE")]
    pub file_pos: Option<String>,

    /// Fichier cible (forme explicite : `-f/--file`)
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file_flag: Option<String>,

    /// Afficher l'extension et le type (façon `file`)
    #[arg(short = 't', long = "type")]
    pub show_type: bool,

    /// Afficher les processus liés au fichier (user, pid, statut, dernière utilisation)
    #[arg(short = 'p', long = "process")]
    pub show_process: bool,

    /// Scanner un ou plusieurs répertoires à la recherche de références au fichier
    #[arg(short = 's', long = "scan", value_name = "DIR", num_args = 1..)]
    pub scan_dirs: Vec<String>,

    /// Afficher la dernière utilisation du fichier (accès/modification) et s'il est actif
    #[arg(short = 'u', long = "usage")]
    pub show_usage: bool,

    /// Indiquer si une fonction/programme fait appel au fichier (implique un scan)
    #[arg(short = 'c', long = "call")]
    pub show_calls: bool,

    /// Sortie au format JSON
    #[arg(short = 'j', long = "json")]
    pub json: bool,
}

impl Cli {
    /// Résout le chemin de fichier, qu'il soit passé en positionnel ou via -f
    pub fn target_file(&self) -> Option<String> {
        self.file_flag.clone().or_else(|| self.file_pos.clone())
    }

    /// Si aucun flag d'affichage n'est donné, on active tout par défaut
    /// (comportement "informatif complet" par défaut, comme `file -i` mais en plus riche)
    pub fn effective_flags(&self) -> (bool, bool, bool, bool) {
        let nothing_selected =
            !self.show_type && !self.show_process && !self.show_usage && !self.show_calls;

        if nothing_selected {
            (true, true, true, true)
        } else {
            (
                self.show_type,
                self.show_process,
                self.show_usage,
                self.show_calls,
            )
        }
    }
}

