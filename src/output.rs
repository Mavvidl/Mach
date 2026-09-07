use crate::process_info::ProcessEntry;
use serde::Serialize;

#[derive(Debug, Serialize, Default)]
pub struct MachOutput {
    pub file: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_description: Option<String>,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<ProcessEntry>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_accessed: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub currently_in_use: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls: Option<Vec<String>>,
}

impl MachOutput {
    pub fn print(&self, as_json: bool) {
        if as_json {
            match serde_json::to_string_pretty(self) {
                Ok(s) => println!("{s}"),
                Err(e) => eprintln!("Erreur de sérialisation JSON: {e}"),
            }
            return;
        }

        
        
        println!("File      : {}", self.file);
        if let Some(ext) = &self.extension {
            if let Some(description) = &self.extension_description {
                println!("Extension    : {ext} ({description})");
            } else {
                println!("Extension    : {ext}");
            }
        }
        if let Some(t) = &self.file_type {
            println!("Type         : {t}");
        }
        if let Some(m) = &self.mime {
            println!("MIME         : {m}");
        }

        if let Some(procs) = &self.processes {
            println!("Processus liés :");
            if procs.is_empty() {
                println!("  (aucun processus trouvé)");
            }
            for p in procs {
                let marker = if p.confirmed { "confirmé" } else { "indice" };
                println!(
                    "  - pid {:<8} user {:<12} status {:<10} dernier accès {}  [{}]",
                    p.pid, p.user, p.status, p.last_used, marker
                );
            }
        }

        if let Some(u) = &self.usage {
            println!("Usage        : {u}");
        }
        if let Some(a) = &self.last_accessed {
            println!("Dernier accès (fs) : {a}");
        }
        if let Some(m) = &self.last_modified {
            println!("Dernière modif (fs): {m}");
        }
        if let Some(in_use) = self.currently_in_use {
            println!("En cours d'utilisation : {}", if in_use { "yes" } else { "no" });
        }

        if let Some(calls) = &self.calls {
            println!("Found References :");
            if calls.is_empty() {
                println!("No entries found in the scanned directories");
            }
            for c in calls {
                println!("  - {c}");
            }
        }
    }
}
