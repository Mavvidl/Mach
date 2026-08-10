use std::fs;
use std::io::Read;
use std::path::Path;

/// Résultat de l'analyse de type d'un fichier
#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub extension: Option<String>,
    pub description: String,
    pub mime: Option<String>,
}

/// Détecte l'extension déclarée et le type réel du fichier.
///
/// Stratégie :
/// 1. `infer` sur les octets de signature (magic bytes) -> couvre la plupart
///    des formats binaires (images, archives, exécutables, etc).
/// 2. Heuristiques texte pour les formats que `infer` ne reconnaît pas
///    (clés OpenSSH/PEM, scripts, JSON, etc), car ce sont des fichiers texte
///    sans signature binaire fiable.
/// 3. Repli sur l'extension déclarée si rien n'a été identifié.
pub fn analyze(path: &Path) -> std::io::Result<TypeInfo> {
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase());

    let mut buf = Vec::with_capacity(8192);
    {
        let mut f = fs::File::open(path)?;
        f.by_ref().take(8192).read_to_end(&mut buf)?;
    }

    // 1. Détection binaire via `infer`
    if let Some(kind) = infer::get(&buf) {
        return Ok(TypeInfo {
            extension,
            description: kind.mime_type().to_string(),
            mime: Some(kind.mime_type().to_string()),
        });
    }

    // 2. Heuristiques texte
    if let Ok(text) = std::str::from_utf8(&buf) {
        if let Some(desc) = sniff_text_format(text) {
            return Ok(TypeInfo {
                extension,
                description: desc.to_string(),
                mime: Some("text/plain".to_string()),
            });
        }
        if !text.trim().is_empty() {
            return Ok(TypeInfo {
                extension,
                description: "ASCII/UTF-8 text".to_string(),
                mime: Some("text/plain".to_string()),
            });
        }
    }

    // 3. Repli sur l'extension
    let description = extension
        .as_deref()
        .map(describe_by_extension)
        .unwrap_or_else(|| "data (type inconnu)".to_string());

    Ok(TypeInfo {
        extension,
        description,
        mime: None,
    })
}

fn sniff_text_format(text: &str) -> Option<&'static str> {
    let head = text.trim_start();

    if head.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Some("OpenSSH private key");
    }
    if head.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        return Some("RSA private key (PEM)");
    }
    if head.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        return Some("EC private key (PEM)");
    }
    if head.starts_with("-----BEGIN PRIVATE KEY-----") {
        return Some("PKCS#8 private key (PEM)");
    }
    if head.starts_with("-----BEGIN CERTIFICATE-----") {
        return Some("X.509 certificate (PEM)");
    }
    if head.starts_with("ssh-ed25519")
        || head.starts_with("ssh-rsa")
        || head.starts_with("ecdsa-sha2")
    {
        return Some("OpenSSH public key");
    }
    if head.starts_with("#!/") {
        return Some("script (shebang)");
    }
    if (head.starts_with('{') && head.trim_end().ends_with('}'))
        || (head.starts_with('[') && head.trim_end().ends_with(']'))
    {
        return Some("JSON data");
    }
    if head.starts_with("<?xml") {
        return Some("XML document");
    }
    if head.starts_with("---") && text.contains(':') {
        return Some("YAML document (probable)");
    }

    None
}

fn describe_by_extension(ext: &str) -> String {
    match ext {
        "pem" | "key" => "PEM/clé (contenu non déterminé)".to_string(),
        "pub" => "clé publique probable".to_string(),
        "conf" | "cfg" | "ini" => "fichier de configuration".to_string(),
        "log" => "fichier journal (log)".to_string(),
        "toml" => "TOML data".to_string(),
        "yaml" | "yml" => "YAML data".to_string(),
        "md" => "Markdown document".to_string(),
        other => format!("fichier .{other} (type non identifié)"),
    }
}
