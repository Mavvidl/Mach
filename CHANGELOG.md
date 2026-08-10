# Changelog

Toutes les modifications notables de ce projet sont documentées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et ce projet suit [Semantic Versioning](https://semver.org/lang/fr/).

## [Unreleased]

## [0.1.0] - 2026-08-10

### Ajouté

- Détection d'extension et de type de fichier (`-t/--type`) via `infer` +
  heuristiques texte (clés PEM/OpenSSH, JSON, YAML, scripts).
- Détection des processus liés à un fichier (`-p/--process`) :
  - preuve directe via `/proc/[pid]/fd` sur Linux,
  - heuristique nom/ligne de commande sur Windows.
- Détection de la dernière utilisation et de l'usage actif (`-u/--usage`).
- Scan de répertoires pour trouver les références au fichier
  (`-s/--scan`, `-c/--call`).
- Sortie JSON (`-j/--json`).
- CI GitHub Actions (build + tests Linux/Windows, fmt, clippy).
- Workflow de release automatique avec binaires attachés.
