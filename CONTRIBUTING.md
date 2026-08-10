# Contribuer à mach

Merci de vouloir contribuer ! Voici comment t'y prendre.

## Mise en place

```bash
git clone https://github.com/<ton-user>/mach.git
cd mach
cargo build
```

## Avant d'ouvrir une PR

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

La CI GitHub Actions relance ces mêmes vérifications sur Linux et Windows —
autant les faire passer en local avant de pousser.

## Structure du projet

```
src/
├── main.rs          # point d'entrée, orchestration
├── cli.rs            # définition des flags (clap)
├── file_info.rs       # détection extension/type
├── process_info.rs    # processus liés au fichier
├── usage.rs           # dernière utilisation / usage actif
├── scan.rs            # recherche de références dans des répertoires
└── output.rs           # formatage JSON / texte
```

## Idées de contributions bienvenues

- Détection fiable des handles de fichiers ouverts sous Windows (via
  `windows-rs` / `NtQuerySystemInformation`), pour remplacer l'heuristique
  actuelle par une détection confirmée comme sur Linux.
- Support macOS (`lsof`-like via `/dev/fd` ou appel à la commande `lsof`).
- Tests d'intégration (fichiers de test fournis dans `tests/fixtures/`).
- Mode "watch" pour surveiller un fichier en continu.

## Signaler un bug / proposer une fonctionnalité

Utilise les templates d'issue GitHub (`Bug report` / `Feature request`) — ça
aide à avoir toutes les infos utiles dès le départ.

## Style de commit

Pas de convention stricte imposée, mais des messages clairs et en anglais ou
français cohérent avec le reste de l'historique sont appréciés.
