# mach

[![CI](https://github.com/Mavvidl/mach/actions/workflows/ci.yml/badge.svg)](https://github.com/Mavvidl/mach/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](Cargo.toml)

`mach` est un outil CLI en Rust qui va plus loin que `file` : il identifie le
type d'un fichier, liste les processus qui l'utilisent, indique sa dernière
utilisation et cherche les fichiers qui y font référence (configs, logs...).


## Installation

### Depuis les sources

```bash
git clone https://github.com/Mavvidl/mach.git
cd mach
cargo build --release
```

Le binaire est produit dans `target/release/mach` (`mach.exe` sur Windows).

### Exécuter le binaire sans repasser par `cargo`

#### Linux

Depuis la racine du projet :

```bash
cd /chemin/vers/mach
./target/release/mach --help
```


```bash
sudo install -m 755 target/release/mach /usr/local/bin/mach
mach --help
```

#### Windows (PowerShell)

```powershell
cd C:\chemin\vers\mach
cargo build --release
.\target\release\mach.exe --help
```

Pour l’utiliser depuis n’importe quel dossier, ajoute le dossier de sortie au `PATH` :

```powershell
$env:Path += ";C:\chemin\vers\mach\target\release"
mach.exe --help
```

Ou copie le binaire dans un dossier déjà connu :

```powershell
Copy-Item "C:\chemin\vers\mach\target\release\mach.exe" "C:\Windows\System32\mach.exe"
mach --help
```

### Depuis une release

Télécharge le binaire correspondant à ton OS depuis la page
[Releases](https://github.com/Mavvidl/mach/releases) (généré automatiquement
par la CI à chaque tag `vX.Y.Z`).

Compatible Linux et Windows (voir la section « Limitations » pour les
différences de comportement entre les deux).

## Utilisation

```bash
mach <fichier> [OPTIONS]
```

| Flag              | Rôle                                                          |
|-------------------|----------------------------------------------------------------|
| `-f, --file`      | Fichier cible (alternative à la forme positionnelle)          |
| `-t, --type`      | Extension + type MIME/description                             |
| `-p, --process`   | Processus liés (user, pid, statut, date)                       |
| `-s, --scan <dir>`| Répertoire(s) à scanner pour trouver des références au fichier |
| `-u, --usage`     | Dernière utilisation + indicateur "en cours d'utilisation"     |
| `-c, --call`      | Cherche les fichiers qui appellent/référencent la cible        |
| `-j, --json`      | Sortie JSON                                                     |

Sans aucun flag d'affichage, `mach` active `-t -p -u -c` par défaut.

### Exemple

```bash
mach id_ed25519 --type --process --usage --json
```

```json
{
  "file": "id_ed25519",
  "extension": "",
  "type": "OpenSSH private key",
  "processes": [
    {
      "pid": 1234,
      "user": "root",
      "status": "Sleeping",
      "last_used": "2026-08-10 08:30",
      "confirmed": true
    }
  ],
  "usage": "Actuellement utilisé par le processus root (pid 1234)",
  "last_accessed": "2026-08-10 08:30:12",
  "last_modified": "2026-01-02 10:00:00",
  "currently_in_use": true
}
```

## Comment ça marche

- **Type de fichier** (`file_info.rs`) : `infer` détecte les formats binaires
  par signature (magic bytes). Pour les fichiers texte sans signature fiable
  (clés PEM/OpenSSH, JSON, YAML, scripts...), une heuristique de contenu prend
  le relais. En dernier recours, on retombe sur l'extension déclarée.

- **Processus liés** (`process_info.rs`) :
  - **Linux** : lecture de `/proc/[pid]/fd/*` — équivalent maison de `lsof`.
    C'est une **preuve directe** qu'un processus a le fichier ouvert
    (`confirmed: true`).
  - **Windows** : il n'existe pas d'API simple et stable pour lister les
    handles de fichiers ouverts par processus sans passer par des appels
    natifs non documentés (`NtQuerySystemInformation`) ou des outils tiers
    (Sysinternals `handle.exe`). Le programme retombe donc sur une
    **heuristique** : il regarde si le nom du fichier apparaît dans le nom du
    processus ou sa ligne de commande (`confirmed: false`). C'est un indice,
    pas une certitude — à garder en tête si tu automatises des décisions
    dessus.

- **Usage** (`usage.rs`) : dates d'accès/modification via les métadonnées du
  système de fichiers. La détection "en cours d'utilisation" s'appuie sur les
  processus confirmés (Linux) ou, à défaut, sur une tentative d'ouverture en
  écriture exclusive (Windows : si ça échoue, le fichier est probablement
  verrouillé par quelqu'un d'autre).

- **Références/appels** (`scan.rs`) : parcourt récursivement les répertoires
  donnés (`walkdir`) et cherche le nom du fichier dans le contenu texte de
  chaque fichier rencontré (`regex`), avec une limite de taille par fichier
  (5 Mo) pour rester rapide. Les fichiers binaires ou non-UTF8 sont ignorés
  silencieusement.

## Limitations connues

- La détection Windows des processus/handles est **heuristique**, pas fiable
  à 100 % (voir ci-dessus). Pour un résultat fiable sur Windows, il faudrait
  intégrer les API natives (`winapi`/`windows-rs`) et énumérer les handles
  système — hors périmètre de cette première version.
- Le scan de références est un simple `grep` récursif, pas une analyse
  sémantique : il peut avoir des faux positifs si le nom du fichier est
  courant (ex. `config` apparaissant ailleurs sans lien réel).
- Sur Linux, lire `/proc/[pid]/fd` pour des process d'autres utilisateurs
  nécessite en général d'être root ; sinon ces process sont silencieusement
  ignorés (pas de crash, juste absent des résultats).

## Dépendances

- [`clap`](https://docs.rs/clap) — parsing CLI (derive API)
- [`infer`](https://docs.rs/infer) — détection de type par signature binaire
- [`sysinfo`](https://docs.rs/sysinfo) — liste des processus, users, etc.
- [`walkdir`](https://docs.rs/walkdir) — parcours récursif de répertoires
- [`regex`](https://docs.rs/regex) — recherche de motifs dans les fichiers
- [`serde`](https://docs.rs/serde) / [`serde_json`](https://docs.rs/serde_json) — sortie JSON
- [`chrono`](https://docs.rs/chrono) — formatage des dates


## Contribuer

Les contributions sont bienvenues ! Voir [CONTRIBUTING.md](CONTRIBUTING.md)
pour la mise en place du projet et les vérifications à faire avant une PR.

## Licence

Ce projet est sous licence MIT — voir [LICENSE](LICENSE).

## Changelog

Voir [CHANGELOG.md](CHANGELOG.md) pour l'historique des versions.
