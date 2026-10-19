# mach

[![CI](https://github.com/Mavvidl/mach/actions/workflows/ci.yml/badge.svg)](https://github.com/Mavvidl/mach/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](Cargo.toml)

`mach` est une plateforme locale d'investigation système. Elle relie fichiers,
processus, références textuelles et instantanés afin de produire des résultats
étayés, avec leurs sources, niveaux de confiance et limites de collecte.


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

La release stable [v1.1.0](https://github.com/Mavvidl/Mach/releases/tag/v1.1.0)
fournit ces binaires :

- [Linux x86_64](https://github.com/Mavvidl/Mach/releases/download/v1.1.0/mach-linux-x86_64)
- [Windows x86_64](https://github.com/Mavvidl/Mach/releases/download/v1.1.0/mach-windows-x86_64.exe)

Les releases futures sont publiées par la CI à chaque tag `vX.Y.Z`, après les
tests et un smoke test du binaire sur Linux et Windows. Les différences de
collecte entre plateformes sont décrites dans « Limitations connues ».

## Utilisation

### Commandes d'investigation

```bash
mach inspect <fichier> [--scan <répertoire>...] [--db <base.sqlite3>] [--json]
mach who <fichier> [--json]
mach refs <fichier> [--scan <répertoire>...] [--json]
mach impact <fichier> [--scan <répertoire>...] [--json]
mach graph <fichier> [--scan <répertoire>...] [--db <base.sqlite3>] [--json]
mach anomaly <fichier> [--db <base.sqlite3>] [--json]
mach history <fichier> [--db <base.sqlite3>] [--json]
mach diff [--since 24h] [--db <base.sqlite3>] [--json]
mach watch <chemin> [--interval 30] [--db <base.sqlite3>] [--json]
```

`inspect` est le point d'entrée général : il rassemble type, métadonnées,
SHA-256, processus, références, historique disponible, indicateurs d'anomalie
et graphe de relations. `who` cible les processus, `refs` les références
textuelles, `impact` les conséquences possibles et `graph` les relations
collectées. Toutes ces commandes acceptent `--json`.

Les commandes historiques (`mach <fichier> [OPTIONS]`) restent disponibles :

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

### Historique local et analyse d'impact

```bash
mach watch /etc/ssh/sshd_config --interval 30
mach history /etc/ssh/sshd_config
mach diff --since 24h
mach impact /etc/ssh/sshd_config
mach anomaly /etc/ssh/sshd_config
```

`watch` enregistre des instantanés dans SQLite (`$XDG_DATA_HOME/mach/history.sqlite3`
ou `~/.local/share/mach/history.sqlite3` sous Linux; `%LOCALAPPDATA%/mach/history.sqlite3`
sous Windows). L'option `--db` permet de choisir un autre emplacement. La surveillance
est un polling, pas un journal système : l'historique commence à la première observation
et peut manquer tout changement intervenu entre deux passages. Une absence observée ne
permet pas non plus de distinguer une suppression d'une inaccessibilité.

`watch` s'arrête avec Ctrl+C. Son premier passage constitue la référence initiale;
une apparition vue lors d'un passage ultérieur est signalée comme telle, sans prétendre
connaître sa date de création. La base est locale et peut contenir chemins, empreintes,
permissions et identifiants de propriétaire observés.

`impact` rapporte les processus observés et les références trouvées dans les répertoires
analysés (`/etc` et les répertoires systemd usuels sous Linux, `ProgramData` sous Windows,
ou les chemins fournis avec `--scan`). Chaque référence inclut sa ligne source et un niveau
de confiance. Une mention dans une configuration ou une unité de service ne prouve pas une
dépendance active. La commande ne modifie jamais le système.

### Inspection, graphe et anomalies

```bash
mach inspect /etc/ssh/sshd_config --scan /etc --json
mach who /etc/ssh/sshd_config
mach refs /etc/ssh/sshd_config --scan /etc --json
mach graph /etc/ssh/sshd_config --scan /etc --json
mach anomaly /usr/local/bin/agent --json
```

`inspect` rassemble le type, les métadonnées disponibles, SHA-256, processus,
références, historique local, indicateurs d'anomalie et graphe. Le champ de dernier
accès est sourcé par les métadonnées du système de fichiers; ce n'est pas une preuve
d'utilisation par un processus.

`graph` relie uniquement les éléments effectivement collectés. Une ouverture de fichier
observée est une relation directe au moment du contrôle; une référence dans un script,
une configuration ou une unité est une relation déduite, avec ligne source et confiance.
Les services candidats ne sont pas présentés comme des dépendances avérées.

`anomaly` compare le fichier à sa dernière observation présente. Sans référence antérieure,
la sortie indique que la comparaison est impossible. Les permissions, le propriétaire,
la taille, SHA-256 et la date de modification sont comparés lorsque les valeurs sont
disponibles. Un fichier vu pour la première fois après l'instantané initial d'un `watch`
est signalé comme apparition observée, sans inférer sa date de création. Une anomalie
est un indicateur à examiner, jamais un verdict de logiciel malveillant.

Les changements de permissions, propriétaire ou date de modification peuvent être
signalés seulement si les métadonnées sont accessibles sur le système de fichiers et
si une référence historique existe. Les relations inhabituelles ne sont pas classées
automatiquement comme anomalies : il n'existe pas encore de profil de référence approuvé.

Pour inspecter une sortie JSON ou isoler la base d'historique :

```bash
mach impact /etc/ssh/sshd_config --scan /etc --json
mach history /etc/ssh/sshd_config --db ./mach-history.sqlite3 --json
mach diff --since 7d --db ./mach-history.sqlite3 --json
mach anomaly ./config.toml --db ./mach-history.sqlite3 --json
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
  le relais. Les autres fichiers texte sont décrits à partir de leur extension
  (langage, format ou type de document) ; l'extension sert aussi de dernier
  recours quand le contenu n'est pas reconnu.

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
- **Historique/anomalies** (`history.rs`, `anomaly.rs`) : empreintes SHA-256 et
  attributs de métadonnées sont comparés aux observations SQLite locales. Le polling
  peut manquer des événements entre deux passages et ne reconstitue rien d'antérieur.
- **Relations** (`graph.rs`) : les relations exposent leur source, heure, confiance,
  caractère direct ou déduit et limite de collecte. Les inférences textuelles ne sont
  jamais assimilées à une dépendance prouvée.

## Limitations connues

- La détection Windows des processus/handles est **heuristique**, pas fiable
  à 100 % (voir ci-dessus). Pour un résultat fiable sur Windows, il faudrait
  intégrer les API natives (`winapi`/`windows-rs`) et énumérer les handles
  système — hors périmètre de cette première version.
- La détection des processus sous Windows recherche des indices dans le nom et la
  ligne de commande; elle ne confirme pas l'ouverture du fichier. Sous Linux,
  l'accès à `/proc` peut être limité par les permissions.
- L'indicateur d'emplacement exécutable inhabituel est une heuristique limitée à
  certains répertoires volatils Unix (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`).
  Il n'est pas évalué sous Windows.
- Les dates d'accès dépendent des options et du comportement du système de fichiers;
  elles ne prouvent pas qu'un processus particulier a consulté le fichier.
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
- [`rusqlite`](https://docs.rs/rusqlite) — historique SQLite local
- [`sha2`](https://docs.rs/sha2) — empreintes SHA-256
- [`ctrlc`](https://docs.rs/ctrlc) — arrêt propre de la surveillance avec Ctrl+C


## Contribuer

Les contributions sont bienvenues ! Voir [CONTRIBUTING.md](CONTRIBUTING.md)
pour la mise en place du projet et les vérifications à faire avant une PR.

## Licence

Ce projet est sous licence MIT — voir [LICENSE](LICENSE).

## Changelog

Voir [CHANGELOG.md](CHANGELOG.md) pour l'historique des versions.

Version publiée : [v1.1.0](https://github.com/Mavvidl/Mach/releases/tag/v1.1.0).
