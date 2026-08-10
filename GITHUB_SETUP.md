# Réglages GitHub à saisir manuellement

Ce fichier n'est pas destiné à rester dans le dépôt une fois configuré — c'est
juste un pense-bête pour remplir la page GitHub du repo. Tu peux le supprimer
après usage (ou le garder, il ne gêne pas).

## Nom du dépôt

```
mach
```

## Description courte (champ "Description" en haut du repo)

```
Outil CLI Rust type `file`, en plus poussé : type de fichier, processus liés, dernière utilisation et références (Linux/Windows).
```

## Site web (optionnel)

Laisse vide, ou mets le lien vers la page Releases une fois publiée.

## Topics (mots-clés, à ajouter dans "About" → icône engrenage)

```
rust
cli
file-type
forensics
sysadmin
lsof
process-monitoring
cross-platform
command-line-tool
system-utility
```

## À faire une fois le repo créé

1. `git init && git add . && git commit -m "Initial commit"`
2. `git branch -M main`
3. `git remote add origin https://github.com/<ton-user>/mach.git`
4. `git push -u origin main`
5. Remplacer `<ton-user>` dans `README.md` (badges + liens clone/releases).
6. Dans **Settings → General** : activer "Issues" (déjà activé par défaut),
   désactiver "Wikis"/"Projects" si tu n'en as pas l'usage.
7. Dans **Settings → Branches** : ajouter une règle de protection sur `main`
   exigeant que le workflow CI passe avant merge (optionnel mais recommandé).
8. Pour publier une release : `git tag v0.1.0 && git push origin v0.1.0` — le
   workflow `release.yml` compile et attache les binaires Linux/Windows
   automatiquement.
9. Supprimer ce fichier (`GITHUB_SETUP.md`) une fois les réglages faits.

## Nom d'auteur / licence

Le fichier `LICENSE` (MIT) est signé "mach contributors" par défaut — remplace
par ton nom si tu préfères un copyright nominatif.
