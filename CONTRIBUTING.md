# Conventions

Notes for how this repository is organized and how new entries get added — mainly so structure stays consistent as it grows.

## Structure

- `writeups/` — case studies, investigations, research, and CTF write-ups. Organized by category (`dfir/`, `soc/`, `malware-analysis/`, `threat-research/`).
- `projects/` — actual tools and code I've built, each with its own README, source, and docs.

## Adding a new write-up

1. Create a folder under the right category: `writeups/<category>/<kebab-case-title>/`
2. Add a `README.md` with the write-up itself.
3. If relevant, add:
   - `references.md` — external sources, CVEs, links
   - `scripts/` — any custom tooling written for the case
   - `evidence/` or `screenshots/` — only sanitized, non-sensitive material
4. Add a row for it in that category's `writeups/<category>/README.md`.

## Adding a new project

1. Create a folder under `projects/<project-name>/`.
2. Add a `README.md` describing what it does, how to run it, and its current status.
3. Add a row for it in `projects/README.md`.

## Naming

Use `kebab-case` for all folder names (`lockbit-ransomware-investigation`, not spaces or CamelCase).

## Sanitization

No credentials, real client names, real hostnames/IPs, or confidential material. Anonymize identifying details (as done in the DFIR write-ups) while keeping tooling, commands, and technical reasoning accurate.
