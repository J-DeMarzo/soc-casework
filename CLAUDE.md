# soc-casework

Public portfolio repo (github.com/J-DeMarzo/soc-casework) for SOC case work: emulated attacks investigated in Splunk and written up as cases. The audience is someone hiring for a SOC analyst role.

The lab itself lives in **enterprise-homelab**, cloned locally at `/home/demarzo/claude/the_kennel`. That repo owns Splunk config (`splunk/`) and **all detections** (`detections/`), because `splunk/build-savedsearches.py` generates the deployed searches from them. Never copy a detection into this repo: write or tune it there, commit it there, and link to it from here.

## Cases

- One folder per case: `cases/YYYY-MM-DD-short-name/README.md` plus `evidence/`. Create it with `scripts/new-case.sh <short-name> "<title>"`.
- Case IDs are `CASE-YYYY-NNN`, numbered in order within the year.
- Link a case's detection by **commit permalink** (`.../blob/<sha>/detections/...`), so it points at the version that actually fired. The detections table in `README.md` links to `main`.
- The emulation details go only in the appendix. The investigation reads as if it were blind.
- Every finding cites the SPL that produced it and an evidence file.
- Times are UTC.
- When a case is done: add it to the cases table in `README.md`, fill in the Case column of the detections table, tick it in `roadmap.md`, and replace "Phase 5"/"Planned" for that detection in enterprise-homelab's `detections/README.md` with a link to the case.

## Evidence and redaction

- Allowed: RFC 1918 addresses, `demarzo.lab` names, lab hostnames, lab usernames.
- Never committed: credentials, tokens, keys, session cookies, **public IPs**. This includes the home's public IP, which shows up as `src_ip` in Caddy/`web` events from demarzo.dev. Replace public IPs with `203.0.113.x` and say so in the case.
- No household data. Splunk only holds filtered household data ([ADR 0007](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/adr/0007-splunk-topology-and-household-data.md)), but check screenshots for Internal-zone devices anyway.
- Screenshots are cropped to what matters. Put originals that need redaction in `raw/` (gitignored), and only the redacted copy goes in `evidence/`.
- No live malware or pcaps; summarize them in the case instead.
- Commits run gitleaks through `.githooks/pre-commit` (`git config core.hooksPath .githooks`).

## Style

Match enterprise-homelab: plain, direct English, short sections, evidence-first, ✅/❌ where useful, links to ADRs instead of repeating them.
