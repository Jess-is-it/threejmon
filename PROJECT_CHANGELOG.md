# ThreeJ Notifier Suite — Project Changelog

Use this file to record every meaningful system change in reverse-chronological order.

## Changelog Rules (Mandatory)

1. Any feature/function/behavior/schema/permission/architecture change must add a new entry.
2. Each entry must be added **in the same commit/PR** as the code change.
3. Keep entries factual and operation-focused (what changed, impact, rollback path).
4. Do not include secrets, tokens, passwords, or sensitive data.

---

## Entry Template

```md
## YYYY-MM-DD HH:MM UTC — <Short Change Title>
- Type: feature | fix | refactor | perf | security | docs | migration
- Scope: <feature/page/module names>
- Summary:
  - <what changed>
  - <what changed>
- Files:
  - <path>
  - <path>
- DB/Config Impact:
  - Schema: none | <details>
  - Settings/State keys: none | <details>
- Runtime Impact:
  - <performance/behavior/user-visible impact>
- Validation:
  - <commands/tests/run checks performed>
- Rollback:
  - <commit hash or exact rollback steps>
```

---

## Entries

## 2026-03-09 05:54 UTC — Exposed core Profile Review diagnostics to page viewers
- Type: fix
- Scope: Profile Review / access behavior
- Summary:
  - Updated Profile Review so the core diagnostic cards are shown to users with normal `profile_review.view` access, instead of requiring the extra `profile_review.details.view` permission.
  - This restores visibility of Account Details, Testing Focus, Under Surveillance, Offline, and the new Inspect Activity panel for operators who could already open the page.
- Files:
  - `app/templates/profile_review.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Profile Review now exposes the main diagnostic section consistently for standard page viewers.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/profile_review.html').read_text())"`
  - `node -e "const fs=require('fs'); const s=fs.readFileSync('/opt/threejnotif/app/templates/profile_review.html','utf8'); const m=s.match(/<script>([\\s\\S]*?)<\\/script>/); if(!m) throw new Error('script block not found'); const js=m[1].replace(/\\{\\{[\\s\\S]*?\\}\\}/g,'null'); new Function(js);"`
- Rollback:
  - Revert the `can_core_details` access change in `app/templates/profile_review.html`.

## 2026-03-09 05:22 UTC — Added Inspect Activity panel to Profile Review
- Type: feature
- Scope: Profile Review / surveillance baseline diagnostics
- Summary:
  - Added an inline Inspect Activity card on Profile Review so operators can see the same ACC-Ping latency/loss baseline used in Surveillance without leaving the page.
  - Reused the existing `/surveillance/inspect_activity` endpoint and surfaced its KPI set, zoomable chart, range label, and baseline anchor text directly in the profile workflow.
- Files:
  - `app/templates/profile_review.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Profile Review now exposes surveillance-style inspection data inline for faster account testing and tagging decisions.
- Validation:
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/profile_review.html').read_text())"`
- Rollback:
  - Revert the Inspect Activity additions in `app/templates/profile_review.html`.

## 2026-03-09 04:46 UTC — Expanded Profile Review into full account diagnostics
- Type: feature
- Scope: Profile Review / account lookup / surveillance-offline account context
- Summary:
  - Reworked Profile Review search and profile context so account lookups can surface surveillance, offline, usage, optical, and ACC-Ping data together.
  - Added consolidated account KPIs, testing-focus guidance, surveillance details, and offline history/status to help operators decide when to tag an account for Under Surveillance.
  - Added exact account helpers for offline history and active surveillance session lookups to avoid broad scans for profile pages.
- Files:
  - `app/main.py`
  - `app/db.py`
  - `app/templates/profile_review.html`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - Profile Review now renders richer cross-module diagnostics and broader search results for account troubleshooting.
- Validation:
  - `python3 -m py_compile /opt/threejnotif/app/main.py /opt/threejnotif/app/db.py`
  - `python3 -c "from jinja2 import Environment; from pathlib import Path; Environment().parse(Path('/opt/threejnotif/app/templates/profile_review.html').read_text())"`
- Rollback:
  - Revert the Profile Review changes in `app/main.py`, `app/db.py`, and `app/templates/profile_review.html`.

## 2026-03-09 03:41 UTC — Added AI short-command onboarding protocol
- Type: docs
- Scope: AI collaboration workflow / repository docs
- Summary:
  - Added mandatory quick-command protocol to `PROJECT_DESCRIPTION.md` so user can say `view project description`.
  - Defined required AI behavior: read project description + changelog, then return a standard acknowledgment before coding.
  - Renumbered section headers in `PROJECT_DESCRIPTION.md` after inserting new onboarding section.
- Files:
  - `PROJECT_DESCRIPTION.md`
  - `PROJECT_CHANGELOG.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - No runtime impact.
- Validation:
  - Verified cross-reference and protocol text is present.
- Rollback:
  - Revert latest docs commit or remove onboarding section and changelog entry.

## 2026-03-09 03:33 UTC — Added project-level AI onboarding documentation
- Type: docs
- Scope: repository documentation
- Summary:
  - Added `PROJECT_DESCRIPTION.md` with architecture, feature map, DB overview, runtime instructions, and security rules.
  - Added mandatory documentation policy requiring updates whenever system behavior changes.
- Files:
  - `PROJECT_DESCRIPTION.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - No runtime impact.
- Validation:
  - Verified file exists and content is readable.
- Rollback:
  - Remove `PROJECT_DESCRIPTION.md`.

## 2026-03-09 03:36 UTC — Added formal project changelog system
- Type: docs
- Scope: repository documentation governance
- Summary:
  - Added `PROJECT_CHANGELOG.md` with mandatory rules and reusable entry template.
  - Linked changelog requirement from `PROJECT_DESCRIPTION.md`.
- Files:
  - `PROJECT_CHANGELOG.md`
  - `PROJECT_DESCRIPTION.md`
- DB/Config Impact:
  - Schema: none
  - Settings/State keys: none
- Runtime Impact:
  - No runtime impact.
- Validation:
  - Verified both markdown files and cross-reference.
- Rollback:
  - Remove `PROJECT_CHANGELOG.md` and revert `PROJECT_DESCRIPTION.md` changelog references.
