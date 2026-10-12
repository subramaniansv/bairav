# Bairav

**One command that audits a Java / Spring / React / JavaScript codebase and hands you two reports:**
a readable HTML report for people and a prioritized fix plan (Markdown + JSON) you can give straight to an AI
coding agent.

Bairav does not reinvent scanners. It orchestrates proven open-source engines (Semgrep, Trivy, Gitleaks,
OSV-Scanner, SpotBugs + Find Security Bugs, npm audit, Lighthouse, OWASP ZAP), adds its own built-in checks,
normalizes everything into one finding model, maps it to OWASP Top 10, scores it, and tells you what to fix first.
It runs locally on the JVM, needs no Docker, and skips any tool that is not installed.

> Setting it up on a new machine? See **[SETUP.md](SETUP.md)**.

## What it checks

| Area | How |
|---|---|
| Security (OWASP Top 10) | Semgrep (OWASP, Java, JWT, JS/TS/React rules), SpotBugs + Find Security Bugs, built-in Spring/React rules |
| Dependencies | Trivy + OSV-Scanner (deduplicated), `npm audit` |
| Secrets | Gitleaks (+ built-in checks). Secret values are never copied into the AI plan |
| Licenses and SBOM | CycloneDX SBOM per project; copyleft / deny / unknown-license policy |
| Performance | Unbounded `findAll`, EAGER fetch, large bundles, Lighthouse (for running apps) |
| Code quality | Cyclomatic complexity, long methods, duplicated blocks, git-churn hotspots, TODO count |
| Tests | Test-file detection, coverage from JaCoCo / LCOV / Istanbul reports |
| Build health | LOC, dependency counts, artifact sizes, lockfiles, optional build timing |
| SEO / GEO / AEO / accessibility | Titles, meta, canonical, Open Graph, JSON-LD, `llms.txt`, AI-bot rules in robots.txt, alt text, landmarks |
| Dynamic security | OWASP ZAP active scan against your own running app (opt-in) |
| Supply chain | Unpinned GitHub Actions, workflow permissions / `pull_request_target` / script injection, missing provenance, mutable Docker tags, floating or insecure Maven/npm sources |
| Compliance | Findings mapped (indicatively) to SOC 2, ISO 27001, PCI-DSS and GDPR controls; summary in `report.json` and the HTML report |
| Architecture and test health | Controller→repository shortcuts, field injection, unused imports/methods, circular and orphan JS modules, skipped / focused / assertion-free tests |
| Team metrics | Bus factor, CODEOWNERS, stale branches, oversized commits, DORA proxies from tags (needs a git repo) |
| Outdated dependencies | Major-version gaps from `npm outdated` / Maven versions plugin, with upgrade effort |
| Operations | Actuator / health / structured logging / error tracking, `.env` hygiene, prod config smells, Dockerfile / K8s / Terraform (Trivy, with a built-in fallback) |
| API and database | OpenAPI lint and breaking-change detection (vs `BAIRAV_API_BASE_REF`, default `HEAD`), Flyway / Liquibase migration safety, missing indexes, N+1 queries |
| Deeper performance | Bundle size per chunk (gzip), source maps in production, heavy libraries, large images, JVM hints; opt-in k6 load test with `--load --url` |
| Privacy and i18n | Secrets / PII in logs, trackers without consent, PII in localStorage, insecure cookies, missing privacy policy, hard-coded UI strings |

### PR bot and auto-fix

```bash
# Post/update ONE comment on a PR (new findings only when --baseline is used) + inline review
GITHUB_TOKEN=... bairav . --baseline auto --pr-comment auto        # or owner/repo#12

# Let an AI agent fix the top tasks; each fix is verified, committed on a new branch, or rolled back
bairav . --autofix 'my-agent --prompt {prompt_file}' --autofix-max 5   # needs a clean git tree
```

The agent command also receives `BAIRAV_TASK_FILE` and `BAIRAV_TASK_ID`. After fixing, Bairav re-scans and prints fixed/new counts.

Monorepos are handled automatically: every Maven / Gradle / npm project found is scanned, scored and reported separately.

## Quick start

```bash
git clone https://github.com/subramaniansv/bairav.git && cd bairav
mvn -q package -DskipTests            # needs JDK 17+ and Maven
bin/bairav --doctor                   # shows which scanners are installed
bin/bairav /path/to/your/repo --out ./report
open report/report.html               # human report
cat report/ai-fix-plan.md             # give this to your AI agent
```

Try it on the bundled sample first: `bin/bairav samples/vulnerable-app --out /tmp/bairav-demo`.

## Outputs

| File | For |
|---|---|
| `report.html` | People: grades per project, OWASP table, metrics, grouped findings, gate result |
| `ai-fix-plan.md` / `.json` | AI agents: tasks ordered by severity, with code snippets, how to fix, a verify command and a done-when line |
| `report.json` | Machines: versioned (`schemaVersion`), includes run metadata and gate result. Also usable as a baseline |
| `report.sarif` | GitHub code scanning and IDEs |
| `sbom/<project>.cdx.json` | CycloneDX SBOM |
| `work/<project>/raw`, `logs` | Raw tool output and logs, for debugging a misbehaving tool |

## Typical usage

```bash
# Gate a CI job: exit code 2 if anything HIGH or worse exists
bin/bairav . --fail-on HIGH

# Compare with an earlier run, fail a PR only for findings it introduced
bin/bairav . --baseline previous/report.json --fail-on HIGH --new-only

# Central policy + shared history across many projects
export BAIRAV_POLICY=/shared/bairav-policy.yml BAIRAV_STORE=/shared/bairav-store
bin/bairav . --project-id payments-api --baseline auto
bin/bairav --history --project-id payments-api         # score trend

# Performance / SEO / a11y of a running frontend (uses headless Chrome)
bin/bairav . --url student=http://localhost:5173

# Only specific engines
bin/bairav . --only builtin-rules,semgrep,gitleaks
```

Run `bin/bairav --help` for every option. Exit codes: `0` passed, `1` error, `2` quality gate failed.

## Using Bairav centrally

- **One policy, many projects.** A single YAML file (see [`configs/policy.example.yml`](configs/policy.example.yml))
  sets coverage, complexity, score, severity and license rules. A project's own `.bairav.yml` can add suppressions
  but cannot weaken the policy.
- **Shared history.** `--store` + `--project-id` keep every run per project; `--baseline auto` diffs against the last one.
- **Library.** Call it from any JVM tool or web app:
  ```java
  Bairav.Result res = Bairav.scan(Bairav.Request.of(Path.of("/repo"), Path.of("/out")));
  res.projects(); res.gate(); res.meta();
  ```
- **Plugins.** Put a jar with a `dev.repolens.runners.ToolRunner` service into a folder and pass `--plugins <dir>`.
- **CI.** Ready-made GitHub Actions workflow: [`ci/github-action.yml`](ci/github-action.yml).

## Per-project config (`.bairav.yml`)

```yaml
ignorePaths: ["**/generated/**"]
ignoreRules: ["spotbugs:DB_DUPLICATE_BRANCHES"]
severityOverrides: { "builtin-rules/cors-wildcard": LOW }
disableRunners: [lighthouse]
disableRunnersFor: { admin: [seo-geo-aeo] }   # per project name
```

Unknown keys fail fast so typos are caught. `spotbugs:EI_EXPOSE_REP(2)` is ignored by default (noise in Spring apps).

## How scoring works

Each area gets `100 x 100 / (100 + penalty)` where findings add penalty by severity (low 1, medium 3, high 7, critical 10).
Areas are weighted (Security 40%, Performance 15%, Build 10%, Quality 10%, Compliance 5%, and for indexable frontends SEO 10%,
GEO/AEO 5%, Accessibility 10%) and combined into a grade: A >= 90, B >= 75, C >= 60, D >= 40, F below.

## Project layout

```
src/main/java/dev/repolens/
  core/Bairav          library entry point
  cli/                 Main (Picocli), Analyzer (per-project orchestration)
  runners/             one class per tool; Runners = registry + plugin loader
  normalize/ owasp/ score/ detect/ config/ model/ util/
  report/              HTML, JSON, SARIF, baseline, run store, gate
  ai/AiPlanWriter      builds the AI fix plan
bin/bairav             launcher script
scripts/install-tools.sh   installs the optional scanners
configs/               example central policy
ci/                    GitHub Actions template
samples/vulnerable-app intentionally vulnerable demo
```

The Java package is still `dev.repolens` internally (the project's former name).

## Adding a tool

Extend `ExternalToolRunner` (implement `command(...)` and `parse(...)`) or implement `ToolRunner`, register it in
`Runners.defaults()` or ship it as a plugin jar. A tool that is missing, times out or fails never stops the others.

## Known limitations

- OWASP ZAP integration is only unit-tested against sample output, not yet against a live target.
- Complexity and duplication come from a lightweight scanner: good for ranking, not exact.
- Dual-licensed packages that Trivy lists as separate entries are reported per entry.
- Windows is supported through WSL2 only.

## Contributing / debugging

`mvn test` runs the unit tests. When a tool misbehaves, read `work/<project>/logs/<tool>.log` in the output folder
and re-run just that engine with `--only <tool> --verbose`.
