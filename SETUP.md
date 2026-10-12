# Setting up Bairav on a new machine

About 10 minutes. Bairav itself needs only **Java 17+ and Maven**. The scanners are optional but recommended;
anything missing is skipped and shown as `SKIPPED` in the report.

## 1. Prerequisites

| Tool | Needed for | Check |
|---|---|---|
| JDK 17 or newer | Running/building Bairav (required) | `java -version` |
| Maven 3.8+ | Building Bairav (required) | `mvn -v` |
| git | Cloning, code-churn hotspots, run metadata | `git --version` |
| Node.js 18+ and npm | `npm audit`, scanning React/JS projects, Lighthouse | `node -v` |
| Google Chrome | Lighthouse only (`--url`) | open Chrome |

Supported: **macOS** and **Linux**. On Windows use **WSL2** (Ubuntu) and follow the Linux steps there.

### macOS

```bash
brew install openjdk@21 maven git node
# make the JDK visible (Apple Silicon path shown)
sudo ln -sfn /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-21.jdk
```

### Ubuntu / Debian

```bash
sudo apt-get update && sudo apt-get install -y openjdk-21-jdk maven git nodejs npm python3-pip curl
```

## 2. Get and build Bairav

```bash
git clone https://github.com/subramaniansv/bairav.git
cd bairav
mvn -q package            # builds target/bairav-<version>.jar and runs the tests
```

Faster build without tests: `mvn -q package -DskipTests`.

## 3. Install the scanners (optional, recommended)

```bash
scripts/install-tools.sh      # macOS: Homebrew; Linux: apt/pip/curl
bin/bairav --doctor           # shows OK / MISSING for each tool
```

What each one adds:

| Scanner | Adds | Manual install |
|---|---|---|
| semgrep | OWASP / code-security rules | `brew install semgrep` or `pip install semgrep` |
| trivy | Dependency CVEs, misconfig, SBOM, licenses | `brew install trivy` |
| gitleaks | Hard-coded secrets | `brew install gitleaks` |
| osv-scanner | Second dependency CVE source | `brew install osv-scanner` |
| spotbugs | Java bytecode bugs + Find Security Bugs (needs the project compiled to `target/classes`) | `brew install spotbugs` |
| OWASP ZAP | Dynamic scan, only with `--zap` | `brew install --cask zap` |

The first run downloads rule sets and vulnerability databases, so it needs internet and takes longer.

## 4. First run

```bash
bin/bairav samples/vulnerable-app --out /tmp/bairav-demo
open /tmp/bairav-demo/report.html            # macOS (use xdg-open on Linux)
less /tmp/bairav-demo/ai-fix-plan.md
```

Scan your own project (a single repo or a folder with several projects):

```bash
bin/bairav /path/to/project --out ./report
```

Tip: put `bin` on your PATH to run `bairav` from anywhere:

```bash
echo 'export PATH="$PATH:'"$PWD"'/bin"' >> ~/.zshrc     # or ~/.bashrc
```

## 5. Better results (optional)

- **Java projects:** run `mvn -q compile` first so SpotBugs has classes; run `mvn verify` with JaCoCo to get coverage.
- **Frontend projects:** run `npm ci` so `npm audit` has a lockfile; run tests with coverage (`--coverage`).
- **Running frontend:** start it, then `bin/bairav . --url <project-name>=http://localhost:5173` for Lighthouse.
- **Policy for a team:** copy `configs/policy.example.yml`, edit it, and set `BAIRAV_POLICY=/path/policy.yml`.
- **Run history:** set `BAIRAV_STORE=/path/store` and use `--project-id <name> --baseline auto`.

## 6. Environment variables

| Variable | Meaning |
|---|---|
| `BAIRAV_POLICY` | Central policy file (same as `--policy`) |
| `BAIRAV_STORE` | Central run-history folder (same as `--store`) |
| `CHROME_PATH` | Chrome/Chromium binary for Lighthouse if not in a standard location |

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `release version 17 not supported` | Your JDK is older than 17. Install JDK 17+ and check `java -version` / `JAVA_HOME` |
| A tool shows `SKIPPED ... not installed` | Install it (step 3) or ignore; Bairav continues without it |
| Trivy: `docker-credential-... not found` | Handled automatically. If you see it elsewhere, run with `DOCKER_CONFIG=$(mktemp -d)` |
| Semgrep `FAILED` / exit 7 | No internet or a rule-set fetch failed. Read `work/<project>/logs/semgrep.log` |
| SpotBugs `SKIPPED: target/classes` | Compile the project first (`mvn -q compile`) |
| Lighthouse `no output produced` | Chrome missing or not found: install Chrome or set `CHROME_PATH`; check the URL is reachable |
| Scan is slow | Use `--only` to select engines, or raise `--timeout` for big repos |
| Too many findings from tests/build output | Add `ignorePaths` in `.bairav.yml` |
| Any tool misbehaves | Read `<out>/work/<project>/logs/<tool>.log`, re-run with `--only <tool> --verbose` |

## 8. Updating and removing

```bash
git pull && mvn -q package -DskipTests      # update
rm -rf bairav                               # remove (scanners installed with brew/pip stay installed)
```
