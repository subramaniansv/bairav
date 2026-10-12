package dev.repolens.cli;

import dev.repolens.core.Bairav;
import dev.repolens.model.Severity;
import dev.repolens.report.RunMeta;
import dev.repolens.report.RunStore;
import dev.repolens.util.ProcessRunner;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(name = "bairav", mixinStandardHelpOptions = true, version = "bairav " + Bairav.VERSION,
        description = "Analyzes Java/Spring/React/JS repos (or a monorepo of them) with open-source engines and writes "
                + "a human report (report.html) and an AI fix plan (ai-fix-plan.md/json).",
        exitCodeListHeading = "%nExit codes:%n",
        exitCodeList = {"0:Success, quality gate passed", "1:Usage or runtime error", "2:Quality gate failed"})
public class Main implements Callable<Integer> {

    @Parameters(index = "0", arity = "0..1", description = "Path to a repo, or a folder containing several projects")
    Path repo;

    @Option(names = "--out", description = "Report directory (default: ./bairav-report)")
    Path out = Path.of("bairav-report");

    @Option(names = "--timeout", description = "Per-tool timeout in seconds (default: ${DEFAULT-VALUE})")
    int timeout = 600;

    @Option(names = "--dry-run", description = "Print external commands without running them")
    boolean dryRun;

    @Option(names = "--build", description = "Also run and time the project build (mvn package / npm run build)")
    boolean build;

    @Option(names = "--only", split = ",", description = "Run only these tools (e.g. semgrep,builtin-rules)")
    Set<String> only = new LinkedHashSet<>();

    @Option(names = "--fail-on", description = "Exit 2 if any finding at or above this severity: ${COMPLETION-CANDIDATES}")
    Severity failOn;

    @Option(names = "--new-only", description = "With --baseline: apply --fail-on only to findings new since the baseline (PR gating)")
    boolean newOnly;

    @Option(names = "--config", description = "Repo config file (default: <repo>/.bairav.yml)")
    Path config;

    @Option(names = "--policy", description = "Central policy file (thresholds, license rules) enforced on top of the repo config. "
            + "Env: BAIRAV_POLICY")
    Path policy;

    @Option(names = "--baseline", description = "Previous report.json to compare against, or 'auto' to use the latest run in --store")
    String baseline;

    @Option(names = "--store", description = "Central run-history directory shared by many projects. Env: BAIRAV_STORE")
    Path store;

    @Option(names = "--project-id", description = "Stable id for this project in the store (default: CI repository name or folder name)")
    String projectId;

    @Option(names = "--plugins", description = "Directory of runner plugin jars (ServiceLoader: dev.repolens.runners.ToolRunner)")
    Path plugins;

    @Option(names = "--history", description = "Print the score history of --project-id from --store, then exit")
    boolean history;

    @Option(names = "--url", description = "Running app URL for Lighthouse/ZAP, per project: --url student=http://localhost:5173 (use * for all)")
    Map<String, String> urls = new LinkedHashMap<>();

    @Option(names = "--zap", description = "Run an OWASP ZAP active scan against --url targets (own apps only)")
    boolean zap;

    @Option(names = "--load", description = "Run a short k6 load test against --url targets (own apps only; needs k6)")
    boolean load;

    @Option(names = "--pr-comment", description = "Write pr-comment.md/pr-review.json and post them to a GitHub PR: owner/repo#N or 'auto' (needs GITHUB_TOKEN)")
    String prComment;

    @Option(names = "--autofix", description = "After scanning, run this agent command per top task; use {prompt_file}. Verified fixes are committed on a new branch (repo must be a clean git tree)")
    String autofix;

    @Option(names = "--autofix-max", defaultValue = "5", description = "Max tasks to attempt (default: ${DEFAULT-VALUE})")
    int autofixMax;

    @Option(names = "--doctor", description = "Show which external tools are installed, then exit")
    boolean doctor;

    @Option(names = "--verbose", description = "Print stack traces for runner errors")
    boolean verbose;

    public static void main(String[] args) {
        System.exit(new CommandLine(new Main()).execute(args));
    }

    @Override
    public Integer call() throws Exception {
        if (doctor) return doctor();
        if (store == null && System.getenv("BAIRAV_STORE") != null) store = Path.of(System.getenv("BAIRAV_STORE"));
        if (policy == null && System.getenv("BAIRAV_POLICY") != null) policy = Path.of(System.getenv("BAIRAV_POLICY"));
        if (history) return history();
        if (repo == null) {
            System.err.println("Missing repo path. Usage: bairav <path> [options]  (or --doctor)");
            return 1;
        }
        if (!Files.isDirectory(repo)) {
            System.err.println("Not a directory: " + repo.toAbsolutePath().normalize());
            return 1;
        }
        if (baseline != null && !baseline.equals("auto") && !Files.isRegularFile(Path.of(baseline))) {
            System.err.println("Baseline not found: " + baseline);
            return 1;
        }

        Bairav.Request req = new Bairav.Request(repo, out, timeout, dryRun, build, only, urls, zap, verbose, config,
                policy, baseline, store, projectId, plugins, failOn, newOnly, load);
        Bairav.Result res = Bairav.scan(req);

        System.out.println("Total findings: " + res.totalFindings() + (res.diff() == null ? ""
                : " (" + res.diff().added().size() + " new, " + res.diff().fixed() + " fixed since baseline)"));
        System.out.println("Human report: " + res.outDir().resolve("report.html"));
        System.out.println("AI fix plan:  " + res.outDir().resolve("ai-fix-plan.md") + "  (+ ai-fix-plan.json)");
        if (Files.isDirectory(res.outDir().resolve("sbom"))) System.out.println("SBOM:         " + res.outDir().resolve("sbom"));
        if (store != null) System.out.println("Stored run:   " + store.toAbsolutePath().normalize().resolve(res.meta().projectId()));
        if (prComment != null) postPrComment(res);
        if (autofix != null) runAutofix(req, res);
        if (!res.gate().passed()) {
            System.out.println("\nQUALITY GATE FAILED");
            res.gate().violations().forEach(v -> System.out.println("  - " + v));
            return 2;
        }
        return 0;
    }

    private void postPrComment(Bairav.Result res) throws Exception {
        String body = dev.repolens.report.PrComment.render(res.projects(), res.diff(), res.gate());
        var inline = dev.repolens.report.PrComment.inline(res.projects(), res.diff());
        Files.writeString(res.outDir().resolve("pr-comment.md"), body);
        Files.writeString(res.outDir().resolve("pr-review.json"),
                new com.fasterxml.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(inline));
        System.out.println("PR comment:   " + res.outDir().resolve("pr-comment.md"));
        var target = dev.repolens.report.PrComment.parseTarget(prComment, System.getenv());
        String token = System.getenv("GITHUB_TOKEN");
        if (target == null) {
            System.out.println("Not a pull request run; comment written but not posted.");
        } else if (token == null || token.isBlank()) {
            System.out.println("GITHUB_TOKEN not set; comment written but not posted.");
        } else {
            String api = System.getenv().getOrDefault("GITHUB_API_URL", "https://api.github.com");
            try {
                dev.repolens.report.PrComment.post(target, body, inline, token, api);
                System.out.println("Posted PR comment to " + target.repo() + "#" + target.number());
            } catch (java.io.IOException e) {
                System.out.println("Could not post PR comment: " + e.getMessage());
            }
        }
    }

    private void runAutofix(Bairav.Request req, Bairav.Result res) throws Exception {
        var tasks = dev.repolens.ai.AiPlanWriter.buildTasks(repo.toAbsolutePath().normalize(), res.projects());
        System.out.println("\nAuto-fix: attempting up to " + Math.min(autofixMax, tasks.size()) + " of " + tasks.size() + " tasks");
        List<dev.repolens.ai.AutoFix.Outcome> outcomes;
        try {
            outcomes = dev.repolens.ai.AutoFix.run(repo.toAbsolutePath().normalize(), res.outDir(), tasks, autofix, autofixMax, timeout);
        } catch (java.io.IOException e) {
            System.out.println("Auto-fix aborted: " + e.getMessage());
            return;
        }
        outcomes.forEach(o -> System.out.println("  " + (o.fixed() ? "FIXED  " : "SKIPPED") + " " + o.taskId() + " - " + o.detail()));
        if (outcomes.stream().anyMatch(dev.repolens.ai.AutoFix.Outcome::fixed)) {
            var after = dev.repolens.ai.AutoFix.rescan(req, res.outDir().resolve("report.json"), res.outDir().resolve("autofix-rescan"));
            System.out.println("Re-scan: " + after.totalFindings() + " findings"
                    + (after.diff() == null ? "" : " (" + after.diff().added().size() + " new, " + after.diff().fixed() + " fixed)"));
        }
    }

    private Integer history() throws Exception {
        if (store == null) {
            System.err.println("--history needs --store (or BAIRAV_STORE)");
            return 1;
        }
        String id = projectId != null ? projectId
                : RunMeta.detect((repo == null ? Path.of(".") : repo).toAbsolutePath().normalize(), null, Bairav.VERSION,
                java.time.LocalDateTime.now(), 0).projectId();
        var points = RunStore.history(store.toAbsolutePath().normalize(), id);
        System.out.println("History for " + id + " (" + points.size() + " runs)");
        for (var p : points) {
            System.out.printf("  %s  %-14s %-8s score %3d  findings %4d  %s%s%n", p.startedAt(), p.branch(),
                    p.commit().substring(0, Math.min(8, p.commit().length())), p.overall(), p.findings(), p.grades(),
                    p.vitals().isEmpty() ? "" : "  | CWV " + p.vitals());
        }
        return 0;
    }

    private Integer doctor() {
        System.out.println("External tools (missing ones are skipped during analysis):");
        Map<String, String> tools = new LinkedHashMap<>();
        tools.put("semgrep", "brew install semgrep");
        tools.put("trivy", "brew install trivy (also used for SBOM + licenses)");
        tools.put("gitleaks", "brew install gitleaks");
        tools.put("osv-scanner", "brew install osv-scanner");
        tools.put("spotbugs", "brew install spotbugs");
        tools.put("git", "install git (code churn hotspots)");
        tools.put("npm", "install Node.js");
        tools.put("mvn", "brew install maven");
        tools.put("k6", "brew install k6 (optional, --load)");
        tools.put("zap.sh", "brew install --cask zap (optional, --zap)");
        tools.forEach((t, hint) -> {
            Path p = ProcessRunner.which(t);
            if (p == null && t.equals("zap.sh") && Files.exists(Path.of("/Applications/ZAP.app"))) p = Path.of("/Applications/ZAP.app");
            System.out.printf("  %-12s %s%n", t, p != null ? "OK  " + p : "MISSING  -> " + hint);
        });
        boolean chrome = Files.exists(Path.of("/Applications/Google Chrome.app"));
        System.out.printf("  %-12s %s%n", "chrome", chrome ? "OK (for Lighthouse)" : "MISSING (needed for Lighthouse)");
        return 0;
    }
}
