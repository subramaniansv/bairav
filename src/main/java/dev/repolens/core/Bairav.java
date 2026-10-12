package dev.repolens.core;

import dev.repolens.ai.AiPlanWriter;
import dev.repolens.cli.Analyzer;
import dev.repolens.config.Config;
import dev.repolens.detect.ProjectDiscovery;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.Severity;
import dev.repolens.report.Baseline;
import dev.repolens.report.Gate;
import dev.repolens.report.ReportWriter;
import dev.repolens.report.RunMeta;
import dev.repolens.report.RunStore;
import dev.repolens.report.SarifWriter;
import dev.repolens.runners.Runners;
import dev.repolens.runners.ToolRunner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Programmatic entry point: the CLI, a CI step, a web app or a test harness can all call
 * {@code Bairav.scan(request)} in-process and read the {@link Result}. Every call is self-contained
 * (own output dir, no global state), so several scans can run in parallel in one JVM.
 */
public final class Bairav {

    public static final String VERSION = "0.4.0";

    private Bairav() {}

    /**
     * @param baseline  path to a previous report.json, or "auto" to use the latest run in the store
     * @param store     central history directory shared by many projects (optional)
     * @param policy    central policy file enforced on top of the repo's own .bairav.yml (optional)
     * @param plugins   directory of runner plugin jars (optional)
     * @param newOnly   gate only on findings that are new relative to the baseline
     */
    public record Request(Path repo, Path out, int timeoutSec, boolean dryRun, boolean build, Set<String> only,
                          Map<String, String> urls, boolean zap, boolean verbose, Path config, Path policy,
                          String baseline, Path store, String projectId, Path plugins, Severity failOn,
                          boolean newOnly, boolean load) {

        public static Request of(Path repo, Path out) {
            return new Request(repo, out, 600, false, false, new LinkedHashSet<>(), new LinkedHashMap<>(), false, false,
                    null, null, null, null, null, null, null, false, false);
        }
    }

    public record Result(List<ProjectResult> projects, RunMeta meta, Gate gate, Baseline.Diff diff, Path outDir) {
        public int totalFindings() {
            return projects.stream().mapToInt(p -> p.findings().size()).sum();
        }
    }

    public static Result scan(Request r) throws Exception {
        LocalDateTime started = LocalDateTime.now();
        Path root = r.repo().toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) throw new IOException("Not a directory: " + root);
        Path outDir = r.out().toAbsolutePath().normalize();

        Config repoCfg = Config.load(r.config() != null ? r.config() : root.resolve(".bairav.yml"));
        Config cfg = r.policy() == null ? repoCfg : Config.merge(Config.load(r.policy()), repoCfg);

        List<Path> projectDirs = ProjectDiscovery.find(root);
        System.out.println("Scan root: " + root);
        System.out.println("Output:    " + outDir);
        System.out.println("Projects:  " + projectDirs.size() + "\n");

        List<ToolRunner> runners = Runners.withPlugins(r.plugins());
        Analyzer.Options opts = new Analyzer.Options(outDir, r.dryRun(), r.timeoutSec(), r.build(), r.only(), r.urls(),
                r.zap(), r.verbose(), r.load());

        List<ProjectResult> projects = new ArrayList<>();
        Set<String> usedNames = new HashSet<>();
        for (Path dir : projectDirs) {
            String name = dir.equals(root) ? root.getFileName().toString() : dir.getFileName().toString();
            if (!usedNames.add(name)) {
                name = root.relativize(dir).toString().replace('/', '-');
                usedNames.add(name);
            }
            projects.add(Analyzer.analyze(root, dir, name, cfg, runners, opts));
            System.out.println();
        }
        copySboms(outDir, projects);

        RunMeta meta = RunMeta.detect(root, r.projectId(), VERSION, started,
                java.time.Duration.between(started, LocalDateTime.now()).toMillis());

        Path baselineFile = resolveBaseline(r, meta);
        Baseline.Diff diff = baselineFile == null ? null : Baseline.compare(Baseline.load(baselineFile), projects);

        Severity failOn = r.failOn() != null ? r.failOn() : cfg.failOn == null ? null : Severity.parse(cfg.failOn);
        Set<String> only = r.newOnly() && diff != null ? Gate.fingerprints(diff.added()) : null;
        Gate gate = Gate.evaluate(projects, failOn, cfg.minScore, only);

        ReportWriter.write(outDir, root, projects, diff, meta, gate);
        SarifWriter.write(outDir.resolve("report.sarif"), projects);
        String hint = "java -jar bairav.jar " + root + " --baseline " + outDir.resolve("report.json") + " --out <new-dir>";
        AiPlanWriter.write(outDir, root, projects, diff, hint, meta, gate);
        if (r.store() != null) RunStore.save(r.store().toAbsolutePath().normalize(), meta, outDir.resolve("report.json"));
        return new Result(projects, meta, gate, diff, outDir);
    }

    private static Path resolveBaseline(Request r, RunMeta meta) {
        if (r.baseline() == null) return null;
        if (!r.baseline().equals("auto")) return Path.of(r.baseline());
        if (r.store() == null) return null;
        Path latest = RunStore.latest(r.store().toAbsolutePath().normalize(), meta.projectId());
        return Files.isRegularFile(latest) ? latest : null;
    }

    private static void copySboms(Path outDir, List<ProjectResult> projects) throws IOException {
        for (ProjectResult p : projects) {
            Path sbom = outDir.resolve("work").resolve(p.name()).resolve("raw").resolve("sbom.cdx.json");
            if (Files.isRegularFile(sbom)) {
                Files.createDirectories(outDir.resolve("sbom"));
                Files.copy(sbom, outDir.resolve("sbom").resolve(p.name() + ".cdx.json"), StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
}
