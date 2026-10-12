package dev.repolens.cli;

import dev.repolens.config.Config;
import dev.repolens.detect.StackDetector;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.ToolResult;
import dev.repolens.owasp.OwaspMapper;
import dev.repolens.runners.SeoRunner;
import dev.repolens.runners.ToolRunner;
import dev.repolens.score.Scorer;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Runs every applicable runner on one project and normalises the output. */
public final class Analyzer {

    public record Options(Path outDir, boolean dryRun, int timeoutSec, boolean build, Set<String> only,
                          java.util.Map<String, String> urls, boolean zap, boolean verbose, boolean load) {}

    private Analyzer() {}

    public static ProjectResult analyze(Path scanRoot, Path projectDir, String name, Config config,
                                        List<ToolRunner> runners, Options o) {
        RepoInfo info = StackDetector.detect(projectDir);
        String rel = scanRoot.equals(projectDir) ? "." : scanRoot.relativize(projectDir).toString();
        String url = o.urls().getOrDefault(name, o.urls().get("*"));
        ToolRunner.Context ctx = new ToolRunner.Context(info, o.outDir().resolve("work").resolve(name), o.dryRun(),
                o.timeoutSec(), o.build(), url, o.zap(), config, o.load());

        System.out.println("== " + name + " (" + rel + ") " + (info.stacks().isEmpty() ? "[no stack detected]" : info.stacks()));
        List<ToolResult> results = new ArrayList<>();
        for (ToolRunner r : runners) {
            if (!o.only().isEmpty() && !o.only().contains(r.name())) continue;
            if (!r.applicable(info)) continue;
            if (config.disableRunners.contains(r.name())
                    || config.disableRunnersFor.getOrDefault(name, List.of()).contains(r.name())) continue;
            System.out.printf("   %-14s ", r.name());
            ToolResult res;
            try {
                res = r.run(ctx);
            } catch (Exception e) {
                if (o.verbose()) e.printStackTrace();
                res = ToolResult.failed(r.name(), e.toString(), 0);
            }
            System.out.printf("%-8s %s%n", res.status(), res.detail());
            results.add(res);
        }

        List<Finding> all = results.stream().flatMap(r -> r.findings().stream())
                .map(f -> f.withFile(prefix(rel, f.file())))
                .map(OwaspMapper::tag)
                .toList();
        List<Finding> kept = dedupeDependencies(
                all.stream().map(config::apply).filter(java.util.Objects::nonNull).distinct().toList());

        boolean web = results.stream().anyMatch(r -> r.tool().equals(SeoRunner.NAME)
                && r.status() == ToolResult.Status.OK
                && SeoRunner.SCOPE_ACTIVE.equals(r.metrics().get(SeoRunner.SCOPE_KEY)));
        Scorer.Scores scores = Scorer.compute(kept, web);
        System.out.println("   -> " + scores.grade() + " (" + scores.overall() + "), " + kept.size() + " findings"
                + (all.size() != kept.size() ? ", " + (all.size() - kept.size()) + " suppressed" : ""));
        return new ProjectResult(name, rel, info.stacks(), results, kept, all.size() - kept.size(), scores, web);
    }

    /** Trivy and OSV-Scanner both report the same CVE per package: keep one (first seen, upgraded to the higher severity). */
    static List<Finding> dedupeDependencies(List<Finding> in) {
        java.util.regex.Pattern pkg = java.util.regex.Pattern.compile("Package:? '?([^\\s;@']+)");
        java.util.Map<String, Finding> seen = new java.util.LinkedHashMap<>();
        List<Finding> out = new ArrayList<>();
        for (Finding f : in) {
            java.util.regex.Matcher m = pkg.matcher(f.message());
            if (f.category() != dev.repolens.model.Category.DEPENDENCY || !m.find()) {
                out.add(f);
                continue;
            }
            String key = f.rule() + "|" + f.file() + "|" + m.group(1);
            Finding prev = seen.get(key);
            if (prev == null) {
                seen.put(key, f);
                out.add(f);
            } else if (f.severity().weight > prev.severity().weight) {
                out.set(out.indexOf(prev), prev.withSeverity(f.severity()));
                seen.put(key, prev.withSeverity(f.severity()));
            }
        }
        return out;
    }

    private static String prefix(String rel, String file) {
        if (rel.equals(".") || file.startsWith("http")) return file;
        if (file.equals(".") || file.isEmpty()) return rel;
        return rel + "/" + file;
    }
}
