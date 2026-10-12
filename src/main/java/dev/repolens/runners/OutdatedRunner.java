package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.ProcessRunner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Outdated-dependency report with upgrade effort (Renovate/Dependabot style), using `npm outdated` and the
 * Maven versions plugin. Needs network access; a failure leaves the other checks untouched.
 */
public class OutdatedRunner implements ToolRunner {

    public static final String NAME = "outdated-deps";

    private static final int CAP = 40;
    private static final Pattern MVN_LINE = Pattern.compile("^\\s*([\\w.\\-]+:[\\w.\\-]+)\\s*\\.{2,}\\s*(\\S+)\\s*->\\s*(\\S+)\\s*$");

    @Override public String name() { return NAME; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return repo.has(RepoInfo.Stack.NODE) || repo.has(RepoInfo.Stack.MAVEN);
    }

    @Override
    public ToolResult run(Context ctx) throws Exception {
        long start = System.currentTimeMillis();
        if (ctx.dryRun()) return ToolResult.skipped(NAME, "dry run");
        List<Finding> out = new ArrayList<>();
        Map<String, String> metrics = new LinkedHashMap<>();
        List<String> notes = new ArrayList<>();

        if (ctx.repo().has(RepoInfo.Stack.NODE) && Files.exists(ctx.root().resolve("package.json"))) {
            if (ProcessRunner.which("npm") == null) notes.add("npm missing");
            else npm(ctx, out, metrics, notes);
        }
        if (ctx.repo().has(RepoInfo.Stack.MAVEN) && Files.exists(ctx.root().resolve("pom.xml"))) {
            Path mvn = Files.isExecutable(ctx.root().resolve("mvnw")) ? ctx.root().resolve("mvnw") : ProcessRunner.which("mvn");
            if (mvn == null) notes.add("mvn missing");
            else maven(ctx, mvn, out, metrics, notes);
        }
        if (out.isEmpty() && metrics.isEmpty() && !notes.isEmpty()) return ToolResult.skipped(NAME, String.join("; ", notes));
        String detail = out.size() + " finding(s)" + (notes.isEmpty() ? "" : " (" + String.join("; ", notes) + ")");
        return ToolResult.ok(NAME, out, detail, System.currentTimeMillis() - start).withMetrics(metrics);
    }

    private void npm(Context ctx, List<Finding> out, Map<String, String> metrics, List<String> notes) throws Exception {
        Path raw = ctx.rawFile("npm-outdated.json");
        int rc = ProcessRunner.run(List.of(ProcessRunner.which("npm").toString(), "outdated", "--json"), ctx.root(), raw,
                ctx.logFile(NAME), Math.min(ctx.timeoutSec(), 180));
        if (rc == ProcessRunner.TIMEOUT || !Files.exists(raw) || Files.size(raw) == 0) {
            notes.add("npm outdated: no output (offline?)");
            return;
        }
        JsonNode root = new ObjectMapper().readTree(raw.toFile());
        int total = 0;
        int majors = 0;
        for (Map.Entry<String, JsonNode> e : (Iterable<Map.Entry<String, JsonNode>>) root::fields) {
            JsonNode v = e.getValue();
            String current = v.path("current").asText(v.path("wanted").asText(""));
            String latest = v.path("latest").asText("");
            if (current.isEmpty() || latest.isEmpty() || current.equals(latest)) continue;
            total++;
            Finding f = finding(e.getKey(), current, latest, "package.json");
            if (f != null) {
                majors++;
                if (out.size() < CAP) out.add(f);
            }
        }
        metrics.put("npm outdated packages", String.valueOf(total));
        metrics.put("npm majors behind", String.valueOf(majors));
    }

    private void maven(Context ctx, Path mvn, List<Finding> out, Map<String, String> metrics, List<String> notes) throws Exception {
        Path raw = ctx.rawFile("mvn-updates.txt");
        Files.createDirectories(raw.getParent());
        Files.deleteIfExists(raw);
        int rc = ProcessRunner.run(List.of(mvn.toString(), "-B", "-q", "versions:display-dependency-updates",
                "-DprocessDependencyManagement=false", "-DoutputFile=" + raw.toAbsolutePath()), ctx.root(),
                ctx.logFile(NAME), ctx.logFile(NAME), Math.min(ctx.timeoutSec(), 300));
        if (rc != 0 || !Files.exists(raw)) {
            notes.add("maven versions plugin failed (offline?) - see logs/" + NAME + ".log");
            return;
        }
        int total = 0;
        int majors = 0;
        for (String line : Files.readAllLines(raw)) {
            Matcher m = MVN_LINE.matcher(line);
            if (!m.matches()) continue;
            total++;
            Finding f = finding(m.group(1), m.group(2), m.group(3), "pom.xml");
            if (f != null) {
                majors++;
                if (out.size() < CAP) out.add(f);
            }
        }
        metrics.put("maven outdated dependencies", String.valueOf(total));
        metrics.put("maven majors behind", String.valueOf(majors));
    }

    /** Only major-version gaps become findings; minor/patch lag is counted in metrics. */
    static Finding finding(String pkg, String current, String latest, String file) {
        int cm = major(current);
        int lm = major(latest);
        if (cm < 0 || lm < 0 || lm <= cm) return null;
        int gap = lm - cm;
        Severity sev = gap >= 2 ? Severity.MEDIUM : Severity.LOW;
        String effort = gap >= 2 ? "high effort: " + gap + " major versions of breaking changes"
                : "medium effort: one major version (read the migration guide)";
        return new Finding(NAME, Category.BUILD_HEALTH, sev, file, 0, "outdated-major",
                pkg + " is " + gap + " major version(s) behind (" + current + " -> " + latest + ")",
                "CWE-1104", "A06", "Upgrade " + pkg + " to " + latest + " (" + effort + ").");
    }

    static int major(String v) {
        Matcher m = Pattern.compile("(\\d+)").matcher(v == null ? "" : v);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }
}
