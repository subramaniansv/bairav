package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.RepoInfo.Stack;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.ProcessRunner;
import dev.repolens.util.RepoWalker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/** Size, dependency and build metrics; optionally times a real build with --build. */
public class BuildHealthRunner implements ToolRunner {

    private static final long BUNDLE_WARN = 500 * 1024;
    private static final long LARGE_FILE = 1024 * 1024;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String name() { return "build-health"; }

    @Override public boolean applicable(RepoInfo repo) { return true; }

    @Override
    public ToolResult run(Context ctx) throws Exception {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        List<Finding> findings = new ArrayList<>();
        Map<String, String> m = new LinkedHashMap<>();
        m.put("Detected stacks", ctx.repo().stacks().toString());

        AtomicLong javaFiles = new AtomicLong();
        AtomicLong jsFiles = new AtomicLong();
        AtomicLong loc = new AtomicLong();
        RepoWalker.walk(root, (f, a) -> {
            String n = f.getFileName().toString();
            boolean java = n.endsWith(".java");
            boolean js = n.matches(".*\\.(js|jsx|ts|tsx|mjs)$");
            if (java) javaFiles.incrementAndGet();
            if (js) jsFiles.incrementAndGet();
            if ((java || js) && a.size() < LARGE_FILE) {
                try (Stream<String> s = Files.lines(f)) {
                    loc.addAndGet(s.count());
                } catch (Exception ignored) {
                    // skip unreadable
                }
            }
            if (a.size() > LARGE_FILE && !n.matches(".*\\.(md|lock|json)$") && !isBinaryAsset(n)) {
                findings.add(new Finding(name(), Category.BUILD_HEALTH, Severity.LOW,
                        root.relativize(f).toString(), 0, "large-file",
                        "Large file in repo (" + kb(a.size()) + ")", null, null,
                        "Check if it belongs in version control (consider Git LFS or removal)."));
            }
        });
        m.put("Java files", String.valueOf(javaFiles));
        m.put("JS/TS files", String.valueOf(jsFiles));
        m.put("Lines of code (java+js/ts)", String.valueOf(loc));

        if (ctx.repo().has(Stack.MAVEN)) mavenChecks(ctx, m);
        if (ctx.repo().has(Stack.NODE)) nodeChecks(ctx, m, findings);
        artifactChecks(root, m, findings);
        if (ctx.build() && !ctx.dryRun()) timeBuild(ctx, m, findings);

        return ToolResult.ok(name(), findings, findings.size() + " finding(s)", System.currentTimeMillis() - start)
                .withMetrics(m);
    }

    private void mavenChecks(Context ctx, Map<String, String> m) throws IOException {
        String pom = Files.readString(ctx.root().resolve("pom.xml"));
        m.put("Maven <dependency> entries (root pom)", String.valueOf(Pattern.compile("<dependency>").matcher(pom).results().count()));
    }

    private void nodeChecks(Context ctx, Map<String, String> m, List<Finding> findings) throws IOException {
        Path root = ctx.root();
        JsonNode pkg = MAPPER.readTree(root.resolve("package.json").toFile());
        m.put("npm dependencies", String.valueOf(pkg.path("dependencies").size()));
        m.put("npm devDependencies", String.valueOf(pkg.path("devDependencies").size()));
        boolean lock = Files.exists(root.resolve("package-lock.json")) || Files.exists(root.resolve("yarn.lock"))
                || Files.exists(root.resolve("pnpm-lock.yaml"));
        if (!lock) {
            findings.add(new Finding(name(), Category.BUILD_HEALTH, Severity.MEDIUM, "package.json", 0,
                    "missing-lockfile", "No lockfile: builds are not reproducible and npm audit cannot run",
                    null, "A08", "Commit package-lock.json / yarn.lock / pnpm-lock.yaml."));
        }
        if (pkg.path("scripts").path("build").isMissingNode()) {
            m.put("npm build script", "none");
        }
    }

    private void artifactChecks(Path root, Map<String, String> m, List<Finding> findings) throws IOException {
        long jarBytes = 0;
        Path target = root.resolve("target");
        if (Files.isDirectory(target)) {
            try (Stream<Path> s = Files.list(target)) {
                for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".jar"))::iterator) {
                    long size = Files.size(p);
                    jarBytes += size;
                    m.put("Artifact " + p.getFileName(), kb(size));
                }
            }
        }
        for (String dir : List.of("dist", "build", "build/static")) {
            Path d = root.resolve(dir);
            if (!Files.isDirectory(d)) continue;
            AtomicLong total = new AtomicLong();
            try (Stream<Path> s = Files.walk(d)) {
                s.filter(Files::isRegularFile).forEach(f -> {
                    try {
                        long size = Files.size(f);
                        total.addAndGet(size);
                        String n = f.getFileName().toString();
                        if (size > BUNDLE_WARN && n.matches(".*\\.(js|css|mjs)$")) {
                            findings.add(new Finding(name(), Category.PERFORMANCE, Severity.MEDIUM,
                                    root.relativize(f).toString(), 0, "large-bundle",
                                    "Large front-end asset (" + kb(size) + ")", null, null,
                                    "Code-split (React.lazy / dynamic import), tree-shake, analyze with source-map-explorer."));
                        }
                    } catch (IOException ignored) {
                        // skip
                    }
                });
            }
            m.put("Front-end output size (" + dir + ")", kb(total.get()));
        }
        if (jarBytes > 100L * 1024 * 1024) {
            findings.add(new Finding("build-health", Category.BUILD_HEALTH, Severity.MEDIUM, "target", 0,
                    "huge-jar", "Total JAR size " + kb(jarBytes), null, null,
                    "Run `mvn dependency:analyze` to find unused dependencies; consider layered jars."));
        }
    }

    private void timeBuild(Context ctx, Map<String, String> m, List<Finding> findings) throws Exception {
        List<String> cmd = null;
        String label = null;
        if (ctx.repo().has(Stack.MAVEN)) {
            Path wrapper = ctx.root().resolve("mvnw");
            String mvn = Files.isExecutable(wrapper) ? wrapper.toString()
                    : (ProcessRunner.which("mvn") != null ? "mvn" : null);
            if (mvn != null) {
                cmd = List.of(mvn, "-q", "-B", "-DskipTests", "package");
                label = "Maven";
            }
        } else if (ctx.repo().has(Stack.NODE) && ProcessRunner.which("npm") != null) {
            cmd = List.of("npm", "run", "build");
            label = "npm";
        }
        if (cmd == null) {
            m.put("Build", "skipped (no build tool found)");
            return;
        }
        Path log = ctx.logFile("build");
        long t = System.currentTimeMillis();
        int exit = ProcessRunner.run(cmd, ctx.root(), log, log, ctx.timeoutSec());
        long secs = (System.currentTimeMillis() - t) / 1000;
        m.put(label + " build time", secs + "s (exit " + exit + ")");
        if (exit != 0) {
            findings.add(new Finding(name(), Category.BUILD_HEALTH, Severity.HIGH, ".", 0, "build-failed",
                    label + " build failed or timed out (exit " + exit + ")", null, null, "See " + log));
        } else if (secs > 300) {
            findings.add(new Finding(name(), Category.BUILD_HEALTH, Severity.LOW, ".", 0, "slow-build",
                    label + " build took " + secs + "s", null, null, "Enable build cache / parallel builds."));
        }
    }

    private static boolean isBinaryAsset(String n) {
        return n.matches("(?i).*\\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|pdf)$");
    }

    static String kb(long bytes) {
        return bytes >= 1024 * 1024 ? String.format("%.1f MB", bytes / 1048576.0) : (bytes / 1024) + " KB";
    }
}
