package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.RepoWalker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

/**
 * Deeper performance checks that need no running app: built-bundle analysis (gzip size per chunk, shipped
 * source maps), heavy dependencies, oversized images, and JVM/Spring startup and memory hints.
 * Run `npm run build` first to get bundle results.
 */
public class PerformanceDeepRunner implements ToolRunner {

    public static final String NAME = "perf-deep";

    static final long CHUNK_WARN_GZ = 250 * 1024L;
    static final long CHUNK_HIGH_GZ = 500 * 1024L;
    static final long TOTAL_WARN_GZ = 500 * 1024L;
    static final long TOTAL_HIGH_GZ = 1024 * 1024L;
    private static final List<String> OUTPUT_DIRS = List.of("dist", "build", "out", ".next/static");

    @Override public String name() { return NAME; }

    @Override public boolean applicable(RepoInfo repo) { return !repo.stacks().isEmpty(); }

    @Override
    public ToolResult run(Context ctx) throws IOException {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        List<Finding> out = new ArrayList<>();
        Map<String, String> metrics = new LinkedHashMap<>();

        if (ctx.repo().has(RepoInfo.Stack.NODE)) {
            boolean found = false;
            for (String d : OUTPUT_DIRS) {
                Path dir = root.resolve(d);
                if (Files.isDirectory(dir) && containsJs(dir)) {
                    bundle(root, dir, out, metrics);
                    found = true;
                    break;
                }
            }
            if (!found) metrics.put("Bundle analysis", "skipped: no build output (run npm run build)");
            heavyDeps(root, out);
        }
        images(root, out);
        if (ctx.repo().has(RepoInfo.Stack.MAVEN) || ctx.repo().has(RepoInfo.Stack.GRADLE)) jvmHints(root, out);
        return ToolResult.ok(NAME, out, out.size() + " finding(s)", System.currentTimeMillis() - start).withMetrics(metrics);
    }

    private static boolean containsJs(Path dir) throws IOException {
        try (Stream<Path> s = Files.walk(dir, 4)) {
            return s.anyMatch(p -> p.toString().endsWith(".js") || p.toString().endsWith(".mjs"));
        }
    }

    // ---- bundle -----------------------------------------------------------------------------------------------

    static void bundle(Path root, Path dir, List<Finding> out, Map<String, String> metrics) throws IOException {
        record Chunk(String rel, long gz) {}
        List<Chunk> chunks = new ArrayList<>();
        List<String> maps = new ArrayList<>();
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path p : s.filter(Files::isRegularFile).toList()) {
                String n = p.getFileName().toString();
                String rel = root.relativize(p).toString().replace('\\', '/');
                if (n.endsWith(".map")) maps.add(rel);
                else if ((n.endsWith(".js") || n.endsWith(".mjs")) && Files.size(p) < 20_000_000) chunks.add(new Chunk(rel, gzipSize(Files.readAllBytes(p))));
            }
        }
        long total = chunks.stream().mapToLong(Chunk::gz).sum();
        metrics.put("Bundle JS total (gzip)", kb(total));
        chunks.stream().max(Comparator.comparingLong(Chunk::gz)).ifPresent(c -> metrics.put("Largest chunk (gzip)", c.rel() + " " + kb(c.gz())));
        metrics.put("JS chunks", String.valueOf(chunks.size()));

        for (Chunk c : chunks) {
            if (c.gz() >= CHUNK_WARN_GZ) {
                out.add(new Finding(NAME, Category.PERFORMANCE, c.gz() >= CHUNK_HIGH_GZ ? Severity.HIGH : Severity.MEDIUM, c.rel(), 0,
                        "large-js-chunk", "JavaScript chunk is " + kb(c.gz()) + " gzipped", null, null,
                        "Split it: route-level lazy loading (React.lazy + Suspense), dynamic import() for heavy libs, tree-shaking."));
            }
        }
        if (total >= TOTAL_WARN_GZ) {
            out.add(new Finding(NAME, Category.PERFORMANCE, total >= TOTAL_HIGH_GZ ? Severity.HIGH : Severity.MEDIUM,
                    root.relativize(dir).toString().replace('\\', '/'), 0, "large-total-js",
                    "Total JavaScript is " + kb(total) + " gzipped", null, null,
                    "Audit with source-map-explorer or vite-bundle-visualizer; drop or replace the largest dependencies."));
        }
        if (!maps.isEmpty()) {
            out.add(new Finding(NAME, Category.SECURITY, Severity.LOW, maps.get(0), 0, "sourcemaps-in-build",
                    maps.size() + " source map(s) in the build output expose original source if deployed", "CWE-540", "A05",
                    "Disable production source maps or upload them to your error tracker and do not serve them."));
        }
    }

    static long gzipSize(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(data);
        }
        return bos.size();
    }

    static String kb(long bytes) {
        return Math.round(bytes / 1024.0) + " KB";
    }

    // ---- dependencies / images --------------------------------------------------------------------------------

    static void heavyDeps(Path root, List<Finding> out) throws IOException {
        Path pkg = root.resolve("package.json");
        if (!Files.exists(pkg)) return;
        String t = Files.readString(pkg);
        Map<String, String[]> heavy = Map.of(
                "moment", new String[]{"~70 KB gzipped with locales", "Use date-fns or dayjs."},
                "lodash", new String[]{"~25 KB if imported whole", "Use lodash-es with named imports, or native methods."},
                "jquery", new String[]{"~30 KB and not needed with React", "Remove it; use the platform DOM APIs."});
        heavy.forEach((dep, info) -> {
            if (Pattern.compile("\"" + dep + "\"\\s*:").matcher(t).find()) {
                out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, "package.json", 0, "heavy-dependency",
                        "Heavy dependency '" + dep + "' (" + info[0] + ")", null, null, info[1]));
            }
        });
    }

    static void images(Path root, List<Finding> out) throws IOException {
        int[] n = {0};
        RepoWalker.walk(root, (p, a) -> {
            String name = p.getFileName().toString().toLowerCase();
            if (n[0] >= 20 || a.size() < 300 * 1024 || !name.matches(".*\\.(png|jpe?g|gif|bmp|tiff?)$")) return;
            String rel = root.relativize(p).toString().replace('\\', '/');
            if (rel.contains("/test") || rel.contains("fixtures")) return;
            n[0]++;
            out.add(new Finding(NAME, Category.PERFORMANCE, a.size() > 1024 * 1024 ? Severity.MEDIUM : Severity.LOW, rel, 0, "large-image",
                    "Image is " + kb(a.size()) + " and not in a modern format", null, null,
                    "Compress and convert to WebP/AVIF, serve responsive sizes, lazy-load below the fold."));
        });
    }

    // ---- JVM / Spring -----------------------------------------------------------------------------------------

    static void jvmHints(Path root, List<Finding> out) throws IOException {
        Path pom = root.resolve("pom.xml");
        if (Files.exists(pom)) {
            String t = Files.readString(pom);
            Matcher m = Pattern.compile("<(?:java\\.version|maven\\.compiler\\.(?:release|source|target))>\\s*(?:1\\.)?(\\d+)\\s*<").matcher(t);
            if (m.find() && Integer.parseInt(m.group(1)) < 17) {
                out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, "pom.xml", 0, "old-java",
                        "Java " + m.group(1) + " target: newer LTS releases have faster GC, startup and lower memory", null, null,
                        "Move to Java 21 (virtual threads, ZGC generational, better container support)."));
            }
            Matcher sb = Pattern.compile("<artifactId>spring-boot-starter-parent</artifactId>\\s*<version>\\s*(\\d+)\\.(\\d+)").matcher(t);
            if (sb.find() && Integer.parseInt(sb.group(1)) < 3) {
                out.add(new Finding(NAME, Category.BUILD_HEALTH, Severity.MEDIUM, "pom.xml", 0, "spring-boot-2",
                        "Spring Boot " + sb.group(1) + "." + sb.group(2) + " is past open-source support", "CWE-1104", "A06",
                        "Upgrade to a supported Spring Boot 3.x (needs Java 17 and the jakarta.* namespace)."));
            }
        }
        RepoWalker.walk(root, (p, a) -> {
            String n = p.getFileName().toString();
            try {
                if (n.matches("application(-\\w+)?\\.(properties|ya?ml)") && a.size() < 200_000) {
                    String t = Files.readString(p);
                    String rel = root.relativize(p).toString().replace('\\', '/');
                    if (n.equals("application.properties") || n.equals("application.yml") || n.equals("application.yaml")) {
                        if (!t.matches("(?s).*open-in-view\\s*[:=]\\s*false.*") && !t.matches("(?s).*open-in-view:\\s*false.*")
                                && Files.exists(root.resolve("pom.xml")) && Files.readString(root.resolve("pom.xml")).contains("data-jpa")) {
                            out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, rel, 0, "open-in-view-default",
                                    "spring.jpa.open-in-view defaults to true: a DB connection is held for the whole request", null, null,
                                    "Set spring.jpa.open-in-view=false and fetch what the view needs in the service layer."));
                        }
                    }
                    if (t.matches("(?is).*show-sql\\s*[:=]\\s*true.*")) {
                        out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, rel, 0, "show-sql",
                                "spring.jpa.show-sql=true writes every query to stdout", null, null,
                                "Use logging.level.org.hibernate.SQL=debug only when debugging."));
                    }
                } else if (n.equals("Dockerfile") || n.startsWith("Dockerfile.")) {
                    String t = Files.readString(p);
                    if (t.matches("(?s).*(java\\s+(-\\w+\\s+)*-jar|\"java\"\\s*,).*") && !t.matches("(?s).*(MaxRAMPercentage|-Xmx|JAVA_TOOL_OPTIONS|JAVA_OPTS).*")) {
                        out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, root.relativize(p).toString().replace('\\', '/'), 0,
                                "jvm-no-memory-flags", "JVM started without heap sizing (-XX:MaxRAMPercentage / -Xmx)", null, null,
                                "Set -XX:MaxRAMPercentage=75 so the heap follows the container memory limit; measure GC with -Xlog:gc."));
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                // skip
            }
        });
    }
}
