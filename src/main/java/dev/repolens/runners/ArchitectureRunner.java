package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.RepoWalker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Architecture and test-health checks without an external install (ArchUnit/madge/knip style):
 * Java layering violations, circular JS/TS imports, orphan modules, unused Java imports/private methods,
 * and skipped / focused / sleep-based / assertion-free tests.
 */
public class ArchitectureRunner implements ToolRunner {

    public static final String NAME = "architecture";

    private static final Pattern JS_IMPORT = Pattern.compile(
            "(?:import\\s+(?:[^'\"();]*?\\s+from\\s+)?|export\\s+[^'\"();]*?\\s+from\\s+|import\\s*\\(\\s*|require\\s*\\(\\s*)['\"]([^'\"]+)['\"]");
    private static final String[] EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs"};
    private static final Pattern JAVA_IMPORT = Pattern.compile("^import\\s+(?:static\\s+)?([\\w.]+)\\.(\\w+|\\*);");
    private static final Pattern PRIVATE_METHOD = Pattern.compile("^\\s*private\\s+(?:static\\s+)?(?:final\\s+)?[\\w<>\\[\\],.? ]+\\s+(\\w+)\\s*\\(");
    private static final Set<String> ENTRY = Set.of("index", "main", "app", "setuptests", "vite-env.d", "reportwebvitals", "serviceworker");
    private static final int CAP = 40;

    @Override public String name() { return NAME; }

    @Override public boolean applicable(RepoInfo repo) { return !repo.stacks().isEmpty(); }

    @Override
    public ToolResult run(Context ctx) throws IOException {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        List<Finding> out = new ArrayList<>();
        Map<String, Path> jsFiles = new LinkedHashMap<>();
        List<Path> javaFiles = new ArrayList<>();

        RepoWalker.walk(root, (p, a) -> {
            String n = p.getFileName().toString();
            if (a.size() > 400_000) return;
            if (n.endsWith(".java")) javaFiles.add(p);
            else if (isJs(n)) jsFiles.put(rel(root, p), p);
        });

        for (Path p : javaFiles) java(root, p, out);
        for (Map.Entry<String, Path> e : jsFiles.entrySet()) {
            if (isTest(e.getKey())) jsTest(e.getKey(), e.getValue(), out);
        }
        jsGraph(root, jsFiles, out);
        return ToolResult.ok(NAME, out, out.size() + " finding(s)", System.currentTimeMillis() - start);
    }

    // ---- Java -------------------------------------------------------------------------------------------------

    static void java(Path root, Path p, List<Finding> out) {
        String rel = rel(root, p);
        List<String> lines;
        try {
            lines = Files.readAllLines(p);
        } catch (IOException | RuntimeException e) {
            return;
        }
        String text = String.join("\n", lines);
        boolean test = isTest(rel);
        if (test) {
            javaTest(rel, lines, text, out);
            return;
        }
        boolean controller = text.contains("@RestController") || text.contains("@Controller");
        boolean service = text.contains("@Service");
        if (controller) {
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i);
                Matcher m = JAVA_IMPORT.matcher(l.trim());
                if (m.find() && m.group(2).endsWith("Repository") && !l.contains("//")) {
                    add(out, Severity.MEDIUM, rel, i + 1, "controller-uses-repository",
                            "Controller depends on repository " + m.group(2) + " directly (skips the service layer)",
                            "Move data access behind a @Service; controllers should call services only.");
                    break;
                }
            }
        }
        if (service) {
            for (int i = 0; i < lines.size(); i++) {
                Matcher m = JAVA_IMPORT.matcher(lines.get(i).trim());
                if (m.find() && m.group(1).matches(".*\\.(controller|web|rest)s?") ) {
                    add(out, Severity.MEDIUM, rel, i + 1, "service-uses-controller",
                            "Service depends on the web layer (" + m.group(2) + "): layering inverted",
                            "Services must not import controllers/web types; pass plain DTOs instead.");
                    break;
                }
            }
        }
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).trim().equals("@Autowired") && i + 1 < lines.size()
                    && lines.get(i + 1).trim().matches("(private|protected)\\s+(final\\s+)?[\\w<>,.? ]+\\s+\\w+;")) {
                add(out, Severity.LOW, rel, i + 2, "field-injection",
                        "Field injection hides dependencies and blocks immutability/testing",
                        "Use constructor injection (a final field + constructor).");
                break;
            }
        }
        // unused imports (skip wildcard and annotation-only guesses: name must not appear anywhere else)
        int unused = 0;
        for (int i = 0; i < lines.size() && unused < 5; i++) {
            Matcher m = JAVA_IMPORT.matcher(lines.get(i).trim());
            if (!m.find() || m.group(2).equals("*") || lines.get(i).contains("import static")) continue;
            String simple = m.group(2);
            Pattern use = Pattern.compile("\\b" + Pattern.quote(simple) + "\\b");
            long uses = lines.stream().filter(l -> !l.trim().startsWith("import ")).filter(l -> use.matcher(l).find()).count();
            if (uses == 0) {
                add(out, Severity.LOW, rel, i + 1, "unused-import", "Unused import " + simple, "Remove it (IDE: Optimize Imports).");
                unused++;
            }
        }
        // unused private methods
        for (int i = 0; i < lines.size(); i++) {
            Matcher m = PRIVATE_METHOD.matcher(lines.get(i));
            if (!m.find()) continue;
            String name = m.group(1);
            Pattern call = Pattern.compile("\\b" + Pattern.quote(name) + "\\b");
            long refs = lines.stream().filter(l -> call.matcher(l).find()).count();
            boolean reflective = i > 0 && lines.get(i - 1).trim().startsWith("@");
            if (refs <= 1 && !reflective) {
                add(out, Severity.LOW, rel, i + 1, "unused-private-method", "Private method " + name + "() is never called",
                        "Delete it if it is really dead code.");
            }
        }
    }

    static void javaTest(String rel, List<String> lines, String text, List<Finding> out) {
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i).trim();
            if (l.startsWith("@Disabled") || l.startsWith("@Ignore")) {
                add(out, Severity.LOW, rel, i + 1, "test-disabled", "Disabled test (coverage silently lost)",
                        "Fix and re-enable it, or delete it with a note on why.");
            } else if (l.contains("Thread.sleep(")) {
                add(out, Severity.LOW, rel, i + 1, "test-sleep", "Thread.sleep in a test is a common flakiness source",
                        "Use Awaitility or a deterministic clock/latch instead.");
            }
        }
        if (text.contains("@Test") && !text.matches("(?s).*(assert|verify|expect|fail\\(|andExpect|should|assertThat).*")) {
            add(out, Severity.MEDIUM, rel, 1, "test-no-assertions", "Test class has @Test methods but no assertions",
                    "Assert on outcomes; a test that cannot fail proves nothing.");
        }
    }

    // ---- JS / TS ----------------------------------------------------------------------------------------------

    static void jsTest(String rel, Path p, List<Finding> out) {
        List<String> lines;
        try {
            lines = Files.readAllLines(p);
        } catch (IOException | RuntimeException e) {
            return;
        }
        String text = String.join("\n", lines);
        Pattern skip = Pattern.compile("\\b(xit|xdescribe|xtest)\\s*\\(|\\b(it|test|describe)\\.skip\\b");
        Pattern only = Pattern.compile("\\b(fit|fdescribe)\\s*\\(|\\b(it|test|describe)\\.only\\b");
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            if (skip.matcher(l).find()) {
                add(out, Severity.LOW, rel, i + 1, "test-skipped", "Skipped test (coverage silently lost)", "Fix and re-enable it, or delete it.");
            } else if (only.matcher(l).find()) {
                add(out, Severity.MEDIUM, rel, i + 1, "test-focused", "Focused test (.only) silently skips all others",
                        "Remove .only before committing.");
            } else if (l.contains("setTimeout(") || l.contains("waitForTimeout(")) {
                add(out, Severity.LOW, rel, i + 1, "test-timer", "Real timers in tests cause flakiness",
                        "Use fake timers or await the condition (waitFor / findBy*).");
            }
        }
        if (text.matches("(?s).*\\b(it|test)\\s*\\(.*") && !text.matches("(?s).*(expect\\s*\\(|assert|should|toBe).*")) {
            add(out, Severity.MEDIUM, rel, 1, "test-no-assertions", "Test file has tests but no assertions",
                    "Assert on outcomes; a test that cannot fail proves nothing.");
        }
    }

    static void jsGraph(Path root, Map<String, Path> files, List<Finding> out) {
        Map<String, Set<String>> graph = new HashMap<>();
        Set<String> imported = new HashSet<>();
        for (Map.Entry<String, Path> e : files.entrySet()) {
            Set<String> deps = new HashSet<>();
            String text;
            try {
                text = Files.readString(e.getValue());
            } catch (IOException | RuntimeException ex) {
                continue;
            }
            Matcher m = JS_IMPORT.matcher(text);
            while (m.find()) {
                String spec = m.group(1);
                if (!spec.startsWith(".")) continue;
                String target = resolve(e.getKey(), spec, files);
                if (target != null) {
                    deps.add(target);
                    imported.add(target);
                }
            }
            graph.put(e.getKey(), deps);
        }
        // referenced from html entry points
        try {
            RepoWalker.walk(root, (p, a) -> {
                if (p.getFileName().toString().endsWith(".html") && a.size() < 200_000) {
                    try {
                        String h = Files.readString(p);
                        Matcher m = Pattern.compile("src=['\"]([^'\"]+)['\"]").matcher(h);
                        while (m.find()) {
                            String t = resolve(rel(root, p), m.group(1).startsWith("/") ? "." + m.group(1) : m.group(1), files);
                            if (t != null) imported.add(t);
                        }
                    } catch (IOException | RuntimeException ignored) {
                        // skip
                    }
                }
            });
        } catch (IOException ignored) {
            // skip
        }

        // circular dependencies (Tarjan SCC) among non-test modules
        Tarjan t = new Tarjan(graph);
        int cycles = 0;
        for (List<String> scc : t.run()) {
            if (scc.size() < 2 || cycles >= 15) continue;
            Collections.sort(scc);
            add(out, Severity.MEDIUM, scc.get(0), 1, "circular-dependency",
                    "Circular import among " + scc.size() + " modules: " + String.join(" <-> ", scc.stream().limit(4).toList())
                            + (scc.size() > 4 ? " ..." : ""),
                    "Extract the shared code into a third module or invert one dependency.");
            cycles++;
        }

        // orphan modules
        int orphans = 0;
        for (String f : files.keySet()) {
            if (orphans >= CAP || imported.contains(f) || isTest(f)) continue;
            String base = f.substring(f.lastIndexOf('/') + 1);
            String stem = base.substring(0, base.lastIndexOf('.')).toLowerCase();
            if (ENTRY.contains(stem) || base.contains(".config.") || base.endsWith(".d.ts") || base.contains(".stories.")
                    || f.contains("/pages/") || f.contains("/app/") || f.startsWith("pages/") || f.startsWith("app/")
                    || f.contains("/scripts/") || f.startsWith("scripts/") || f.contains("/public/") || f.startsWith("public/")
                    || f.contains("/bin/") || f.startsWith("bin/") || f.contains("/api/") || f.startsWith("api/")) continue;
            add(out, Severity.LOW, f, 1, "orphan-module", "Module is never imported (possibly dead code)",
                    "Delete it, or wire it up if it is an entry point.");
            orphans++;
        }
    }

    static String resolve(String from, String spec, Map<String, Path> files) {
        String dir = from.contains("/") ? from.substring(0, from.lastIndexOf('/')) : "";
        String joined = normalize(dir.isEmpty() ? spec : dir + "/" + spec);
        if (files.containsKey(joined)) return joined;
        for (String e : EXTS) if (files.containsKey(joined + e)) return joined + e;
        for (String e : EXTS) if (files.containsKey(joined + "/index" + e)) return joined + "/index" + e;
        return null;
    }

    static String normalize(String path) {
        List<String> parts = new ArrayList<>();
        for (String s : path.split("/")) {
            if (s.equals(".") || s.isEmpty()) continue;
            if (s.equals("..")) {
                if (!parts.isEmpty()) parts.remove(parts.size() - 1);
            } else parts.add(s);
        }
        return String.join("/", parts);
    }

    /** Strongly connected components. Recursion depth equals the longest import chain, which is small. */
    static final class Tarjan {
        private final Map<String, Set<String>> g;
        private final Map<String, Integer> idx = new HashMap<>();
        private final Map<String, Integer> low = new HashMap<>();
        private final List<String> stack = new ArrayList<>();
        private final Set<String> on = new HashSet<>();
        private final List<List<String>> result = new ArrayList<>();
        private int counter;

        Tarjan(Map<String, Set<String>> g) { this.g = g; }

        List<List<String>> run() {
            for (String v : g.keySet()) if (!idx.containsKey(v)) visit(v);
            return result;
        }

        private void visit(String v) {
            idx.put(v, counter);
            low.put(v, counter++);
            stack.add(v);
            on.add(v);
            for (String w : g.getOrDefault(v, Set.of())) {
                if (!idx.containsKey(w)) {
                    visit(w);
                    low.put(v, Math.min(low.get(v), low.get(w)));
                } else if (on.contains(w)) {
                    low.put(v, Math.min(low.get(v), idx.get(w)));
                }
            }
            if (low.get(v).equals(idx.get(v))) {
                List<String> scc = new ArrayList<>();
                String w;
                do {
                    w = stack.remove(stack.size() - 1);
                    on.remove(w);
                    scc.add(w);
                } while (!w.equals(v));
                result.add(scc);
            }
        }
    }

    // ---- helpers ----------------------------------------------------------------------------------------------

    private static boolean isJs(String n) {
        return (n.endsWith(".js") || n.endsWith(".jsx") || n.endsWith(".ts") || n.endsWith(".tsx") || n.endsWith(".mjs"))
                && !n.endsWith(".min.js");
    }

    static boolean isTest(String rel) {
        String r = "/" + rel.toLowerCase();
        return r.contains("/test/") || r.contains("/tests/") || r.contains("/__tests__/") || r.contains("/e2e/")
                || r.matches(".*\\.(test|spec)\\.[a-z]+$") || rel.matches(".*(Test|Tests|IT)\\.java$");
    }

    private static String rel(Path root, Path p) {
        return root.relativize(p).toString().replace('\\', '/');
    }

    private static void add(List<Finding> out, Severity s, String file, int line, String rule, String msg, String fix) {
        out.add(new Finding(NAME, Category.QUALITY, s, file, line, rule, msg, null, null, fix));
    }
}
