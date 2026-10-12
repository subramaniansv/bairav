package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.RepoWalker;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Reads coverage reports the project's own test run already produced (JaCoCo XML, LCOV, Istanbul
 * json-summary); it never runs tests itself. Also counts test files vs source files.
 */
public class CoverageRunner implements ToolRunner {

    public static final String NAME = "coverage";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final List<String> JACOCO = List.of("target/site/jacoco/jacoco.xml", "build/reports/jacoco/test/jacocoTestReport.xml");
    private static final List<String> LCOV = List.of("coverage/lcov.info", "coverage/lcov/lcov.info");
    private static final List<String> ISTANBUL = List.of("coverage/coverage-summary.json");

    public record Coverage(String source, double linePct, double branchPct) {}

    @Override public String name() { return NAME; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return !repo.stacks().isEmpty();
    }

    @Override
    public ToolResult run(Context ctx) throws Exception {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        boolean java = ctx.repo().has(RepoInfo.Stack.MAVEN) || ctx.repo().has(RepoInfo.Stack.GRADLE);
        List<Finding> findings = new ArrayList<>();
        Map<String, String> m = new LinkedHashMap<>();

        AtomicInteger src = new AtomicInteger();
        AtomicInteger tests = new AtomicInteger();
        RepoWalker.walk(root, (p, a) -> {
            String n = p.getFileName().toString();
            if (!(n.endsWith(".java") || n.matches(".*\\.(js|jsx|ts|tsx|mjs)$")) || n.endsWith(".d.ts")) return;
            String rel = root.relativize(p).toString().replace('\\', '/');
            boolean isTest = rel.contains("src/test/") || rel.contains("__tests__/") || rel.startsWith("tests/") || rel.contains("/tests/")
                    || n.matches(".*\\.(test|spec)\\.[jt]sx?$") || n.matches(".*(Test|Tests|IT)\\.java$");
            (isTest ? tests : src).incrementAndGet();
        });
        m.put("Source files", String.valueOf(src.get()));
        m.put("Test files", String.valueOf(tests.get()));

        String manifest = java ? (Files.exists(root.resolve("pom.xml")) ? "pom.xml" : "build.gradle") : "package.json";
        if (src.get() > 0 && tests.get() == 0) {
            findings.add(new Finding(NAME, Category.QUALITY, Severity.HIGH, manifest, 0, "coverage/no-tests",
                    "No automated tests found", "CWE-1059", null,
                    "Add unit tests for the core logic first (services, utilities, reducers), then run them in CI."));
        }

        Coverage cov = find(root);
        if (cov == null) {
            if (tests.get() > 0) {
                findings.add(new Finding(NAME, Category.QUALITY, Severity.LOW, manifest, 0, "coverage/no-report",
                        "Tests exist but no coverage report was found", null, null, java
                        ? "Add the JaCoCo Maven plugin (prepare-agent + report goals) and run `mvn verify` before Bairav."
                        : "Run the tests with coverage (e.g. `vitest run --coverage` / `jest --coverage` with the lcov or json-summary reporter) before Bairav."));
            }
            m.put("Coverage", "no report found");
        } else {
            m.put("Coverage source", cov.source());
            m.put("Line coverage", String.format("%.1f%%", cov.linePct()));
            if (cov.branchPct() >= 0) m.put("Branch coverage", String.format("%.1f%%", cov.branchPct()));
            int min = ctx.config().minCoverage();
            if (cov.linePct() < min) {
                Severity s = cov.linePct() < min / 2.0 ? Severity.HIGH : Severity.MEDIUM;
                findings.add(new Finding(NAME, Category.QUALITY, s, manifest, 0, "coverage/below-threshold",
                        "Line coverage is below the required " + min + "%", "CWE-1059", null,
                        String.format("Currently %.1f%%. Add tests for the least-covered packages until coverage reaches %d%%.",
                                cov.linePct(), min)));
            }
        }
        return ToolResult.ok(NAME, findings, findings.size() + " finding(s)", System.currentTimeMillis() - start).withMetrics(m);
    }

    static Coverage find(Path root) throws Exception {
        for (String r : JACOCO) if (Files.isRegularFile(root.resolve(r))) return parseJacoco(root.resolve(r));
        for (String r : LCOV) if (Files.isRegularFile(root.resolve(r))) return parseLcov(root.resolve(r));
        for (String r : ISTANBUL) if (Files.isRegularFile(root.resolve(r))) return parseIstanbul(root.resolve(r));
        return null;
    }

    static Coverage parseJacoco(Path xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        Document d = f.newDocumentBuilder().parse(xml.toFile());
        double line = -1;
        double branch = -1;
        NodeList kids = d.getDocumentElement().getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            if (!(kids.item(i) instanceof Element e) || !e.getTagName().equals("counter")) continue;
            double missed = Double.parseDouble(e.getAttribute("missed"));
            double covered = Double.parseDouble(e.getAttribute("covered"));
            double pct = missed + covered == 0 ? 100 : covered * 100 / (missed + covered);
            if (e.getAttribute("type").equals("LINE")) line = pct;
            if (e.getAttribute("type").equals("BRANCH")) branch = pct;
        }
        return new Coverage("JaCoCo " + xml.getFileName(), Math.max(line, 0), branch);
    }

    static Coverage parseLcov(Path file) throws Exception {
        long lf = 0, lh = 0, bf = 0, bh = 0;
        for (String l : Files.readAllLines(file)) {
            if (l.startsWith("LF:")) lf += Long.parseLong(l.substring(3).trim());
            else if (l.startsWith("LH:")) lh += Long.parseLong(l.substring(3).trim());
            else if (l.startsWith("BRF:")) bf += Long.parseLong(l.substring(4).trim());
            else if (l.startsWith("BRH:")) bh += Long.parseLong(l.substring(4).trim());
        }
        return new Coverage("LCOV " + file.getFileName(), lf == 0 ? 0 : lh * 100.0 / lf, bf == 0 ? -1 : bh * 100.0 / bf);
    }

    static Coverage parseIstanbul(Path file) throws Exception {
        JsonNode t = MAPPER.readTree(file.toFile()).path("total");
        double b = t.path("branches").path("pct").isNumber() ? t.path("branches").path("pct").asDouble() : -1;
        return new Coverage("Istanbul " + file.getFileName(), t.path("lines").path("pct").asDouble(0), b);
    }
}
