package dev.repolens;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.config.Config;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.report.Gate;
import dev.repolens.report.RunMeta;
import dev.repolens.report.RunStore;
import dev.repolens.runners.CodeQualityRunner;
import dev.repolens.runners.CoverageRunner;
import dev.repolens.runners.SbomLicenseRunner;
import dev.repolens.runners.ToolRunner;
import dev.repolens.score.Scorer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformTest {

    @TempDir
    Path tmp;

    private ToolRunner.Context ctx(Path root, Config cfg) {
        RepoInfo info = new RepoInfo(root, Set.of(RepoInfo.Stack.NODE));
        return new ToolRunner.Context(info, tmp.resolve("work"), false, 10, false, null, false, cfg);
    }

    @Test
    void licenseRulesFlagCopyleftAndHonourPolicy() throws Exception {
        String bom = "{\"components\":["
                + "{\"type\":\"library\",\"name\":\"a\",\"version\":\"1\",\"licenses\":[{\"license\":{\"id\":\"MIT\"}}]},"
                + "{\"type\":\"library\",\"name\":\"b\",\"version\":\"1\",\"licenses\":[{\"license\":{\"id\":\"AGPL-3.0-only\"}}]},"
                + "{\"type\":\"library\",\"name\":\"c\",\"version\":\"1\",\"licenses\":[{\"license\":{\"id\":\"LGPL-2.1\"}}]},"
                + "{\"type\":\"library\",\"name\":\"d\",\"version\":\"1\"}]}";
        var node = new ObjectMapper().readTree(bom);

        List<Finding> defaults = SbomLicenseRunner.evaluate(node, new Config(), "pom.xml");
        assertEquals(3, defaults.size());
        assertTrue(defaults.stream().anyMatch(f -> f.severity() == Severity.HIGH && f.message().contains("AGPL")));
        assertTrue(defaults.stream().anyMatch(f -> f.rule().equals("license/unknown")));
        assertTrue(defaults.stream().allMatch(f -> f.category() == Category.LICENSE));

        Config strict = new Config();
        strict.licenseDeny = List.of("LGPL");
        strict.allowUnknownLicenses = true;
        List<Finding> custom = SbomLicenseRunner.evaluate(node, strict, "pom.xml");
        assertEquals(1, custom.size());
        assertEquals(Severity.HIGH, custom.get(0).severity());
    }

    @Test
    void complexMethodAndDuplicatesAreFound() throws Exception {
        Path src = Files.createDirectories(tmp.resolve("proj/src"));
        StringBuilder body = new StringBuilder("public class A {\n  int run(int x, int y) {\n    int r = 0;\n");
        for (int i = 0; i < 20; i++) body.append("    if (x > ").append(i).append(" && y < ").append(i).append(") { r += ").append(i).append("; }\n");
        body.append("    return r;\n  }\n}\n");
        Files.writeString(src.resolve("A.java"), body.toString());
        StringBuilder dup = new StringBuilder();
        for (int i = 0; i < 12; i++) dup.append("const value").append(i).append(" = compute(").append(i).append(", 'abc');\n");
        Files.writeString(src.resolve("one.js"), dup.toString());
        Files.writeString(src.resolve("two.js"), dup.toString());

        Config cfg = new Config();
        cfg.maxComplexity = 10;
        ToolResult r = new CodeQualityRunner().run(ctx(tmp.resolve("proj"), cfg));

        assertEquals(ToolResult.Status.OK, r.status());
        assertTrue(r.findings().stream().anyMatch(f -> f.rule().equals("quality/high-complexity") && f.message().contains("run")));
        assertTrue(r.findings().stream().anyMatch(f -> f.rule().equals("quality/duplicate-block")));
        assertNotNull(r.metrics().get("Duplicated lines"));
    }

    @Test
    void jsMethodComplexityIgnoresStringsAndComments() throws Exception {
        Path src = Files.createDirectories(tmp.resolve("p2/src"));
        Files.writeString(src.resolve("x.ts"), "export const f = (a: number) => {\n  // if (a) while (a)\n"
                + "  const s = \"if && || while\";\n  return a ? 1 : 2;\n};\n");
        ToolResult r = new CodeQualityRunner().run(ctx(tmp.resolve("p2"), new Config()));
        assertEquals("2", r.metrics().get("Max complexity"));
    }

    @Test
    void coverageIsParsedAndThresholdEnforced() throws Exception {
        Path root = Files.createDirectories(tmp.resolve("cov"));
        Files.createDirectories(root.resolve("coverage"));
        Files.createDirectories(root.resolve("src"));
        Files.writeString(root.resolve("src/a.ts"), "export const a = 1;\n");
        Files.writeString(root.resolve("src/a.test.ts"), "test('a', () => {});\n");
        Files.writeString(root.resolve("coverage/lcov.info"), "SF:a\nLF:10\nLH:4\nBRF:0\nBRH:0\nend_of_record\n");
        Config cfg = new Config();
        cfg.minCoverage = 70;
        ToolResult r = new CoverageRunner().run(ctx(root, cfg));
        assertEquals("40.0%", r.metrics().get("Line coverage"));
        assertTrue(r.findings().stream().anyMatch(f -> f.rule().equals("coverage/below-threshold")));

        Path bare = Files.createDirectories(tmp.resolve("bare/src"));
        Files.writeString(bare.resolve("a.ts"), "export const a = 1;\n");
        ToolResult none = new CoverageRunner().run(ctx(tmp.resolve("bare"), new Config()));
        assertTrue(none.findings().stream().anyMatch(f -> f.rule().equals("coverage/no-tests") && f.severity() == Severity.HIGH));
    }

    @Test
    void jacocoXmlWithDoctypeParses() throws Exception {
        Path root = Files.createDirectories(tmp.resolve("jac/target/site/jacoco"));
        Files.writeString(root.resolve("jacoco.xml"), "<?xml version=\"1.0\"?>\n"
                + "<!DOCTYPE report PUBLIC \"-//JACOCO//DTD Report 1.1//EN\" \"report.dtd\">\n"
                + "<report name=\"x\"><counter type=\"LINE\" missed=\"25\" covered=\"75\"/>"
                + "<counter type=\"BRANCH\" missed=\"50\" covered=\"50\"/></report>");
        Path proj = tmp.resolve("jac");
        Files.createDirectories(proj.resolve("src/test/java"));
        Files.writeString(proj.resolve("src/test/java/FooTest.java"), "class FooTest {}\n");
        Files.writeString(proj.resolve("pom.xml"), "<project/>");
        RepoInfo info = new RepoInfo(proj, Set.of(RepoInfo.Stack.MAVEN));
        ToolResult r = new CoverageRunner().run(new ToolRunner.Context(info, tmp.resolve("w2"), false, 10, false, null, false, new Config()));
        assertEquals("75.0%", r.metrics().get("Line coverage"));
        assertEquals("50.0%", r.metrics().get("Branch coverage"));
    }

    @Test
    void licenseExpressionsAndExceptionsAreUnderstood() throws Exception {
        String bom = "{\"components\":["
                + "{\"type\":\"library\",\"name\":\"a\",\"version\":\"1\",\"licenses\":[{\"license\":{\"id\":\"GPL-2.0-only WITH classpath-exception-2.0\"}}]},"
                + "{\"type\":\"library\",\"name\":\"b\",\"version\":\"1\",\"licenses\":[{\"expression\":\"EPL-2.0 OR MIT\"}]},"
                + "{\"type\":\"library\",\"name\":\"c\",\"version\":\"1\",\"licenses\":[{\"expression\":\"AGPL-3.0-only OR GPL-3.0-only\"}]}]}";
        List<Finding> f = SbomLicenseRunner.evaluate(new ObjectMapper().readTree(bom), new Config(), "pom.xml");
        assertEquals(1, f.size());
        assertTrue(f.get(0).message().contains("dependency c@1"));
    }

    @Test
    void policyIsEnforcedOverRepoConfig() {
        Config policy = new Config();
        policy.minCoverage = 80;
        policy.licenseDeny = List.of("GPL");
        policy.failOn = "HIGH";
        Config repo = new Config();
        repo.minCoverage = 10;
        repo.licenseDeny = List.of("SSPL");
        repo.ignoreRules = List.of("x/y");
        Config merged = Config.merge(policy, repo);
        assertEquals(80, merged.minCoverage());
        assertEquals(List.of("GPL", "SSPL"), merged.licenseDeny);
        assertEquals("HIGH", merged.failOn);
        assertEquals(List.of("x/y"), merged.ignoreRules);
        assertEquals(15, merged.maxComplexity());
    }

    @Test
    void gateFailsOnSeverityScoreAndNewOnly() {
        Finding high = new Finding("t", Category.SECURITY, Severity.HIGH, "f", 1, "r", "m", null, null, null);
        Finding low = new Finding("t", Category.SECURITY, Severity.LOW, "g", 1, "r2", "m2", null, null, null);
        ProjectResult p = new ProjectResult("app", ".", Set.of(), List.of(), List.of(high, low), 0,
                Scorer.compute(List.of(high, low), false), false);
        assertFalse(Gate.evaluate(List.of(p), Severity.HIGH, null, null).passed());
        assertTrue(Gate.evaluate(List.of(p), Severity.CRITICAL, null, null).passed());
        assertTrue(Gate.evaluate(List.of(p), Severity.HIGH, null, Gate.fingerprints(List.of(low))).passed());
        assertFalse(Gate.evaluate(List.of(p), null, 99, null).passed());
    }

    @Test
    void storeKeepsHistoryAndLatest() throws Exception {
        Path store = tmp.resolve("store");
        Path report = tmp.resolve("report.json");
        Files.writeString(report, "{\"projects\":[{\"name\":\"a\",\"findings\":[1,2],\"scores\":{\"overall\":80,\"grade\":\"B\"}}],"
                + "\"meta\":{\"startedAt\":\"2026-01-01T10:00:00\",\"branch\":\"main\",\"commit\":\"abcdef123456\"}}");
        RunMeta meta = new RunMeta(2, "t", "org_repo", "main", "abcdef123456", "local", "2026-01-01T10:00:00", 1);
        RunStore.save(store, meta, report);
        assertTrue(Files.isRegularFile(RunStore.latest(store, "org/repo")));
        var h = RunStore.history(store, "org/repo");
        assertEquals(1, h.size());
        assertEquals(80, h.get(0).overall());
        assertEquals(2, h.get(0).findings());
    }

    @Test
    void metaSanitizesProjectIdAndDetectsWithoutGit() {
        RunMeta m = RunMeta.detect(tmp, "my org/repo name", "x", LocalDateTime.now(), 5);
        assertEquals("my_org_repo_name", m.projectId());
        assertEquals(RunMeta.SCHEMA_VERSION, m.schemaVersion());
        assertEquals(Map.of(), Map.of());
    }
}
