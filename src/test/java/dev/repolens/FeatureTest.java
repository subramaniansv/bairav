package dev.repolens;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.ai.AiPlanWriter;
import dev.repolens.config.Config;
import dev.repolens.detect.ProjectDiscovery;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.report.Baseline;
import dev.repolens.runners.SeoRunner;
import dev.repolens.runners.ToolRunner;
import dev.repolens.score.Scorer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureTest {

    @TempDir
    Path tmp;

    private static Finding f(String rule, String file, Severity s, Category c) {
        return new Finding("t", c, s, file, 2, rule, "msg " + rule, null, null, "do it");
    }

    @Test
    void discoversNestedProjectsAndDropsSameStackSubmodules() throws Exception {
        Files.createDirectories(tmp.resolve("backend/module"));
        Files.createDirectories(tmp.resolve("web/app"));
        Files.createDirectories(tmp.resolve("packages/lib"));
        Files.writeString(tmp.resolve("backend/pom.xml"), "<project/>");
        Files.writeString(tmp.resolve("backend/module/pom.xml"), "<project/>");
        Files.writeString(tmp.resolve("web/package.json"), "{}");
        Files.writeString(tmp.resolve("packages/lib/package.json"), "{}");
        List<String> names = ProjectDiscovery.find(tmp).stream().map(p -> tmp.relativize(p).toString()).toList();
        assertEquals(List.of("backend", "packages/lib", "web"), names.stream().sorted().toList());
    }

    @Test
    void configSuppressesByPathRuleAndOverridesSeverity() throws Exception {
        Path yml = tmp.resolve("c.yml");
        Files.writeString(yml, "ignorePaths: ['**/gen/**']\nignoreRules: [noisy]\nseverityOverrides: {x: LOW}\n");
        Config c = Config.load(yml);
        assertNull(c.apply(f("noisy", "a/b.java", Severity.HIGH, Category.QUALITY)));
        assertNull(c.apply(f("r", "a/gen/b.java", Severity.HIGH, Category.QUALITY)));
        assertNull(c.apply(f("r", "dist/a.js", Severity.HIGH, Category.QUALITY)));
        assertNull(c.apply(f("r", "student/playwright-report/index.html", Severity.HIGH, Category.QUALITY)));
        assertEquals(Severity.LOW, c.apply(f("x", "a/b.java", Severity.HIGH, Category.QUALITY)).severity());
        assertNotNull(c.apply(f("r", "src/a.java", Severity.HIGH, Category.QUALITY)));
    }

    @Test
    void seoRunnerFlagsSpaShellAndMissingBasics() throws Exception {
        Files.createDirectories(tmp.resolve("src"));
        Files.writeString(tmp.resolve("index.html"),
                "<!doctype html><html><head><title>X</title></head><body><div id=\"root\"></div></body></html>");
        Files.writeString(tmp.resolve("package.json"), "{\"dependencies\":{\"react-router-dom\":\"6\"}}");
        Files.writeString(tmp.resolve("src/A.tsx"), "export const A = () => <img src=\"x.png\" />;");
        RepoInfo info = new RepoInfo(tmp, Set.of(RepoInfo.Stack.NODE));
        ToolResult r = new SeoRunner().run(new ToolRunner.Context(info, tmp.resolve("w"), false, 10, false, null, false));
        Set<String> rules = new java.util.HashSet<>();
        r.findings().forEach(x -> rules.add(x.rule()));
        for (String expected : List.of("title-length", "missing-meta-description", "missing-robots-txt", "missing-sitemap",
                "csr-empty-shell", "ai-bots-cannot-render-js", "missing-jsonld", "missing-llms-txt", "missing-lang",
                "img-missing-alt", "no-per-route-meta")) {
            assertTrue(rules.contains(expected), "missing " + expected + " in " + rules);
        }
        assertEquals(SeoRunner.SCOPE_ACTIVE, r.metrics().get(SeoRunner.SCOPE_KEY));
    }

    @Test
    void seoRunnerSkipsSeoForNoindexButKeepsAccessibility() throws Exception {
        Files.writeString(tmp.resolve("index.html"),
                "<html><head><meta name=\"robots\" content=\"noindex\"><title>Admin panel</title></head><body><div id=\"root\"></div></body></html>");
        Files.writeString(tmp.resolve("package.json"), "{}");
        RepoInfo info = new RepoInfo(tmp, Set.of(RepoInfo.Stack.NODE));
        ToolResult r = new SeoRunner().run(new ToolRunner.Context(info, tmp.resolve("w"), false, 10, false, null, false));
        assertTrue(r.findings().stream().noneMatch(x -> x.category() == Category.SEO));
        assertTrue(r.findings().stream().anyMatch(x -> x.rule().equals("missing-lang")));
    }

    @Test
    void baselineShowsNewAndFixed() throws Exception {
        Finding a = f("a", "x.java", Severity.HIGH, Category.SECURITY);
        Finding b = f("b", "y.java", Severity.LOW, Category.QUALITY);
        ProjectResult before = new ProjectResult("p", ".", Set.of(), List.of(), List.of(a), 0, Scorer.compute(List.of(a), false), false);
        Path prev = tmp.resolve("report.json");
        new ObjectMapper().writeValue(prev.toFile(), java.util.Map.of("projects", List.of(before)));
        ProjectResult now = new ProjectResult("p", ".", Set.of(), List.of(), List.of(b), 0, Scorer.compute(List.of(b), false), false);
        Baseline.Diff d = Baseline.compare(Baseline.load(prev), List.of(now));
        assertEquals(1, d.added().size());
        assertEquals(1, d.fixed());
    }

    @Test
    void aiPlanGroupsByRuleAndIncludesSnippets() throws Exception {
        Files.createDirectories(tmp.resolve("app/src"));
        Files.writeString(tmp.resolve("app/src/A.java"), "line1\nline2 bad\nline3\n");
        Finding f1 = f("r1", "app/src/A.java", Severity.HIGH, Category.SECURITY);
        Finding f2 = f("r1", "app/src/B.java", Severity.HIGH, Category.SECURITY);
        Finding dep = new Finding("npm-audit", Category.DEPENDENCY, Severity.MEDIUM, "app/package.json", 0, "npm:x", "x (1.0)", null, "A06", "npm audit fix");
        ProjectResult p = new ProjectResult("app", "app", Set.of(RepoInfo.Stack.NODE), List.of(), List.of(f1, f2, dep), 0,
                Scorer.compute(List.of(f1, f2, dep), false), false);
        List<AiPlanWriter.Task> tasks = AiPlanWriter.buildTasks(tmp, List.of(p));
        assertEquals(2, tasks.size());
        assertEquals("T001", tasks.get(0).id());
        assertEquals(2, tasks.get(0).occurrences());
        assertNotNull(tasks.get(0).locations().get(0).snippet());
        assertTrue(tasks.get(0).locations().get(0).snippet().contains("> "));
        assertEquals(1, tasks.get(1).items().size());
        assertEquals("cd app && npm run build", tasks.get(0).verify());
    }
}
