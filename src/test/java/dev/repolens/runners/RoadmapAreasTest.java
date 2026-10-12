package dev.repolens.runners;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import dev.repolens.ai.AiPlanWriter;
import dev.repolens.ai.AutoFix;
import dev.repolens.core.Bairav;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.Severity;
import dev.repolens.owasp.ComplianceMapper;
import dev.repolens.report.PrComment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RoadmapAreasTest {

    @TempDir
    Path tmp;

    private List<Finding> scan(Path repo, String... runners) throws Exception {
        Bairav.Request r = new Bairav.Request(repo, tmp.resolve("out"), 120, false, false, new LinkedHashSet<>(List.of(runners)),
                new LinkedHashMap<>(), false, false, null, null, null, null, null, null, null, false, false);
        return Bairav.scan(r).projects().stream().flatMap(p -> p.findings().stream()).toList();
    }

    private static boolean has(List<Finding> fs, String rule) {
        return fs.stream().anyMatch(f -> f.rule().equals(rule));
    }

    @Test
    void helpers() {
        assertEquals(1, GitAnalyticsRunner.busFactor(List.of(60, 20, 20), 100));
        assertEquals(2, GitAnalyticsRunner.busFactor(List.of(40, 30, 30), 100));
        assertEquals(List.of(15, 2000), GitAnalyticsRunner.commitSizes(List.of(
                "@@", " 2 files changed, 10 insertions(+), 5 deletions(-)", "@@", " 9 files changed, 2000 insertions(+)")));
        assertEquals(3, GitAnalyticsRunner.median(List.of(1, 3, 9)));
        assertEquals(4, OutdatedRunner.major("^4.17.1"));
        assertEquals(-1, OutdatedRunner.major(null));
    }

    @Test
    void privacyLogPii() {
        List<Finding> out = new ArrayList<>();
        PrivacyI18nRunner.logPii("A.java", 1, "\"login\", password", out);
        PrivacyI18nRunner.logPii("A.java", 2, "\"user\", user.getEmail()", out);
        PrivacyI18nRunner.logPii("A.java", 3, "\"the password is wrong\"", out);
        assertEquals(List.of("secret-in-log", "pii-in-log"), out.stream().map(Finding::rule).toList());
    }

    @Test
    void complianceMapping() {
        Finding f = new Finding("t", Category.SECURITY, Severity.HIGH, "a", 1, "r", "m", null, "A03", "fix");
        Map<String, Map<String, Integer>> m = ComplianceMapper.summarize(List.of(f));
        assertFalse(m.isEmpty());
        assertTrue(m.values().stream().anyMatch(c -> !c.isEmpty()));
    }

    @Test
    void supplyChainAndOperationsOnFixture() throws Exception {
        Path repo = tmp.resolve("repo");
        Files.createDirectories(repo.resolve(".github/workflows"));
        Files.writeString(repo.resolve("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId>"
                + "<artifactId>x</artifactId><version>1</version></project>");
        Files.writeString(repo.resolve(".github/workflows/ci.yml"),
                "on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
                        + "      - uses: actions/checkout@v4\n      - run: echo ${{ github.event.pull_request.title }}\n");
        Files.writeString(repo.resolve("Dockerfile"), "FROM node:latest\nCMD [\"node\"]\n");
        List<Finding> fs = scan(repo, "supply-chain");
        for (String r : List.of("action-not-pinned", "pull-request-target", "workflow-script-injection", "docker-mutable-tag")) {
            assertTrue(has(fs, r), r + " in " + fs);
        }
    }

    @Test
    void architectureFindsCyclesAndFocusedTests() throws Exception {
        Path repo = tmp.resolve("web");
        Files.createDirectories(repo.resolve("src"));
        Files.writeString(repo.resolve("package.json"), "{\"name\":\"web\"}");
        Files.writeString(repo.resolve("src/a.js"), "import { b } from './b';\nexport const a = 1;\n");
        Files.writeString(repo.resolve("src/b.js"), "import { a } from './a';\nexport const b = 1;\n");
        Files.writeString(repo.resolve("src/a.test.js"), "it.only('x', () => { expect(1).toBe(1); });\n");
        List<Finding> fs = scan(repo, "architecture");
        assertTrue(fs.stream().anyMatch(f -> f.message().toLowerCase().contains("circular")), fs.toString());
        assertTrue(fs.stream().anyMatch(f -> f.message().toLowerCase().contains("only") || f.message().toLowerCase().contains("focused")), fs.toString());
    }

    @Test
    void apiBreakingChanges() throws Exception {
        ObjectMapper om = new ObjectMapper();
        var oldSpec = om.readTree("{\"paths\":{\"/a\":{\"get\":{}},\"/b\":{\"get\":{}}}}");
        var newSpec = om.readTree("{\"paths\":{\"/a\":{\"get\":{}}}}");
        assertEquals(1, ApiDbRunner.breaking(oldSpec, newSpec).size());
        assertTrue(ApiDbRunner.breaking(newSpec, oldSpec).isEmpty());
    }

    @Test
    void sqlMigrationSafety() throws Exception {
        Path f = tmp.resolve("V1__x.sql");
        Files.writeString(f, "DROP TABLE users;\n");
        List<Finding> out = new ArrayList<>();
        ApiDbRunner.sqlSafety(f, "V1__x.sql", out);
        assertFalse(out.isEmpty());
    }

    @Test
    void loadTestParsesSummary() throws Exception {
        var doc = new ObjectMapper().readTree("{\"metrics\":{\"http_req_duration\":{\"p(95)\":2500.0,\"avg\":900.0},"
                + "\"http_req_failed\":{\"value\":0.2},\"http_reqs\":{\"count\":100,\"rate\":5.0}}}");
        Map<String, String> metrics = new LinkedHashMap<>();
        List<Finding> fs = LoadTestRunner.parse(doc, "http://x", "10", "20s", metrics);
        assertFalse(fs.isEmpty());
    }

    @Test
    void gzipSizeIsSmallerForRepetitiveData() throws Exception {
        byte[] data = "abcabcabc".repeat(1000).getBytes();
        assertTrue(PerformanceDeepRunner.gzipSize(data) < data.length / 10);
    }

    @Test
    void prCommentRenderAndTarget() {
        assertEquals(new PrComment.Target("o/r", 7), PrComment.parseTarget("o/r#7", Map.of()));
        assertEquals(new PrComment.Target("o/r", 9),
                PrComment.parseTarget("auto", Map.of("GITHUB_REPOSITORY", "o/r", "GITHUB_REF", "refs/pull/9/merge")));
        assertNull(PrComment.parseTarget("auto", Map.of("GITHUB_REPOSITORY", "o/r", "GITHUB_REF", "refs/heads/main")));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> PrComment.parseTarget("a b#1", Map.of()));
    }

    @Test
    void prCommentUpsertsAgainstMockGitHub() throws Exception {
        List<String> calls = new CopyOnWriteArrayList<>();
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext("/", ex -> {
            calls.add(ex.getRequestMethod() + " " + ex.getRequestURI().getPath());
            byte[] body = ex.getRequestMethod().equals("GET")
                    ? ("[{\"id\":55,\"body\":\"" + PrComment.MARKER + " old\"}]").getBytes() : "{}".getBytes();
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        s.start();
        try {
            String api = "http://127.0.0.1:" + s.getAddress().getPort();
            PrComment.post(new PrComment.Target("o/r", 3), PrComment.MARKER + "new", List.of(), "tok", api);
            assertEquals(List.of("GET /repos/o/r/issues/3/comments", "PATCH /repos/o/r/issues/comments/55"), calls);
        } finally {
            s.stop(0);
        }
    }

    @Test
    void autoFixCommitsVerifiedAndRollsBackFailed() throws Exception {
        Path repo = tmp.resolve("ar");
        Files.createDirectories(repo);
        run(repo, "git init -q -b main && git config user.email t@t && git config user.name t && echo a > f.txt && git add -A && git commit -qm init");
        var loc = new AiPlanWriter.Location("f.txt", 1, "");
        AiPlanWriter.Task good = new AiPlanWriter.Task("good", "p", ".", Severity.HIGH, Category.SECURITY, "r", "t", null, null,
                "t", "prob", "fix", 1, List.of(loc), List.of(), "grep -q fixed f.txt", "done");
        AiPlanWriter.Task bad = new AiPlanWriter.Task("bad", "p", ".", Severity.HIGH, Category.SECURITY, "r2", "t", null, null,
                "t", "prob", "fix", 1, List.of(loc), List.of(), "false", "done");
        Path out = tmp.resolve("o");
        List<AutoFix.Outcome> res;
        res = AutoFix.run(repo, out, List.of(bad), "echo fixed > f.txt; echo junk > junk.txt", 5, 30);
        assertFalse(res.get(0).fixed());
        assertEquals("a", Files.readString(repo.resolve("f.txt")).trim());
        assertFalse(Files.exists(repo.resolve("junk.txt")));
        run(repo, "git checkout -q main");
        res = AutoFix.run(repo, out, List.of(good), "echo fixed > f.txt", 5, 30);
        assertTrue(res.get(0).fixed(), res.toString());
        assertEquals("", run(repo, "git status --porcelain").trim());
    }

    @Test
    void autoFixRefusesDirtyTree() throws Exception {
        Path repo = tmp.resolve("dirty");
        Files.createDirectories(repo);
        run(repo, "git init -q -b main && git config user.email t@t && git config user.name t && echo a > f.txt && git add -A && git commit -qm init && echo b > f.txt");
        org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class,
                () -> AutoFix.run(repo, tmp.resolve("o2"), List.of(), "true", 1, 10));
    }

    private static String run(Path dir, String cmd) throws Exception {
        Process p = new ProcessBuilder("sh", "-c", cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        String o = new String(p.getInputStream().readAllBytes());
        p.waitFor();
        return o;
    }
}
