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

/**
 * Short k6 load test against a running app you own (--load --url name=URL). Generates the script itself,
 * hitting the base URL plus up to five parameter-free GET endpoints from an OpenAPI file if present.
 * Tune with BAIRAV_LOAD_VUS (default 10) and BAIRAV_LOAD_DURATION (default 20s).
 */
public class LoadTestRunner implements ToolRunner {

    public static final String NAME = "load-test";

    @Override public String name() { return NAME; }

    @Override public boolean applicable(RepoInfo repo) { return true; }

    @Override
    public ToolResult run(Context ctx) throws Exception {
        long start = System.currentTimeMillis();
        if (!ctx.load()) return ToolResult.skipped(NAME, "off (use --load --url name=http://host:port, own apps only)");
        if (ctx.url() == null) return ToolResult.skipped(NAME, "no --url for this project");
        if (ctx.dryRun()) return ToolResult.skipped(NAME, "dry run");
        Path k6 = ProcessRunner.which("k6");
        if (k6 == null) return ToolResult.skipped(NAME, "k6 not installed -> brew install k6");

        List<String> paths = endpoints(ctx.root());
        String vus = env("BAIRAV_LOAD_VUS", "10");
        String dur = env("BAIRAV_LOAD_DURATION", "20s");
        Path script = ctx.rawFile("k6-script.js");
        Files.createDirectories(script.getParent());
        Files.writeString(script, script(ctx.url(), paths, vus, dur));
        Path summary = ctx.rawFile("k6-summary.json");

        int rc = ProcessRunner.run(List.of(k6.toString(), "run", "--quiet", "--summary-export", summary.toString(), script.toString()),
                ctx.root(), ctx.logFile(NAME), ctx.logFile(NAME), Math.max(ctx.timeoutSec(), 120));
        if (rc == ProcessRunner.TIMEOUT) return ToolResult.failed(NAME, "timed out", System.currentTimeMillis() - start);
        if (!Files.exists(summary)) return ToolResult.failed(NAME, "k6 produced no summary (exit " + rc + "), see logs/" + NAME + ".log",
                System.currentTimeMillis() - start);

        Map<String, String> metrics = new LinkedHashMap<>();
        List<Finding> f = parse(new ObjectMapper().readTree(summary.toFile()), ctx.url(), vus, dur, metrics);
        return ToolResult.ok(NAME, f, f.size() + " finding(s)", System.currentTimeMillis() - start).withMetrics(metrics);
    }

    static List<Finding> parse(JsonNode doc, String url, String vus, String dur, Map<String, String> metrics) {
        List<Finding> out = new ArrayList<>();
        JsonNode m = doc.path("metrics");
        double p95 = m.path("http_req_duration").path("p(95)").asDouble(-1);
        double avg = m.path("http_req_duration").path("avg").asDouble(-1);
        double failed = m.path("http_req_failed").path("value").asDouble(m.path("http_req_failed").path("rate").asDouble(0));
        double rps = m.path("http_reqs").path("rate").asDouble(0);
        metrics.put("Load: requests/s (" + vus + " VUs, " + dur + ")", String.format("%.1f", rps));
        if (avg >= 0) metrics.put("Load: avg latency", Math.round(avg) + " ms");
        if (p95 >= 0) metrics.put("Load: p95 latency", Math.round(p95) + " ms");
        metrics.put("Load: error rate", String.format("%.2f%%", failed * 100));
        if (p95 > 500) {
            out.add(new Finding(NAME, Category.PERFORMANCE, p95 > 1000 ? Severity.HIGH : Severity.MEDIUM, url, 0, "slow-p95",
                    "p95 latency " + Math.round(p95) + " ms under " + vus + " concurrent users", null, null,
                    "Profile the slowest endpoints (check N+1 queries, missing indexes, blocking calls) and add caching."));
        }
        if (failed > 0.01) {
            out.add(new Finding(NAME, Category.PERFORMANCE, failed > 0.05 ? Severity.HIGH : Severity.MEDIUM, url, 0, "load-errors",
                    String.format("%.1f%% of requests failed under load", failed * 100), null, null,
                    "Check logs for 5xx/timeouts, connection-pool limits and rate limiting."));
        }
        return out;
    }

    static List<String> endpoints(Path root) {
        List<String> paths = new ArrayList<>(List.of("/"));
        try (var s = Files.walk(root, 6)) {
            Path spec = s.filter(p -> p.getFileName().toString().matches("(?i)openapi[\\w.-]*\\.json") && !p.toString().contains("node_modules"))
                    .findFirst().orElse(null);
            if (spec != null) {
                JsonNode doc = new ObjectMapper().readTree(spec.toFile());
                doc.path("paths").fields().forEachRemaining(e -> {
                    if (paths.size() < 6 && !e.getKey().contains("{") && e.getValue().has("get")) paths.add(e.getKey());
                });
            }
        } catch (Exception ignored) {
            // fall back to the base URL only
        }
        return paths;
    }

    static String script(String base, List<String> paths, String vus, String dur) {
        String b = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        StringBuilder arr = new StringBuilder();
        for (String p : paths) arr.append('"').append(p.replace("\"", "")).append("\",");
        return "import http from 'k6/http';\nimport { check, sleep } from 'k6';\n"
                + "export const options = { vus: " + Integer.parseInt(vus) + ", duration: '" + dur.replaceAll("[^0-9a-z]", "") + "', "
                + "thresholds: { http_req_failed: ['rate<0.01'], http_req_duration: ['p(95)<500'] } };\n"
                + "const BASE = '" + b.replace("'", "") + "';\nconst PATHS = [" + arr + "];\n"
                + "export default function () {\n  for (const p of PATHS) {\n    const r = http.get(BASE + p);\n"
                + "    check(r, { 'status < 400': (x) => x.status < 400 });\n  }\n  sleep(0.5);\n}\n";
    }

    private static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isBlank() ? d : v;
    }
}
