package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Lighthouse against a running URL (needs Chrome): performance, SEO, accessibility, best practices. */
public class LighthouseRunner extends ExternalToolRunner {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String name() { return "lighthouse"; }
    @Override protected String binary() { return "npx"; }
    @Override protected String installHint() { return "install Node.js (npx) and Google Chrome"; }
    @Override protected String outputFileName() { return "lighthouse.json"; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return repo.has(RepoInfo.Stack.NODE);
    }

    @Override
    protected String skipReason(Context ctx) {
        return ctx.url() == null ? "no URL: start the app and pass --url <project>=http://localhost:PORT" : null;
    }

    private static final String[] CHROME_PATHS = {
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"};

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        String chrome = System.getenv("CHROME_PATH");
        if (chrome == null) {
            for (String p : CHROME_PATHS) if (java.nio.file.Files.isExecutable(Path.of(p))) { chrome = p; break; }
        }
        String lh = "--yes lighthouse '" + ctx.url() + "' --output=json --output-path='" + out + "' --quiet"
                + " --only-categories=performance,seo,accessibility,best-practices";
        if (chrome == null) {
            return List.of(bin.toString(), "--yes", "lighthouse", ctx.url(), "--output=json", "--output-path=" + out,
                    "--quiet", "--only-categories=performance,seo,accessibility,best-practices",
                    "--chrome-flags=--headless=new --no-sandbox --disable-gpu");
        }
        // Start Chrome ourselves: chrome-launcher fails to find the debug port on some macOS setups.
        int port = 9400 + (int) (ProcessHandle.current().pid() % 500);
        String script = "'" + chrome + "' --headless=new --no-sandbox --disable-gpu --remote-debugging-port=" + port
                + " --user-data-dir=\"$(mktemp -d)\" about:blank >/dev/null 2>&1 & CP=$!; sleep 4; "
                + bin + " " + lh + " --port=" + port + "; RC=$?; kill $CP 2>/dev/null; exit $RC";
        return List.of("bash", "-c", script);
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        return parseJson(MAPPER.readTree(out.toFile()));
    }

    @Override
    protected Map<String, String> metrics(Context ctx, Path out) {
        try {
            return metricsOf(MAPPER.readTree(out.toFile()));
        } catch (Exception e) {
            return Map.of();
        }
    }

    static Map<String, String> metricsOf(JsonNode doc) {
        Map<String, String> m = new LinkedHashMap<>();
        doc.path("categories").fields().forEachRemaining(e ->
                m.put("Lighthouse " + e.getKey(), Math.round(e.getValue().path("score").asDouble() * 100) + "/100"));
        for (String id : List.of("first-contentful-paint", "largest-contentful-paint", "total-blocking-time",
                "cumulative-layout-shift", "speed-index")) {
            JsonNode a = doc.path("audits").path(id);
            if (!a.isMissingNode()) m.put(a.path("title").asText(id), a.path("displayValue").asText("?"));
        }
        return m;
    }

    static List<Finding> parseJson(JsonNode doc) {
        Map<String, Category> auditCat = new LinkedHashMap<>();
        doc.path("categories").fields().forEachRemaining(e -> {
            Category c = switch (e.getKey()) {
                case "performance" -> Category.PERFORMANCE;
                case "seo" -> Category.SEO;
                case "accessibility" -> Category.ACCESSIBILITY;
                default -> Category.QUALITY;
            };
            for (JsonNode ref : e.getValue().path("auditRefs")) {
                if (ref.path("weight").asDouble() > 0) auditCat.putIfAbsent(ref.path("id").asText(), c);
            }
        });
        List<Finding> res = new ArrayList<>();
        String page = doc.path("finalDisplayedUrl").asText(doc.path("finalUrl").asText("page"));
        for (var it = doc.path("audits").fields(); it.hasNext(); ) {
            var e = it.next();
            JsonNode a = e.getValue();
            Category c = auditCat.get(e.getKey());
            String mode = a.path("scoreDisplayMode").asText();
            if (c == null || a.path("score").isNull() || a.path("score").isMissingNode()
                    || !(mode.equals("numeric") || mode.equals("binary"))) continue;
            double score = a.path("score").asDouble();
            if (score >= 0.9) continue;
            Severity sev = score < 0.5 ? Severity.MEDIUM : Severity.LOW;
            String detail = a.path("displayValue").asText("");
            res.add(new Finding("lighthouse", c, sev, page, 0, "lh:" + e.getKey(),
                    a.path("title").asText() + (detail.isEmpty() ? "" : " (" + detail + ")"), null, null,
                    firstSentence(a.path("description").asText(""))));
        }
        return res;
    }

    private static String firstSentence(String md) {
        String s = md.replaceAll("\\[([^\\]]*)\\]\\([^)]*\\)", "$1");
        int i = s.indexOf(". ");
        return i > 0 ? s.substring(0, i + 1) : s;
    }
}
