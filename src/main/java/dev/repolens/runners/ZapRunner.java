package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.Severity;
import dev.repolens.util.ProcessRunner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * OWASP ZAP quick scan (DAST) against a running app. Opt-in (--zap) because it ACTIVELY attacks the
 * target: only point it at your own dev instance.
 */
public class ZapRunner extends ExternalToolRunner {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path MAC_APP = Path.of("/Applications/ZAP.app/Contents/Java/zap.sh");

    @Override public String name() { return "zap"; }
    @Override protected String binary() { return "zap.sh"; }
    @Override protected String installHint() { return "brew install --cask zap"; }
    @Override protected String outputFileName() { return "zap.json"; }
    @Override protected java.util.Set<Integer> okExitCodes() { return java.util.Set.of(0); }

    @Override
    protected Path locate() {
        Path p = ProcessRunner.which("zap.sh");
        return p != null ? p : (Files.isExecutable(MAC_APP) ? MAC_APP : null);
    }

    @Override
    protected String skipReason(Context ctx) {
        if (!ctx.zap()) return "opt-in: pass --zap (active scan, own apps only)";
        return ctx.url() == null ? "no URL: pass --url <project>=http://localhost:PORT" : null;
    }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        return List.of(bin.toString(), "-cmd", "-quickurl", ctx.url(), "-quickout", out.toString(), "-quickprogress");
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        return parseJson(MAPPER.readTree(out.toFile()), ctx.url());
    }

    static List<Finding> parseJson(JsonNode doc, String url) {
        List<Finding> res = new ArrayList<>();
        for (JsonNode site : doc.path("site")) {
            for (JsonNode alert : site.path("alerts")) {
                Severity sev = switch (alert.path("riskcode").asInt(0)) {
                    case 3 -> Severity.HIGH;
                    case 2 -> Severity.MEDIUM;
                    case 1 -> Severity.LOW;
                    default -> Severity.INFO;
                };
                String cwe = alert.path("cweid").asText("");
                String where = alert.path("instances").path(0).path("uri").asText(url);
                res.add(new Finding("zap", Category.SECURITY, sev, where, 0,
                        "zap:" + alert.path("pluginid").asText(alert.path("alert").asText()),
                        alert.path("name").asText(alert.path("alert").asText()),
                        cwe.isEmpty() || cwe.equals("-1") || cwe.equals("0") ? null : "CWE-" + cwe, null,
                        stripHtml(alert.path("solution").asText(""))));
            }
        }
        return res;
    }

    private static String stripHtml(String s) {
        return s.replaceAll("<[^>]*>", "").trim();
    }
}
