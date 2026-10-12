package dev.repolens.normalize;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.Severity;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** One parser for every tool that emits SARIF 2.1.0 (Semgrep, Trivy, Gitleaks, OSV-Scanner...). */
public final class SarifParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern CWE = Pattern.compile("CWE-(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern OWASP = Pattern.compile("A(\\d{2}):2021");

    private SarifParser() {}

    public static List<Finding> parse(Path sarif, String tool, Category category, Path repoRoot) throws IOException {
        JsonNode doc = MAPPER.readTree(sarif.toFile());
        List<Finding> out = new ArrayList<>();
        for (JsonNode run : doc.path("runs")) {
            Map<String, JsonNode> rules = new HashMap<>();
            for (JsonNode r : run.path("tool").path("driver").path("rules")) {
                rules.put(r.path("id").asText(), r);
            }
            for (JsonNode res : run.path("results")) {
                String ruleId = res.path("ruleId").asText("unknown");
                JsonNode rule = rules.getOrDefault(ruleId, MAPPER.createObjectNode());
                out.add(toFinding(res, rule, ruleId, tool, category, repoRoot));
            }
        }
        return out;
    }

    private static Finding toFinding(JsonNode res, JsonNode rule, String ruleId, String tool,
                                     Category category, Path root) {
        JsonNode loc = res.path("locations").path(0).path("physicalLocation");
        String file = relativize(loc.path("artifactLocation").path("uri").asText(""), root);
        int line = loc.path("region").path("startLine").asInt(0);

        String message = res.path("message").path("text").asText(rule.path("shortDescription").path("text").asText(ruleId));
        String tags = rule.path("properties").path("tags").toString() + " " + message;
        String cwe = firstMatch(CWE, tags, "CWE-");
        String owasp = null;
        Matcher m = OWASP.matcher(tags);
        if (m.find()) owasp = "A" + m.group(1);

        Severity sev = severity(res, rule);
        String fix = rule.path("help").path("text").asText(null);
        if (fix != null && fix.length() > 400) fix = fix.substring(0, 400) + "...";
        String shown = category == Category.DEPENDENCY ? collapse(message) : firstLine(message);
        return new Finding(tool, category, sev, file, line, ruleId, shown, cwe, owasp, fix);
    }

    /** Dependency advisories carry package/version/fixed-version on separate lines; keep them all on one line. */
    private static String collapse(String s) {
        String t = s.replaceAll("\\[([^\\]]*)\\]\\([^)]*\\)", "$1").replaceAll("\\s*\\n\\s*", "; ").trim();
        return t.length() > 300 ? t.substring(0, 300) + "..." : t;
    }

    private static Severity severity(JsonNode res, JsonNode rule) {
        JsonNode sec = res.path("properties").path("security-severity");
        if (sec.isMissingNode()) sec = rule.path("properties").path("security-severity");
        if (!sec.isMissingNode()) {
            try {
                double s = Double.parseDouble(sec.asText());
                if (s >= 9.0) return Severity.CRITICAL;
                if (s >= 7.0) return Severity.HIGH;
                if (s >= 4.0) return Severity.MEDIUM;
                return Severity.LOW;
            } catch (NumberFormatException ignored) {
                // fall through to level
            }
        }
        return Severity.parse(res.path("level").asText(rule.path("defaultConfiguration").path("level").asText("warning")));
    }

    private static String firstMatch(Pattern p, String text, String prefix) {
        Matcher m = p.matcher(text);
        return m.find() ? prefix + m.group(1) : null;
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }

    static String relativize(String uri, Path root) {
        String u = uri.startsWith("file://") ? uri.substring(7) : uri;
        try {
            Path p = Path.of(u);
            if (p.isAbsolute() && p.startsWith(root)) return root.relativize(p).toString();
        } catch (Exception ignored) {
            // keep raw uri
        }
        return u;
    }
}
