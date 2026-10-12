package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class NpmAuditRunner extends ExternalToolRunner {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String name() { return "npm-audit"; }
    @Override protected String binary() { return "npm"; }
    @Override protected String installHint() { return "install Node.js"; }
    @Override protected String outputFileName() { return "npm-audit.json"; }
    @Override protected boolean stdoutIsReport() { return true; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return repo.has(RepoInfo.Stack.NODE);
    }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        return List.of(bin.toString(), "audit", "--json");
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        JsonNode doc = MAPPER.readTree(Files.readString(out));
        if (doc.has("error")) {
            // typically "no lockfile": surface it instead of silently reporting zero
            throw new IllegalStateException(doc.path("error").path("summary").asText("npm audit error"));
        }
        List<Finding> res = new ArrayList<>();
        doc.path("vulnerabilities").fields().forEachRemaining(e -> {
            JsonNode v = e.getValue();
            String fix = v.path("fixAvailable").isBoolean()
                    ? (v.path("fixAvailable").asBoolean() ? "npm audit fix" : "No fix available yet")
                    : "Upgrade to " + v.path("fixAvailable").path("name").asText() + "@"
                            + v.path("fixAvailable").path("version").asText();
            String msg = e.getKey() + " (" + v.path("range").asText("?") + ")"
                    + (v.path("isDirect").asBoolean() ? " [direct]" : " [transitive]");
            res.add(new Finding(name(), Category.DEPENDENCY, Severity.parse(v.path("severity").asText()),
                    "package.json", 0, "npm:" + e.getKey(), msg, null, "A06", fix));
        });
        return res;
    }
}
