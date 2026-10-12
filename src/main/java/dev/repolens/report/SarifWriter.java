package dev.repolens.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** SARIF 2.1.0 export so results show up in GitHub code scanning / IDE SARIF viewers. */
public final class SarifWriter {

    private SarifWriter() {}

    public static void write(Path file, List<ProjectResult> projects) throws IOException {
        Set<String> ruleIds = new LinkedHashSet<>();
        List<Map<String, Object>> results = new ArrayList<>();
        for (ProjectResult p : projects) {
            for (Finding f : p.findings()) {
                String id = f.tool() + "/" + f.rule();
                ruleIds.add(id);
                Map<String, Object> region = new LinkedHashMap<>();
                if (f.line() > 0) region.put("startLine", f.line());
                Map<String, Object> phys = new LinkedHashMap<>();
                phys.put("artifactLocation", Map.of("uri", f.file()));
                if (!region.isEmpty()) phys.put("region", region);
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("ruleId", id);
                r.put("level", switch (f.severity()) {
                    case CRITICAL, HIGH -> "error";
                    case MEDIUM -> "warning";
                    default -> "note";
                });
                r.put("message", Map.of("text", f.message() + (f.fix() != null ? " Fix: " + f.fix() : "")));
                r.put("locations", List.of(Map.of("physicalLocation", phys)));
                results.add(r);
            }
        }
        List<Map<String, Object>> rules = new ArrayList<>();
        ruleIds.forEach(id -> rules.add(Map.of("id", id)));
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "Bairav");
        driver.put("version", "0.2.0");
        driver.put("rules", rules);
        Map<String, Object> run = Map.of("tool", Map.of("driver", driver), "results", results);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        doc.put("version", "2.1.0");
        doc.put("runs", List.of(run));
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValue(file.toFile(), doc);
    }
}
