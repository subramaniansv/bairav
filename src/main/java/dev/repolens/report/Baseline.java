package dev.repolens.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Compares the current run against a previous report.json to show new / fixed / unchanged findings. */
public final class Baseline {

    public record Diff(List<Finding> added, int fixed, int unchanged) {}

    private Baseline() {}

    public static Set<String> load(Path reportJson) throws IOException {
        Set<String> fps = new HashSet<>();
        JsonNode doc = new ObjectMapper().readTree(reportJson.toFile());
        for (JsonNode p : doc.path("projects")) {
            for (JsonNode f : p.path("findings")) {
                fps.add(Finding.fingerprint(f.path("tool").asText(), f.path("rule").asText(),
                        f.path("file").asText(), f.path("message").asText()));
            }
        }
        return fps;
    }

    public static Diff compare(Set<String> previous, List<ProjectResult> now) {
        Set<String> current = new HashSet<>();
        List<Finding> added = new ArrayList<>();
        for (ProjectResult p : now) {
            for (Finding f : p.findings()) {
                current.add(f.fingerprint());
                if (!previous.contains(f.fingerprint())) added.add(f);
            }
        }
        int fixed = (int) previous.stream().filter(fp -> !current.contains(fp)).count();
        return new Diff(added, fixed, current.size() - added.size());
    }
}
