package dev.repolens.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Central run history, shared by many projects: {store}/{projectId}/runs/{timestamp}-{commit}.json plus
 * {store}/{projectId}/latest.json. Writes are atomic so concurrent CI jobs never read a half-written file.
 */
public final class RunStore {

    private RunStore() {}

    public static Path latest(Path store, String projectId) {
        return store.resolve(RunMeta.sanitize(projectId)).resolve("latest.json");
    }

    public static void save(Path store, RunMeta meta, Path reportJson) throws IOException {
        Path dir = store.resolve(meta.projectId());
        Files.createDirectories(dir.resolve("runs"));
        String sha = meta.commit() == null ? "nocommit" : meta.commit().substring(0, Math.min(8, meta.commit().length()));
        String stamp = meta.startedAt().replace(":", "").replace("-", "");
        Path run = dir.resolve("runs").resolve(stamp + "-" + sha + ".json");
        Files.copy(reportJson, run, StandardCopyOption.REPLACE_EXISTING);
        Path tmp = Files.createTempFile(dir, "latest", ".tmp");
        Files.copy(reportJson, tmp, StandardCopyOption.REPLACE_EXISTING);
        Files.move(tmp, dir.resolve("latest.json"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public record Point(String startedAt, String branch, String commit, int findings, int overall, String grades,
                        String vitals) {}

    /** Score history for one project, oldest first. */
    public static List<Point> history(Path store, String projectId) throws IOException {
        Path runs = store.resolve(RunMeta.sanitize(projectId)).resolve("runs");
        List<Point> out = new ArrayList<>();
        if (!Files.isDirectory(runs)) return out;
        ObjectMapper m = new ObjectMapper();
        try (Stream<Path> s = Files.list(runs)) {
            for (Path p : s.filter(x -> x.toString().endsWith(".json")).sorted().toList()) {
                JsonNode d = m.readTree(p.toFile());
                int findings = 0;
                double sum = 0;
                StringBuilder grades = new StringBuilder();
                int n = 0;
                StringBuilder vitals = new StringBuilder();
                for (JsonNode pr : d.path("projects")) {
                    findings += pr.path("findings").size();
                    sum += pr.path("scores").path("overall").asInt();
                    n++;
                    grades.append(pr.path("name").asText()).append('=').append(pr.path("scores").path("grade").asText()).append(' ');
                    for (JsonNode t : pr.path("tools")) {
                        JsonNode mt = t.path("metrics");
                        for (String k : List.of("Largest Contentful Paint", "Cumulative Layout Shift", "Total Blocking Time")) {
                            if (mt.has(k)) vitals.append(pr.path("name").asText()).append(' ').append(abbrev(k)).append('=')
                                    .append(mt.path(k).asText().replace(" ", "")).append(' ');
                        }
                    }
                }
                JsonNode meta = d.path("meta");
                out.add(new Point(meta.path("startedAt").asText(d.path("generatedAt").asText("?")),
                        meta.path("branch").asText("-"), meta.path("commit").asText("-"), findings,
                        n == 0 ? 0 : (int) Math.round(sum / n), grades.toString().trim(), vitals.toString().trim()));
            }
        }
        return out;
    }

    private static String abbrev(String k) {
        return k.startsWith("Largest") ? "LCP" : k.startsWith("Cumulative") ? "CLS" : "TBT";
    }
}
