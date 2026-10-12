package dev.repolens.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.owasp.OwaspMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** Human report (report.html) plus the full machine dump (report.json, used as a baseline later). */
public final class ReportWriter {

    private static final int DETAIL_ROWS = 300;

    private ReportWriter() {}

    public static void write(Path outDir, Path scanRoot, List<ProjectResult> projects, Baseline.Diff diff,
                             RunMeta meta, Gate gate) throws IOException {
        Files.createDirectories(outDir);
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("schemaVersion", RunMeta.SCHEMA_VERSION);
        json.put("generatedAt", LocalDateTime.now().withNano(0).toString());
        json.put("scanRoot", scanRoot.toString());
        json.put("meta", meta);
        json.put("gate", gate);
        json.put("projects", projects);
        if (diff != null) {
            json.put("baselineDiff", Map.of("new", diff.added().size(), "fixed", diff.fixed(), "unchanged", diff.unchanged()));
        }
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValue(outDir.resolve("report.json").toFile(), json);
        Files.writeString(outDir.resolve("report.html"), html(scanRoot, projects, diff, meta, gate));
    }

    private static String html(Path root, List<ProjectResult> projects, Baseline.Diff diff, RunMeta meta, Gate gate) {
        StringBuilder h = new StringBuilder();
        h.append("<!doctype html><html><head><meta charset='utf-8'><title>Bairav report</title><style>")
                .append("body{font-family:-apple-system,Segoe UI,sans-serif;margin:2rem;color:#222;max-width:1300px}")
                .append("table{border-collapse:collapse;width:100%;margin:.6rem 0 1.2rem;font-size:13px}")
                .append("th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f4f4f4}")
                .append(".card{display:inline-block;border:1px solid #ddd;border-radius:8px;padding:8px 16px;margin:0 8px 8px 0;text-align:center}")
                .append(".big{font-size:24px;font-weight:bold}.CRITICAL{color:#b00020;font-weight:bold}.HIGH{color:#d84315;font-weight:bold}")
                .append(".MEDIUM{color:#ef6c00}.LOW{color:#6d6d00}.INFO{color:#777}.FAILED{color:#b00020}.SKIPPED{color:#888}.OK{color:#2e7d32}")
                .append("code{background:#f4f4f4;padding:1px 4px}h2{margin-top:2.2rem;border-bottom:2px solid #eee;padding-bottom:4px}")
                .append("details{margin:.5rem 0}summary{cursor:pointer;font-weight:600}.muted{color:#777;font-size:12px}")
                .append("</style></head><body>");
        h.append("<h1>Bairav report</h1><p class='muted'>").append(esc(root.toString())).append(" &middot; ")
                .append(LocalDateTime.now().withNano(0)).append("</p>");
        h.append("<p class='muted'>Project id <b>").append(esc(meta.projectId())).append("</b> &middot; branch ")
                .append(esc(String.valueOf(meta.branch()))).append(" &middot; commit ")
                .append(esc(meta.commit() == null ? "-" : meta.commit().substring(0, Math.min(8, meta.commit().length()))))
                .append(" &middot; ").append(esc(meta.ci())).append(" &middot; Bairav ").append(esc(meta.toolVersion()))
                .append(" &middot; schema v").append(meta.schemaVersion()).append("</p>");
        if (!gate.passed()) {
            h.append("<p class='FAILED'><b>Quality gate FAILED</b></p><ul>");
            gate.violations().forEach(v -> h.append("<li>").append(esc(v)).append("</li>"));
            h.append("</ul>");
        }
        if (diff != null) {
            h.append("<p><b>Since baseline:</b> ").append(diff.added().size()).append(" new, ").append(diff.fixed())
                    .append(" fixed, ").append(diff.unchanged()).append(" unchanged</p>");
        }

        h.append("<h2>Overview</h2><table><tr><th>Project</th><th>Stack</th><th>Grade</th><th>Scores</th><th>High+</th><th>Total</th><th>Suppressed</th></tr>");
        for (ProjectResult p : projects) {
            long high = p.findings().stream().filter(f -> f.severity().weight >= Severity.HIGH.weight).count();
            h.append("<tr><td><a href='#").append(esc(p.name())).append("'>").append(esc(p.name())).append("</a><br><span class='muted'>")
                    .append(esc(p.path())).append("</span></td><td>").append(p.stacks()).append("</td><td><b>").append(p.scores().grade())
                    .append(" (").append(p.scores().overall()).append(")</b></td><td>").append(esc(p.scores().byArea().toString()))
                    .append("</td><td>").append(high).append("</td><td>").append(p.findings().size()).append("</td><td>")
                    .append(p.suppressed()).append("</td></tr>");
        }
        h.append("</table>");

        for (ProjectResult p : projects) project(h, p);
        h.append("</body></html>");
        return h.toString();
    }

    private static void project(StringBuilder h, ProjectResult p) {
        h.append("<h2 id='").append(esc(p.name())).append("'>").append(esc(p.name())).append(" <span class='muted'>")
                .append(esc(p.path())).append("</span></h2>");
        h.append("<div class='card'><div>Overall</div><div class='big'>").append(p.scores().grade()).append(" (")
                .append(p.scores().overall()).append(")</div></div>");
        p.scores().byArea().forEach((k, v) -> h.append("<div class='card'><div>").append(esc(k))
                .append("</div><div class='big'>").append(v).append("</div></div>"));

        h.append("<h3>Tools</h3><table><tr><th>Tool</th><th>Status</th><th>Detail</th><th>Time</th></tr>");
        for (ToolResult r : p.tools()) {
            h.append("<tr><td>").append(esc(r.tool())).append("</td><td class='").append(r.status()).append("'>").append(r.status())
                    .append("</td><td>").append(esc(r.detail())).append("</td><td>").append(r.millis()).append(" ms</td></tr>");
        }
        h.append("</table>");

        Map<String, Long> owasp = new TreeMap<>();
        p.findings().stream().filter(f -> f.owasp() != null)
                .forEach(f -> owasp.merge(OwaspMapper.NAMES.getOrDefault(f.owasp(), "Unmapped"), 1L, Long::sum));
        h.append("<h3>OWASP Top 10 (2021)</h3><table><tr><th>Category</th><th>Findings</th></tr>");
        OwaspMapper.NAMES.values().stream().sorted().forEach(n ->
                h.append("<tr><td>").append(esc(n)).append("</td><td>").append(owasp.getOrDefault(n, 0L)).append("</td></tr>"));
        if (owasp.containsKey("Unmapped")) h.append("<tr><td>Unmapped</td><td>").append(owasp.get("Unmapped")).append("</td></tr>");
        h.append("</table>");

        boolean anyMetric = p.tools().stream().anyMatch(r -> !r.metrics().isEmpty());
        if (anyMetric) {
            h.append("<h3>Metrics</h3><table>");
            p.tools().forEach(r -> r.metrics().forEach((k, v) ->
                    h.append("<tr><td>").append(esc(k)).append("</td><td>").append(esc(v)).append("</td></tr>")));
            h.append("</table>");
        }

        h.append("<h3>Issues grouped by rule</h3><table><tr><th>Severity</th><th>Category</th><th>Count</th><th>Rule / Tool</th>")
                .append("<th>OWASP</th><th>Issue</th><th>Suggested fix</th><th>Examples</th></tr>");
        Map<String, List<Finding>> groups = p.findings().stream()
                .collect(Collectors.groupingBy(f -> f.tool() + "|" + f.rule(), LinkedHashMap::new, Collectors.toList()));
        groups.values().stream()
                .sorted(Comparator.comparingInt((List<Finding> l) -> -l.stream().mapToInt(f -> f.severity().weight).max().orElse(0))
                        .thenComparingInt(l -> -l.size()))
                .forEach(l -> {
                    Finding f = l.get(0);
                    h.append("<tr><td class='").append(f.severity()).append("'>").append(f.severity()).append("</td><td>").append(f.category())
                            .append("</td><td>").append(l.size()).append("</td><td>").append(esc(f.rule())).append("<br><span class='muted'>")
                            .append(esc(f.tool())).append("</span></td><td>").append(esc(f.owasp() == null ? "" : f.owasp())).append("</td><td>")
                            .append(esc(f.message())).append("</td><td>").append(esc(f.fix() == null ? "" : f.fix())).append("</td><td>");
                    l.stream().limit(3).forEach(x -> h.append("<code>").append(esc(x.file())).append(x.line() > 0 ? ":" + x.line() : "").append("</code><br>"));
                    if (l.size() > 3) h.append("<span class='muted'>+").append(l.size() - 3).append(" more</span>");
                    h.append("</td></tr>");
                });
        h.append("</table>");

        h.append("<details><summary>All findings (").append(p.findings().size()).append(")</summary><table><tr><th>Severity</th><th>Tool</th>")
                .append("<th>Location</th><th>Rule</th><th>Message</th></tr>");
        p.findings().stream()
                .sorted(Comparator.comparingInt((Finding f) -> -f.severity().weight).thenComparing(Finding::file))
                .limit(DETAIL_ROWS)
                .forEach(f -> h.append("<tr><td class='").append(f.severity()).append("'>").append(f.severity()).append("</td><td>")
                        .append(esc(f.tool())).append("</td><td><code>").append(esc(f.file())).append(f.line() > 0 ? ":" + f.line() : "")
                        .append("</code></td><td>").append(esc(f.rule())).append("</td><td>").append(esc(f.message())).append("</td></tr>"));
        h.append("</table>");
        if (p.findings().size() > DETAIL_ROWS) h.append("<p class='muted'>Showing ").append(DETAIL_ROWS).append("; see report.json for all.</p>");
        h.append("</details>");
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace("\"", "&quot;");
    }
}
