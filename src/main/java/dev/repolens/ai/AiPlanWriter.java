package dev.repolens.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.owasp.OwaspMapper;
import dev.repolens.report.Baseline;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns findings into a prioritised, grouped task list an AI coding agent can execute one by one:
 * ai-fix-plan.md (readable prompt) and ai-fix-plan.json (machine-readable).
 */
public final class AiPlanWriter {

    private static final int SNIPPET_CONTEXT = 3;
    private static final int SNIPPETS_PER_TASK = 5;
    private static final int LOCATIONS_PER_TASK = 25;

    public record Location(String file, int line, String snippet) {}

    public record Task(String id, String project, String projectPath, Severity severity, Category category,
                       String rule, String tool, String owasp, String cwe, String title, String problem, String fix,
                       int occurrences, List<Location> locations, List<String> items, String verify, String doneWhen) {}

    private AiPlanWriter() {}

    public static List<Task> buildTasks(Path scanRoot, List<ProjectResult> projects) {
        record Key(String project, String group) {}
        Map<Key, List<Finding>> groups = new LinkedHashMap<>();
        Map<String, ProjectResult> byName = new LinkedHashMap<>();
        for (ProjectResult p : projects) {
            byName.put(p.name(), p);
            for (Finding f : p.findings()) {
                if (f.severity() == Severity.INFO) continue;
                String g = f.category() == Category.DEPENDENCY ? "deps:" + f.tool() : f.tool() + ":" + f.rule();
                groups.computeIfAbsent(new Key(p.name(), g), k -> new ArrayList<>()).add(f);
            }
        }
        List<Map.Entry<Key, List<Finding>>> ordered = new ArrayList<>(groups.entrySet());
        ordered.sort(Comparator
                .comparingInt((Map.Entry<Key, List<Finding>> e) -> -maxSeverity(e.getValue()))
                .thenComparingInt(e -> -e.getValue().size())
                .thenComparing(e -> e.getKey().project()));

        List<Task> tasks = new ArrayList<>();
        int n = 1;
        for (var e : ordered) {
            List<Finding> fs = e.getValue();
            Finding first = fs.stream().max(Comparator.comparingInt(f -> f.severity().weight)).orElse(fs.get(0));
            ProjectResult p = byName.get(e.getKey().project());
            boolean deps = first.category() == Category.DEPENDENCY;
            boolean license = first.category() == Category.LICENSE;
            List<Location> locs = new ArrayList<>();
            List<String> items = new ArrayList<>();
            List<Finding> sorted = fs.stream().sorted(Comparator.comparing(Finding::file).thenComparingInt(Finding::line)).toList();
            if (deps || license) {
                for (Finding f : sorted) {
                    items.add("[" + f.severity() + "] " + f.message()
                            + (deps && f.fix() != null ? "  ->  " + oneLine(f.fix()) : "")
                            + (f.file().equals("package.json") ? "" : "  (" + f.file() + ")"));
                }
            } else {
                int shown = 0;
                for (Finding f : sorted) {
                    if (locs.size() >= LOCATIONS_PER_TASK) break;
                    String snip = shown++ < SNIPPETS_PER_TASK && !isSecret(f) ? snippet(scanRoot, f) : null;
                    locs.add(new Location(f.file(), f.line(), snip));
                }
            }
            String title = deps
                    ? "Upgrade " + fs.size() + " vulnerable dependenc" + (fs.size() == 1 ? "y" : "ies") + " (" + first.tool() + ")"
                    : license ? "Resolve " + fs.size() + " dependency license issue" + (fs.size() == 1 ? "" : "s") + " (" + first.rule() + ")"
                    : first.message() + (fs.size() > 1 ? " (x" + fs.size() + ")" : "");
            String owasp = first.owasp() == null ? null : OwaspMapper.NAMES.getOrDefault(first.owasp(), first.owasp());
            String fix = deps ? "Upgrade each package to a fixed version (prefer direct dependencies; `npm audit fix`, "
                    + "override/resolutions for transitive ones, or bump the Maven version). Re-run the project's tests."
                    : (first.fix() == null ? "Review and remediate according to the rule's guidance." : first.fix());
            tasks.add(new Task(String.format("T%03d", n++), p.name(), p.path(), first.severity(), first.category(),
                    first.rule(), first.tool(), owasp, first.cwe(), title, first.message(), fix, fs.size(), locs, items,
                    verifyCommand(p), "Re-running `bairav` no longer reports " + (deps ? first.tool() + " dependency findings for this project"
                    : "rule `" + first.rule() + "` for this project") + ", and `" + verifyCommand(p) + "` still passes."));
        }
        return tasks;
    }

    private static int maxSeverity(List<Finding> fs) {
        return fs.stream().mapToInt(f -> f.severity().weight).max().orElse(0);
    }

    private static String verifyCommand(ProjectResult p) {
        String cd = p.path().equals(".") ? "" : "cd " + p.path() + " && ";
        if (p.stacks().contains(RepoInfo.Stack.MAVEN)) return cd + "mvn -q -B test";
        if (p.stacks().contains(RepoInfo.Stack.GRADLE)) return cd + "./gradlew test";
        return cd + "npm run build";
    }

    private static String snippet(Path root, Finding f) {
        if (f.line() <= 0) return null;
        try {
            Path p = root.resolve(f.file());
            if (!Files.isRegularFile(p) || Files.size(p) > 500_000) return null;
            List<String> lines = Files.readAllLines(p);
            int from = Math.max(1, f.line() - SNIPPET_CONTEXT);
            int to = Math.min(lines.size(), f.line() + SNIPPET_CONTEXT);
            StringBuilder sb = new StringBuilder();
            for (int i = from; i <= to; i++) {
                String l = lines.get(i - 1);
                sb.append(i == f.line() ? "> " : "  ").append(String.format("%4d", i)).append(" | ")
                        .append(l.length() > 200 ? l.substring(0, 200) + "..." : l).append('\n');
            }
            return sb.toString().stripTrailing();
        } catch (Exception e) {
            return null;
        }
    }

    /** Never copy lines that may contain a credential into the plan (it is meant to be pasted into an AI). */
    private static boolean isSecret(Finding f) {
        return f.category() == Category.SECRETS
                || f.rule().toLowerCase().matches(".*(secret|hard_?code|password|credential|token|api-?key).*");
    }

    private static String oneLine(String s) {
        return s.replaceAll("\\s+", " ").trim();
    }

    public static void write(Path outDir, Path scanRoot, List<ProjectResult> projects, Baseline.Diff diff, String cliHint,
                             dev.repolens.report.RunMeta meta, dev.repolens.report.Gate gate)
            throws IOException {
        List<Task> tasks = buildTasks(scanRoot, projects);
        Files.createDirectories(outDir);
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("schemaVersion", dev.repolens.report.RunMeta.SCHEMA_VERSION);
        json.put("meta", meta);
        json.put("gate", gate);
        json.put("scanRoot", scanRoot.toString());
        json.put("instructions", instructions());
        json.put("tasks", tasks);
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValue(outDir.resolve("ai-fix-plan.json").toFile(), json);
        Files.writeString(outDir.resolve("ai-fix-plan.md"), markdown(scanRoot, projects, tasks, diff, cliHint));
    }

    private static List<String> instructions() {
        return List.of(
                "Work through the tasks in order (they are sorted by severity, then number of occurrences).",
                "Make one focused change per task; do not refactor or reformat unrelated code.",
                "File paths are relative to the scan root. Locations marked '>' in snippets are the flagged lines.",
                "After each task run its Verify command; if it fails, fix or revert before moving on.",
                "If a finding is a false positive, do not change code: add a suppression with a one-line justification to .bairav.yml (ignoreRules / ignorePaths).",
                "Never commit secrets: rotate leaked credentials and move them to environment variables.",
                "Security fixes take priority over performance, SEO and style tasks.");
    }

    private static String markdown(Path root, List<ProjectResult> projects, List<Task> tasks, Baseline.Diff diff, String cliHint) {
        StringBuilder m = new StringBuilder();
        m.append("# Bairav AI fix plan\n\n");
        m.append("- Generated: ").append(LocalDateTime.now().withNano(0)).append('\n');
        m.append("- Scan root: `").append(root).append("`\n");
        m.append("- Tasks: ").append(tasks.size()).append('\n');
        if (diff != null) {
            m.append("- Since baseline: ").append(diff.added().size()).append(" new, ").append(diff.fixed())
                    .append(" fixed, ").append(diff.unchanged()).append(" unchanged\n");
        }
        m.append("\n## Instructions for the AI agent\n\n");
        int i = 1;
        for (String s : instructions()) m.append(i++).append(". ").append(s).append('\n');

        m.append("\n## Projects\n\n| Project | Path | Stack | Grade | Scores | Open tasks |\n|---|---|---|---|---|---|\n");
        for (ProjectResult p : projects) {
            long open = tasks.stream().filter(t -> t.project().equals(p.name())).count();
            m.append("| ").append(p.name()).append(" | `").append(p.path()).append("` | ").append(p.stacks()).append(" | ")
                    .append(p.scores().grade()).append(" (").append(p.scores().overall()).append(") | ")
                    .append(p.scores().byArea()).append(" | ").append(open).append(" |\n");
        }

        m.append("\n## Priority order\n\n| ID | Severity | Project | Category | Task | Count |\n|---|---|---|---|---|---|\n");
        for (Task t : tasks) {
            m.append("| ").append(t.id()).append(" | ").append(t.severity()).append(" | ").append(t.project()).append(" | ")
                    .append(t.category()).append(" | ").append(escapePipe(t.title())).append(" | ").append(t.occurrences()).append(" |\n");
        }

        m.append("\n## Suggested batches (one project per AI session)\n\n");
        for (ProjectResult p : projects) {
            List<String> ids = tasks.stream().filter(t -> t.project().equals(p.name())).map(Task::id).toList();
            if (!ids.isEmpty()) m.append("- **").append(p.name()).append("** (`").append(p.path()).append("`): ").append(String.join(", ", ids)).append('\n');
        }

        m.append("\n## Tasks\n");
        for (Task t : tasks) {
            m.append("\n### ").append(t.id()).append(" [").append(t.severity()).append("] ").append(t.title()).append("\n\n");
            m.append("- Project: `").append(t.project()).append("` (`").append(t.projectPath()).append("`)\n");
            m.append("- Category: ").append(t.category()).append(" | Tool: ").append(t.tool()).append(" | Rule: `").append(t.rule()).append("`\n");
            if (t.owasp() != null || t.cwe() != null) {
                m.append("- Standards: ").append(t.owasp() == null ? "" : t.owasp()).append(t.cwe() == null ? "" : " " + t.cwe()).append('\n');
            }
            m.append("- Problem: ").append(t.problem()).append('\n');
            m.append("- Fix: ").append(t.fix()).append('\n');
            m.append("- Occurrences: ").append(t.occurrences()).append('\n');
            if (!t.items().isEmpty()) {
                m.append("- Items:\n");
                t.items().forEach(it -> m.append("  - ").append(it).append('\n'));
            }
            if (!t.locations().isEmpty()) {
                m.append("- Locations:\n");
                for (Location l : t.locations()) {
                    m.append("  - `").append(l.file()).append(l.line() > 0 ? ":" + l.line() : "").append("`\n");
                    if (l.snippet() != null) {
                        m.append("\n    ```").append(lang(l.file())).append('\n');
                        for (String line : l.snippet().split("\n")) m.append("    ").append(line).append('\n');
                        m.append("    ```\n\n");
                    }
                }
                if (t.occurrences() > t.locations().size()) {
                    m.append("  - ... and ").append(t.occurrences() - t.locations().size()).append(" more (see report.json)\n");
                }
            }
            m.append("- Verify: `").append(t.verify()).append("`\n");
            m.append("- Done when: ").append(t.doneWhen()).append('\n');
        }
        if (cliHint != null) m.append("\n---\nRe-check after fixing: `").append(cliHint).append("`\n");
        return m.toString();
    }

    private static String lang(String file) {
        int i = file.lastIndexOf('.');
        String e = i < 0 ? "" : file.substring(i + 1);
        return switch (e) {
            case "tsx", "ts", "jsx", "js", "java", "html", "xml", "properties" -> e;
            case "yml", "yaml" -> "yaml";
            default -> "";
        };
    }

    private static String escapePipe(String s) {
        return s.replace("|", "\\|");
    }
}
