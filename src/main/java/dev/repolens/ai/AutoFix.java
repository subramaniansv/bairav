package dev.repolens.ai;

import dev.repolens.core.Bairav;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Auto-fix loop: for each top task of the AI plan, runs a user-supplied agent command, verifies, and commits.
 * Failed attempts are rolled back, so the branch only ever contains verified fixes. The agent command is
 * user-provided and runs with the user's privileges; it is never executed against a dirty tree.
 */
public final class AutoFix {

    public record Outcome(String taskId, boolean fixed, String detail) {}

    private AutoFix() {}

    public static List<Outcome> run(Path repo, Path outDir, List<AiPlanWriter.Task> tasks, String agentCmd, int max,
                                    int timeoutSec) throws IOException, InterruptedException {
        if (!"".equals(sh(repo, 60, "git status --porcelain").out().trim())) {
            throw new IOException("Working tree is not clean; commit or stash first so failed fixes can be rolled back.");
        }
        String branch = "bairav/autofix-" + System.currentTimeMillis();
        if (sh(repo, 60, "git checkout -b " + branch).code() != 0) throw new IOException("Could not create branch " + branch);
        Path dir = outDir.resolve("autofix");
        Files.createDirectories(dir);

        List<Outcome> outcomes = new ArrayList<>();
        for (AiPlanWriter.Task t : tasks.stream().limit(max).toList()) {
            Path prompt = dir.resolve(safe(t.id()) + ".md");
            Files.writeString(prompt, prompt(t));
            String cmd = agentCmd.replace("{prompt_file}", "'" + prompt.toAbsolutePath() + "'");
            Result a = shEnv(repo, timeoutSec, cmd, t, prompt);
            if (a.code() != 0) {
                rollback(repo);
                outcomes.add(new Outcome(t.id(), false, "agent failed (exit " + a.code() + ")"));
                continue;
            }
            if ("".equals(sh(repo, 60, "git status --porcelain").out().trim())) {
                outcomes.add(new Outcome(t.id(), false, "agent made no changes"));
                continue;
            }
            Result v = t.verify() == null || t.verify().isBlank() ? new Result(0, "") : sh(repo, timeoutSec, t.verify());
            if (v.code() != 0) {
                rollback(repo);
                outcomes.add(new Outcome(t.id(), false, "verify failed (exit " + v.code() + ")"));
                continue;
            }
            Result c = shEnv(repo, 60, "git add -A && git commit -q -m \"bairav: fix " + safe(t.rule()) + " in " + safe(t.project())
                    + "\" -m \"Task " + safe(t.id()) + "\"", t, prompt);
            outcomes.add(new Outcome(t.id(), c.code() == 0, c.code() == 0 ? "committed" : "commit failed"));
            if (c.code() != 0) rollback(repo);
        }
        return outcomes;
    }

    /** Re-scans the fixed tree against the pre-fix report so "fixed vs new" is measured, not assumed. */
    public static Bairav.Result rescan(Bairav.Request base, Path baselineReport, Path out) throws Exception {
        Bairav.Request r = new Bairav.Request(base.repo(), out, base.timeoutSec(), base.dryRun(), base.build(), base.only(),
                base.urls(), base.zap(), base.verbose(), base.config(), base.policy(), baselineReport.toString(), null,
                base.projectId(), base.plugins(), base.failOn(), base.newOnly(), false);
        return Bairav.scan(r);
    }

    static String prompt(AiPlanWriter.Task t) {
        StringBuilder s = new StringBuilder("# Fix: ").append(t.title()).append("\n\n");
        s.append("Project: ").append(t.project()).append(" (").append(t.projectPath()).append(")\n");
        s.append("Severity: ").append(t.severity()).append("  Rule: ").append(t.rule());
        if (t.cwe() != null) s.append("  ").append(t.cwe());
        s.append("\n\n## Problem\n").append(t.problem()).append("\n\n## How to fix\n").append(t.fix()).append("\n\n## Locations\n");
        t.locations().forEach(l -> s.append("- ").append(l.file()).append(l.line() > 0 ? ":" + l.line() : "").append('\n'));
        s.append("\n## Rules\n- Make the smallest change that fixes this issue only.\n- Do not touch unrelated files.\n");
        s.append("- Done when: ").append(t.doneWhen()).append("\n- Verify with: ").append(t.verify()).append('\n');
        return s.toString();
    }

    private static void rollback(Path repo) throws IOException, InterruptedException {
        sh(repo, 60, "git reset -q --hard HEAD");
        sh(repo, 60, "git clean -fdq");
    }

    private static String safe(String s) {
        return s == null ? "" : s.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    record Result(int code, String out) {}

    private static Result sh(Path cwd, int timeoutSec, String cmd) throws IOException, InterruptedException {
        return exec(cwd, timeoutSec, cmd, null, null, null);
    }

    private static Result shEnv(Path cwd, int timeoutSec, String cmd, AiPlanWriter.Task t, Path prompt)
            throws IOException, InterruptedException {
        return exec(cwd, timeoutSec, cmd, t.id(), prompt, t);
    }

    private static Result exec(Path cwd, int timeoutSec, String cmd, String id, Path prompt, AiPlanWriter.Task t)
            throws IOException, InterruptedException {
        Path log = Files.createTempFile("bairav-autofix", ".log");
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd).directory(cwd.toFile()).redirectErrorStream(true)
                    .redirectOutput(log.toFile());
            if (id != null) {
                pb.environment().put("BAIRAV_TASK_ID", id);
                pb.environment().put("BAIRAV_TASK_FILE", prompt.toAbsolutePath().toString());
            }
            Process p = pb.start();
            if (!p.waitFor(timeoutSec, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return new Result(-1, "timeout");
            }
            return new Result(p.exitValue(), Files.readString(log));
        } finally {
            Files.deleteIfExists(log);
        }
    }
}
