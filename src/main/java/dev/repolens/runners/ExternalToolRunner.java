package dev.repolens.runners;

import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.ToolResult;
import dev.repolens.util.ProcessRunner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Template for CLI tools: check installed, run with timeout, parse output file, fail soft. */
public abstract class ExternalToolRunner implements ToolRunner {

    protected abstract String binary();

    protected abstract String installHint();

    protected abstract String outputFileName();

    protected abstract List<String> command(Context ctx, Path binaryPath, Path out);

    protected abstract List<Finding> parse(Context ctx, Path out) throws Exception;

    protected Set<Integer> okExitCodes() {
        return Set.of(0, 1); // most scanners exit 1 when they find something
    }

    /** Where to find the executable; override for tools installed outside PATH. */
    protected Path locate() {
        return ProcessRunner.which(binary());
    }

    /** Non-null means "skip with this reason" (e.g. a prerequisite like a URL or compiled classes is missing). */
    protected String skipReason(Context ctx) {
        return null;
    }

    protected Map<String, String> metrics(Context ctx, Path out) {
        return Map.of();
    }

    /** Extra environment variables for the child process. */
    protected Map<String, String> env() {
        return Map.of();
    }

    /** True when the tool prints its report to stdout instead of writing a file. */
    protected boolean stdoutIsReport() {
        return false;
    }

    @Override
    public boolean applicable(RepoInfo repo) {
        return true;
    }

    @Override
    public final ToolResult run(Context ctx) throws Exception {
        String why = skipReason(ctx);
        if (why != null) {
            return ToolResult.skipped(name(), why);
        }
        Path bin = locate();
        if (bin == null) {
            return ToolResult.skipped(name(), "not installed - " + installHint());
        }
        Path out = ctx.rawFile(outputFileName());
        Files.createDirectories(out.getParent());
        List<String> cmd = command(ctx, bin, out);
        if (ctx.dryRun()) {
            return ToolResult.skipped(name(), "dry-run: " + String.join(" ", cmd));
        }
        Path log = ctx.logFile(name());
        long start = System.currentTimeMillis();
        int exit = stdoutIsReport()
                ? ProcessRunner.run(cmd, ctx.root(), out, log, ctx.timeoutSec(), env())
                : ProcessRunner.run(cmd, ctx.root(), log, log, ctx.timeoutSec(), env());
        long ms = System.currentTimeMillis() - start;
        if (exit == ProcessRunner.TIMEOUT) {
            return ToolResult.failed(name(), "timed out after " + ctx.timeoutSec() + "s, see " + log, ms);
        }
        if (!okExitCodes().contains(exit)) {
            return ToolResult.failed(name(), "exit code " + exit + ", see " + log, ms);
        }
        if (!Files.exists(out)) {
            return ToolResult.failed(name(), "no output produced, see " + log, ms);
        }
        try {
            List<Finding> findings = parse(ctx, out);
            return ToolResult.ok(name(), findings, findings.size() + " finding(s)", ms)
                    .withMetrics(new java.util.LinkedHashMap<>(metrics(ctx, out)));
        } catch (Exception e) {
            return ToolResult.failed(name(), "could not parse " + out + ": " + e.getMessage(), ms);
        }
    }
}
