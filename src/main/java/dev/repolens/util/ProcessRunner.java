package dev.repolens.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

public final class ProcessRunner {

    public static final int TIMEOUT = -1;

    private ProcessRunner() {}

    /**
     * Runs a command. stdout goes to stdoutFile, stderr to stderrFile (same file = merged).
     * Files, not pipes, so a chatty tool can never deadlock on a full buffer.
     */
    public static int run(List<String> cmd, Path cwd, Path stdoutFile, Path stderrFile, int timeoutSec)
            throws IOException, InterruptedException {
        return run(cmd, cwd, stdoutFile, stderrFile, timeoutSec, java.util.Map.of());
    }

    public static int run(List<String> cmd, Path cwd, Path stdoutFile, Path stderrFile, int timeoutSec,
                          java.util.Map<String, String> env) throws IOException, InterruptedException {
        Files.createDirectories(stdoutFile.getParent());
        Files.createDirectories(stderrFile.getParent());
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(cwd.toFile());
        pb.environment().putAll(env);
        pb.redirectOutput(stdoutFile.toFile());
        if (stdoutFile.equals(stderrFile)) {
            pb.redirectErrorStream(true);
        } else {
            pb.redirectError(stderrFile.toFile());
        }
        Process p = pb.start();
        if (!p.waitFor(timeoutSec, TimeUnit.SECONDS)) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
            return TIMEOUT;
        }
        return p.exitValue();
    }

    /** Looks on PATH plus common Homebrew locations (GUI-launched JVMs often have a short PATH). */
    public static Path which(String binary) {
        String path = System.getenv().getOrDefault("PATH", "");
        String[] dirs = (path + ":/opt/homebrew/bin:/usr/local/bin").split(":");
        for (String d : dirs) {
            if (d.isBlank()) continue;
            Path p = Path.of(d, binary);
            if (Files.isRegularFile(p) && Files.isExecutable(p)) return p;
        }
        return null;
    }
}
