package dev.repolens.report;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Who/what/when of a run. Lets a central store and dashboards tell runs from different projects, branches and
 * commits apart. Values come from CI environment variables first, then from git.
 */
public record RunMeta(int schemaVersion, String toolVersion, String projectId, String branch, String commit,
                      String ci, String startedAt, long durationMs) {

    /** Bump when report.json / ai-fix-plan.json change shape in a breaking way. */
    public static final int SCHEMA_VERSION = 2;

    public static RunMeta detect(Path root, String projectIdOverride, String toolVersion, LocalDateTime started, long durationMs) {
        String commit = firstNonBlank(env("GITHUB_SHA"), env("CI_COMMIT_SHA"), env("GIT_COMMIT"), env("BUILD_VCS_NUMBER"),
                git(root, "rev-parse", "HEAD"));
        String branch = firstNonBlank(env("GITHUB_HEAD_REF"), env("GITHUB_REF_NAME"), env("CI_COMMIT_REF_NAME"),
                env("BRANCH_NAME"), env("GIT_BRANCH"), git(root, "rev-parse", "--abbrev-ref", "HEAD"));
        String id = firstNonBlank(projectIdOverride, env("GITHUB_REPOSITORY"), env("CI_PROJECT_PATH"),
                root.getFileName() == null ? "root" : root.getFileName().toString());
        String ci = env("GITHUB_ACTIONS") != null ? "github-actions" : env("GITLAB_CI") != null ? "gitlab-ci"
                : env("JENKINS_URL") != null ? "jenkins" : env("CI") != null ? "ci" : "local";
        return new RunMeta(SCHEMA_VERSION, toolVersion, sanitize(id), branch, commit, ci, started.withNano(0).toString(), durationMs);
    }

    /** Safe as a directory name in the central store. */
    static String sanitize(String id) {
        return id.replaceAll("[^A-Za-z0-9._-]+", "_");
    }

    private static String env(String k) {
        String v = System.getenv(k);
        return v == null || v.isBlank() ? null : v;
    }

    private static String firstNonBlank(String... vs) {
        for (String v : vs) if (v != null && !v.isBlank()) return v;
        return null;
    }

    private static String git(Path root, String... args) {
        try {
            List<String> cmd = new java.util.ArrayList<>(List.of("git", "-C", root.toString()));
            cmd.addAll(List.of(args));
            Process p = new ProcessBuilder(cmd).redirectErrorStream(false)
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            if (!p.waitFor(10, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            return p.exitValue() == 0 && !out.isBlank() ? out : null;
        } catch (Exception e) {
            return null;
        }
    }
}
