package dev.repolens.runners;

import dev.repolens.config.Config;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.ToolResult;

import java.nio.file.Path;

public interface ToolRunner {

    String name();

    boolean applicable(RepoInfo repo);

    ToolResult run(Context ctx) throws Exception;

    /** Everything a runner needs; workDir holds raw outputs and logs for debugging. */
    record Context(RepoInfo repo, Path workDir, boolean dryRun, int timeoutSec, boolean build, String url, boolean zap,
                   Config config, boolean load) {

        public Context(RepoInfo repo, Path workDir, boolean dryRun, int timeoutSec, boolean build, String url, boolean zap,
                       Config config) {
            this(repo, workDir, dryRun, timeoutSec, build, url, zap, config, false);
        }

        public Context(RepoInfo repo, Path workDir, boolean dryRun, int timeoutSec, boolean build, String url, boolean zap) {
            this(repo, workDir, dryRun, timeoutSec, build, url, zap, new Config(), false);
        }

        public Path root() {
            return repo.root();
        }

        public Path rawFile(String name) {
            return workDir.resolve("raw").resolve(name);
        }

        public Path logFile(String tool) {
            return workDir.resolve("logs").resolve(tool + ".log");
        }
    }
}
