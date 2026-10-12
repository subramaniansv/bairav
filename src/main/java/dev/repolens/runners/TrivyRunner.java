package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.normalize.SarifParser;

import java.nio.file.Path;
import java.util.List;

/** Dependency CVEs, secrets and IaC/Dockerfile misconfig in a single pass. */
public class TrivyRunner extends ExternalToolRunner {

    @Override public String name() { return "trivy"; }
    @Override protected String binary() { return "trivy"; }
    @Override protected String installHint() { return "brew install trivy"; }
    @Override protected String outputFileName() { return "trivy.sarif"; }

    /** An empty docker config avoids "docker-credential-osxkeychain not found" when pulling the vuln DB. */
    @Override
    protected java.util.Map<String, String> env() {
        try {
            return java.util.Map.of("DOCKER_CONFIG", java.nio.file.Files.createTempDirectory("bairav-docker").toString());
        } catch (java.io.IOException e) {
            return java.util.Map.of();
        }
    }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        return List.of(bin.toString(), "fs", "--quiet", "--scanners", "vuln,misconfig",
                "--format", "sarif", "--output", out.toString(), ctx.root().toString());
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        return SarifParser.parse(out, name(), Category.DEPENDENCY, ctx.root());
    }
}
