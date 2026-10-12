package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.Severity;
import dev.repolens.normalize.SarifParser;

import java.nio.file.Path;
import java.util.List;

public class GitleaksRunner extends ExternalToolRunner {

    @Override public String name() { return "gitleaks"; }
    @Override protected String binary() { return "gitleaks"; }
    @Override protected String installHint() { return "brew install gitleaks"; }
    @Override protected String outputFileName() { return "gitleaks.sarif"; }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        return List.of(bin.toString(), "detect", "--no-git", "--redact", "--source", ctx.root().toString(),
                "--report-format", "sarif", "--report-path", out.toString());
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        // Gitleaks marks everything "error"; a leaked secret is always at least HIGH.
        return SarifParser.parse(out, name(), Category.SECRETS, ctx.root()).stream()
                .map(f -> new Finding(f.tool(), f.category(), Severity.HIGH, f.file(), f.line(), f.rule(),
                        f.message(), "CWE-798", "A07", "Rotate the credential and move it to a secret manager / env var."))
                .toList();
    }
}
