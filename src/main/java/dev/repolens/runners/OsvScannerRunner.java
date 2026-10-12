package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.normalize.SarifParser;

import java.nio.file.Path;
import java.util.List;

public class OsvScannerRunner extends ExternalToolRunner {

    @Override public String name() { return "osv-scanner"; }
    @Override protected String binary() { return "osv-scanner"; }
    @Override protected String installHint() { return "brew install osv-scanner"; }
    @Override protected String outputFileName() { return "osv.sarif"; }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        return List.of(bin.toString(), "scan", "--format", "sarif", "--output", out.toString(),
                "-r", ctx.root().toString());
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        return SarifParser.parse(out, name(), Category.DEPENDENCY, ctx.root());
    }
}
