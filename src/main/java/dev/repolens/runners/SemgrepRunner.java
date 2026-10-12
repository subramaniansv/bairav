package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.normalize.SarifParser;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SemgrepRunner extends ExternalToolRunner {

    @Override public String name() { return "semgrep"; }
    @Override protected String binary() { return "semgrep"; }
    @Override protected String installHint() { return "brew install semgrep"; }
    @Override protected String outputFileName() { return "semgrep.sarif"; }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        List<String> c = new ArrayList<>(List.of(bin.toString(), "scan", "--metrics=off"));
        for (String cfg : List.of("p/owasp-top-ten", "p/java", "p/findsecbugs", "p/jwt", "p/javascript", "p/typescript",
                "p/react", "p/nodejs", "p/secrets")) {
            c.add("--config");
            c.add(cfg);
        }
        c.addAll(List.of("--sarif", "--output", out.toString(), ctx.root().toString()));
        return c;
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        return SarifParser.parse(out, name(), Category.SECURITY, ctx.root());
    }
}
