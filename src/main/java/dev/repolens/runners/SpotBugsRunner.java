package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.util.ProcessRunner;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/** SpotBugs + Find Security Bugs on compiled classes (target/classes). */
public class SpotBugsRunner extends ExternalToolRunner {

    private static final String FSB_COORD = "com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0";

    @Override public String name() { return "spotbugs"; }
    @Override protected String binary() { return "spotbugs"; }
    @Override protected String installHint() { return "brew install spotbugs"; }
    @Override protected String outputFileName() { return "spotbugs.xml"; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return repo.has(RepoInfo.Stack.MAVEN) || repo.has(RepoInfo.Stack.GRADLE);
    }

    @Override
    protected String skipReason(Context ctx) {
        return classesDir(ctx) == null ? "no compiled classes: run `mvn compile` first, or use --build" : null;
    }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        List<String> c = new ArrayList<>(List.of(bin.toString(), "-textui", "-medium", "-xml:withMessages",
                "-output", out.toString()));
        Path fsb = findSecBugsJar(ctx);
        if (fsb != null) {
            c.add("-pluginList");
            c.add(fsb.toString());
        }
        c.add(classesDir(ctx).toString());
        return c;
    }

    private static Path classesDir(Context ctx) {
        for (String d : List.of("target/classes", "build/classes/java/main")) {
            Path p = ctx.root().resolve(d);
            if (Files.isDirectory(p)) return p;
        }
        return null;
    }

    /** Find Security Bugs adds the injection/crypto/Spring rules; fetched once into ~/.m2 via Maven. */
    private static Path findSecBugsJar(Context ctx) {
        Path base = Path.of(System.getProperty("user.home"), ".m2/repository/com/h3xstream/findsecbugs/findsecbugs-plugin");
        Path jar = lookup(base);
        if (jar == null && ProcessRunner.which("mvn") != null) {
            try {
                Path log = ctx.logFile("spotbugs-plugin-download");
                ProcessRunner.run(List.of("mvn", "-q", "-B", "dependency:get", "-Dartifact=" + FSB_COORD),
                        ctx.root(), log, log, 180);
                jar = lookup(base);
            } catch (Exception ignored) {
                // run without the plugin
            }
        }
        return jar;
    }

    private static Path lookup(Path base) {
        if (!Files.isDirectory(base)) return null;
        try (Stream<Path> s = Files.walk(base, 2)) {
            return s.filter(p -> p.toString().endsWith(".jar")).findFirst().orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        var doc = dbf.newDocumentBuilder().parse(out.toFile());
        List<Finding> res = new ArrayList<>();
        NodeList bugs = doc.getElementsByTagName("BugInstance");
        for (int i = 0; i < bugs.getLength(); i++) {
            Element b = (Element) bugs.item(i);
            String type = b.getAttribute("type");
            String cat = b.getAttribute("category");
            int prio = b.getAttribute("priority").isEmpty() ? 2 : Integer.parseInt(b.getAttribute("priority"));
            Category c = switch (cat) {
                case "SECURITY", "MALICIOUS_CODE" -> Category.SECURITY;
                case "PERFORMANCE" -> Category.PERFORMANCE;
                default -> Category.QUALITY;
            };
            Severity sev = c == Category.SECURITY
                    ? (prio == 1 ? Severity.HIGH : prio == 2 ? Severity.MEDIUM : Severity.LOW)
                    : (prio == 1 ? Severity.MEDIUM : Severity.LOW);
            String file = ".";
            int line = 0;
            Element sl = firstSourceLine(b);
            if (sl != null) {
                file = resolveSource(ctx, sl.getAttribute("sourcepath"));
                line = sl.getAttribute("start").isEmpty() ? 0 : Integer.parseInt(sl.getAttribute("start"));
            }
            String cwe = b.getAttribute("cweid").isEmpty() ? null : "CWE-" + b.getAttribute("cweid");
            NodeList lm = b.getElementsByTagName("LongMessage");
            String msg = lm.getLength() > 0 ? lm.item(0).getTextContent() : type;
            res.add(new Finding(name(), c, sev, file, line, "spotbugs:" + type, msg, cwe, null, null));
        }
        return res;
    }

    private static Element firstSourceLine(Element bug) {
        for (Node n = bug.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && e.getTagName().equals("SourceLine") && !e.getAttribute("start").isEmpty()) return e;
        }
        NodeList all = bug.getElementsByTagName("SourceLine");
        for (int i = 0; i < all.getLength(); i++) {
            Element e = (Element) all.item(i);
            if (!e.getAttribute("start").isEmpty()) return e;
        }
        return null;
    }

    private static String resolveSource(Context ctx, String sourcepath) {
        for (String base : List.of("src/main/java/", "src/test/java/", "")) {
            if (Files.exists(ctx.root().resolve(base + sourcepath))) return base + sourcepath;
        }
        return sourcepath;
    }
}
