package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.RepoWalker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Built-in regex checks for Spring/Java and React/JS. Needs no external install, so the tool
 * always produces something. These are hints, not proof: always review in context.
 */
public class HeuristicRunner implements ToolRunner {

    private static final Set<String> JAVA = Set.of("java");
    private static final Set<String> JS = Set.of("js", "jsx", "ts", "tsx", "mjs", "html");
    private static final Set<String> CFG = Set.of("properties", "yml", "yaml");
    private static final Set<String> JAVA_JS = Set.of("java", "js", "jsx", "ts", "tsx", "mjs");
    private static final int PER_RULE_CAP = 100;
    private static final long MAX_BYTES = 1_000_000;

    record Rule(String id, Pattern pattern, Set<String> exts, Category cat, Severity sev,
                String cwe, String owasp, String msg, String fix) {
        Rule(String id, String regex, Set<String> exts, Category cat, Severity sev,
             String cwe, String owasp, String msg, String fix) {
            this(id, Pattern.compile(regex), exts, cat, sev, cwe, owasp, msg, fix);
        }
    }

    static final List<Rule> RULES = List.of(
            new Rule("sql-concat", "(?i)\"\\s*(select|update|delete|insert)\\b[^\"]*\"\\s*\\+", JAVA,
                    Category.SECURITY, Severity.HIGH, "CWE-89", "A03",
                    "SQL built by string concatenation", "Use parameterized queries / Spring Data named parameters."),
            new Rule("hardcoded-secret",
                    "(?i)(password|passwd|secret|api_?key|token)\\s*[:=]\\s*[\"'][^\"'$\\{\\s]{6,}[\"']", JAVA_JS,
                    Category.SECURITY, Severity.HIGH, "CWE-798", "A07",
                    "Possible hard-coded credential", "Load from environment or a secret manager."),
            new Rule("java-deserialization", "new\\s+ObjectInputStream", JAVA,
                    Category.SECURITY, Severity.HIGH, "CWE-502", "A08",
                    "Native Java deserialization", "Avoid it, or use a serialization filter / JSON."),
            new Rule("os-command", "Runtime\\.getRuntime\\(\\)\\.exec|new\\s+ProcessBuilder", JAVA,
                    Category.SECURITY, Severity.MEDIUM, "CWE-78", "A03",
                    "OS command execution", "Validate input strictly; avoid shelling out."),
            new Rule("weak-hash", "MessageDigest\\.getInstance\\(\\s*\"(MD5|SHA-?1)\"", JAVA,
                    Category.SECURITY, Severity.MEDIUM, "CWE-327", "A02",
                    "Weak hash algorithm", "Use SHA-256+; use bcrypt/argon2 for passwords."),
            new Rule("csrf-disabled", "csrf\\s*\\(\\s*\\)\\s*\\.\\s*disable|csrf\\s*\\(\\s*\\w+\\s*->\\s*\\w+\\.disable", JAVA,
                    Category.SECURITY, Severity.MEDIUM, "CWE-352", "A01",
                    "CSRF protection disabled", "Keep CSRF on for cookie/session auth; disable only for stateless token APIs."),
            new Rule("cors-wildcard", "@CrossOrigin\\([^)]*\"\\*\"|allowedOrigins\\(\\s*\"\\*\"", JAVA,
                    Category.SECURITY, Severity.MEDIUM, "CWE-942", "A05",
                    "CORS allows any origin", "List explicit trusted origins."),
            new Rule("actuator-exposed", "management\\.endpoints\\.web\\.exposure\\.include\\s*[=:]\\s*['\"]?\\*", CFG,
                    Category.SECURITY, Severity.MEDIUM, "CWE-200", "A05",
                    "All Actuator endpoints exposed", "Expose only health/info; secure the rest."),
            new Rule("js-eval", "\\beval\\s*\\(", JS,
                    Category.SECURITY, Severity.HIGH, "CWE-95", "A03",
                    "eval() on dynamic code", "Remove eval; parse data with JSON.parse or use safe APIs."),
            new Rule("react-dangerous-html", "dangerouslySetInnerHTML", JS,
                    Category.SECURITY, Severity.MEDIUM, "CWE-79", "A03",
                    "dangerouslySetInnerHTML (XSS risk)", "Sanitize with DOMPurify or render as text."),
            new Rule("js-innerhtml", "\\.innerHTML\\s*=|document\\.write\\s*\\(", JS,
                    Category.SECURITY, Severity.MEDIUM, "CWE-79", "A03",
                    "Raw HTML sink (XSS risk)", "Use textContent or sanitize first."),
            new Rule("token-in-localstorage", "(?i)localStorage\\.setItem\\(\\s*['\"][^'\"]*(token|jwt)", JS,
                    Category.SECURITY, Severity.MEDIUM, "CWE-922", "A04",
                    "Auth token stored in localStorage", "Prefer HttpOnly, Secure, SameSite cookies."),
            new Rule("jpa-eager", "FetchType\\.EAGER", JAVA,
                    Category.PERFORMANCE, Severity.MEDIUM, null, null,
                    "EAGER fetch can cause N+1 / over-fetching", "Use LAZY and JOIN FETCH or @EntityGraph where needed."),
            new Rule("select-star", "(?i)select\\s+\\*\\s+from", JAVA,
                    Category.PERFORMANCE, Severity.LOW, null, null,
                    "SELECT * pulls unneeded columns", "Select only required columns / use projections."),
            new Rule("find-all-unbounded", "\\.findAll\\(\\s*\\)", JAVA,
                    Category.PERFORMANCE, Severity.MEDIUM, null, null,
                    "Unbounded findAll() loads whole table", "Use Pageable or a filtered query."),
            new Rule("thread-sleep", "Thread\\.sleep\\(", JAVA,
                    Category.PERFORMANCE, Severity.LOW, null, null,
                    "Thread.sleep blocks a thread", "Use scheduling or async/reactive primitives."),
            new Rule("json-deep-clone", "JSON\\.parse\\(\\s*JSON\\.stringify", JS,
                    Category.PERFORMANCE, Severity.LOW, null, null,
                    "JSON deep clone is slow and lossy", "Use structuredClone()."),
            new Rule("print-stacktrace", "printStackTrace\\s*\\(", JAVA,
                    Category.QUALITY, Severity.LOW, "CWE-209", "A04",
                    "printStackTrace instead of logging", "Use a logger (SLF4J)."),
            new Rule("sysout", "System\\.(out|err)\\.print", JAVA,
                    Category.QUALITY, Severity.LOW, null, null,
                    "System.out used for logging", "Use a logger (SLF4J)."),
            new Rule("console-log", "console\\.log\\s*\\(", JS,
                    Category.QUALITY, Severity.LOW, null, null,
                    "console.log left in code", "Remove or use a log-level aware logger.")
    );

    @Override public String name() { return "builtin-rules"; }

    @Override public boolean applicable(RepoInfo repo) { return true; }

    @Override
    public ToolResult run(Context ctx) throws IOException {
        long start = System.currentTimeMillis();
        List<Finding> findings = new ArrayList<>();
        Map<String, Integer> perRule = new HashMap<>();
        RepoWalker.walk(ctx.root(), (file, attrs) -> {
            if (attrs.size() > MAX_BYTES) return;
            String ext = extension(file);
            List<Rule> rules = RULES.stream().filter(r -> r.exts().contains(ext)).toList();
            if (rules.isEmpty()) return;
            List<String> lines;
            try {
                lines = Files.readAllLines(file);
            } catch (Exception e) {
                return; // binary / non-UTF8
            }
            String rel = ctx.root().relativize(file).toString();
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (line.stripLeading().startsWith("//") || line.stripLeading().startsWith("*")) continue;
                for (Rule r : rules) {
                    if (r.pattern().matcher(line).find() && perRule.merge(r.id(), 1, Integer::sum) <= PER_RULE_CAP) {
                        findings.add(new Finding(name(), r.cat(), r.sev(), rel, i + 1, r.id(), r.msg(),
                                r.cwe(), r.owasp(), r.fix()));
                    }
                }
            }
        });
        return ToolResult.ok(name(), findings, findings.size() + " finding(s)", System.currentTimeMillis() - start);
    }

    private static String extension(Path p) {
        String n = p.getFileName().toString();
        int i = n.lastIndexOf('.');
        return i < 0 ? "" : n.substring(i + 1).toLowerCase();
    }
}
