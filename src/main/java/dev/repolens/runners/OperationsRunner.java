package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.ProcessRunner;
import dev.repolens.util.RepoWalker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Operational readiness: observability (health/metrics/tracing/error tracking), configuration and secrets hygiene,
 * and a small built-in Dockerfile/Kubernetes/Terraform check used only when Trivy (which covers IaC properly)
 * is not installed.
 */
public class OperationsRunner implements ToolRunner {

    public static final String NAME = "operations";

    private static final Pattern DDL = Pattern.compile("(?i)ddl-auto\\s*[:=]\\s*(create-drop|create|update)\\b");
    private static final Pattern SECRET_KEY = Pattern.compile("(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)");

    @Override public String name() { return NAME; }

    @Override public boolean applicable(RepoInfo repo) { return true; }

    @Override
    public ToolResult run(Context ctx) throws IOException {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        List<Finding> out = new ArrayList<>();
        boolean trivy = ProcessRunner.which("trivy") != null;

        String pom = read(root.resolve("pom.xml")) + read(root.resolve("build.gradle")) + read(root.resolve("build.gradle.kts"));
        String pkg = read(root.resolve("package.json"));
        boolean spring = pom.contains("spring-boot");
        boolean web = pom.contains("spring-boot-starter-web") || pom.contains("spring-boot-starter-webflux");
        boolean nodeServer = pkg.matches("(?s).*\"(express|fastify|koa|@nestjs/core|hapi)\".*");
        boolean react = pkg.contains("\"react\"");

        if (spring) springObservability(pom, web, out);
        if (nodeServer) nodeObservability(root, pkg, out);
        if (react && !pkg.matches("(?s).*(sentry|bugsnag|datadog|rollbar|newrelic|logrocket|honeybadger|appinsights).*")) {
            add(out, Category.OPERATIONS, Severity.INFO, "package.json", 0, "no-frontend-error-tracking",
                    "No frontend error tracking/RUM dependency found", "Add Sentry/Datadog RUM or similar so production errors are visible.");
        }

        RepoWalkerHolder.walk(root, (p, rel, name, size) -> {
            try {
                if (name.equals(".env") || (name.startsWith(".env.") && !name.endsWith(".example") && !name.endsWith(".sample")
                        && !name.endsWith(".template"))) {
                    envFile(root, p, rel, out);
                } else if (name.matches("application(-[\\w]+)?\\.(properties|ya?ml)")) {
                    springConfig(p, rel, name, out);
                } else if (!trivy) {
                    fallbackIac(p, rel, name, out);
                }
            } catch (IOException | RuntimeException e) {
                // unreadable file
            }
        });
        String d = out.size() + " finding(s)" + (trivy ? "" : " (Trivy missing: used built-in Docker/K8s/Terraform checks)");
        return ToolResult.ok(NAME, out, d, System.currentTimeMillis() - start);
    }

    // ---- observability ----------------------------------------------------------------------------------------

    static void springObservability(String pom, boolean web, List<Finding> out) {
        if (!pom.contains("spring-boot-starter-actuator")) {
            add(out, Category.OPERATIONS, Severity.MEDIUM, "pom.xml", 0, "no-actuator",
                    "Spring Boot app has no Actuator: no health, metrics or readiness endpoints",
                    "Add spring-boot-starter-actuator and expose only health/info (and metrics behind auth).");
        } else if (!pom.matches("(?s).*(micrometer-registry|opentelemetry|micrometer-tracing|spring-boot-starter-opentelemetry).*")) {
            add(out, Category.OPERATIONS, Severity.LOW, "pom.xml", 0, "no-metrics-export",
                    "Actuator present but no metrics registry or tracing exporter (Prometheus/OTel)",
                    "Add micrometer-registry-prometheus or the OpenTelemetry starter and a tracing bridge.");
        }
        if (web && !pom.matches("(?s).*(logstash-logback-encoder|logging-ecs|ecs-logging|log4j-layout-template-json).*")) {
            add(out, Category.OPERATIONS, Severity.INFO, "pom.xml", 0, "no-structured-logging",
                    "No structured (JSON) logging library found",
                    "Use JSON logs (Spring Boot 3.4+ logging.structured.format.console=ecs) so logs are searchable.");
        }
    }

    static void nodeObservability(Path root, String pkg, List<Finding> out) throws IOException {
        boolean[] health = new boolean[1];
        RepoWalker.walk(root, (p, a) -> {
            String n = p.getFileName().toString();
            if (health[0] || a.size() > 300_000 || !n.matches(".*\\.(js|ts|mjs)$")) return;
            try {
                if (Pattern.compile("['\"`]/(health|healthz|ready|readyz|livez|ping|status)['\"`]").matcher(Files.readString(p)).find()) {
                    health[0] = true;
                }
            } catch (IOException | RuntimeException ignored) {
                // skip
            }
        });
        if (!health[0]) {
            add(out, Category.OPERATIONS, Severity.LOW, "package.json", 0, "no-health-endpoint",
                    "Node server has no /health (or similar) endpoint", "Add a cheap /healthz for load balancers and probes.");
        }
        if (!pkg.matches("(?s).*\"(pino|winston|bunyan|log4js)\".*")) {
            add(out, Category.OPERATIONS, Severity.INFO, "package.json", 0, "no-structured-logger",
                    "No structured logger (pino/winston) in dependencies", "Use pino or winston with JSON output.");
        }
    }

    // ---- config hygiene ---------------------------------------------------------------------------------------

    static void envFile(Path root, Path p, String rel, List<Finding> out) throws IOException {
        boolean secret = false;
        for (String l : Files.readAllLines(p)) {
            int i = l.indexOf('=');
            if (i <= 0 || l.trim().startsWith("#")) continue;
            String key = l.substring(0, i);
            String val = l.substring(i + 1).trim().replaceAll("^['\"]|['\"]$", "");
            if (SECRET_KEY.matcher(key).find() && !val.isEmpty() && !val.startsWith("${") && !val.equalsIgnoreCase("changeme")) {
                secret = true;
            }
        }
        boolean ignored = false;
        Path gi = root.resolve(".gitignore");
        if (Files.exists(gi)) {
            String g = Files.readString(gi);
            ignored = g.lines().anyMatch(s -> s.trim().matches("/?\\.env(\\*|\\.\\*|\\.local)?"));
        }
        if (!ignored) {
            add(out, Category.SECURITY, secret ? Severity.HIGH : Severity.MEDIUM, rel, 1, "env-file-committed",
                    "Environment file " + p.getFileName() + " is not git-ignored" + (secret ? " and contains secret-looking keys" : ""),
                    "Add it to .gitignore, rotate any real secret, and commit a .env.example with placeholders only.", "CWE-798", "A05");
        }
    }

    static void springConfig(Path p, String rel, String name, List<Finding> out) throws IOException {
        boolean prod = name.matches("application-(prod|production|live)\\..*");
        List<String> lines = Files.readAllLines(p);
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            if (l.trim().startsWith("#")) continue;
            if (DDL.matcher(l).find()) {
                add(out, Category.OPERATIONS, prod ? Severity.HIGH : Severity.MEDIUM, rel, i + 1, "ddl-auto-mutates-schema",
                        "Hibernate ddl-auto can create/alter the schema at startup" + (prod ? " in the PRODUCTION profile" : ""),
                        "Use ddl-auto=validate (or none) and manage schema with Flyway/Liquibase.", "CWE-1188", "A05");
            }
            if (l.matches("(?i).*h2\\.console\\.enabled\\s*[:=]\\s*true.*")) {
                add(out, Category.OPERATIONS, prod ? Severity.HIGH : Severity.MEDIUM, rel, i + 1, "h2-console-enabled",
                        "H2 web console enabled", "Disable it outside local development.", "CWE-489", "A05");
            }
            if (l.matches("(?i).*include-stacktrace\\s*[:=]\\s*always.*")) {
                add(out, Category.OPERATIONS, Severity.MEDIUM, rel, i + 1, "stacktrace-in-response",
                        "Error responses include stack traces", "Set server.error.include-stacktrace=never.", "CWE-209", "A05");
            }
            if (prod && l.matches("(?i).*(logging\\.level\\.root|^debug)\\s*[:=]\\s*(debug|trace|true).*")) {
                add(out, Category.OPERATIONS, Severity.LOW, rel, i + 1, "debug-logging-in-prod",
                        "Debug/trace logging enabled in the production profile", "Use INFO/WARN in production.", null, null);
            }
            if (l.matches("(?i).*datasource\\.password\\s*[:=]\\s*[^$\\s{][^\\s]*.*")) {
                add(out, Category.SECURITY, Severity.HIGH, rel, i + 1, "datasource-password-literal",
                        "Database password committed in configuration", "Use ${DB_PASSWORD} from the environment or a secret manager.",
                        "CWE-798", "A07");
            }
        }
    }

    // ---- IaC fallback when Trivy is not installed -------------------------------------------------------------

    static void fallbackIac(Path p, String rel, String name, List<Finding> out) throws IOException {
        if (name.equals("Dockerfile") || name.startsWith("Dockerfile.")) {
            List<String> l = Files.readAllLines(p);
            String all = String.join("\n", l);
            if (!all.matches("(?s).*(?m)^\\s*USER\\s+(?!root\\b)\\S+.*")) {
                add(out, Category.OPERATIONS, Severity.MEDIUM, rel, 1, "docker-runs-as-root", "Container runs as root",
                        "Add a non-root USER.", "CWE-250", "A05");
            }
            if (!all.toUpperCase().contains("HEALTHCHECK")) {
                add(out, Category.OPERATIONS, Severity.LOW, rel, 1, "docker-no-healthcheck", "No HEALTHCHECK instruction",
                        "Add HEALTHCHECK or rely on orchestrator probes.", null, null);
            }
        } else if (name.matches(".*\\.ya?ml$")) {
            String t = Files.size(p) < 300_000 ? Files.readString(p) : "";
            if (t.matches("(?s).*kind:\\s*(Deployment|StatefulSet|DaemonSet|Pod|CronJob)\\b.*") && t.contains("apiVersion:")) {
                if (t.matches("(?s).*privileged:\\s*true.*")) {
                    add(out, Category.OPERATIONS, Severity.HIGH, rel, 1, "k8s-privileged", "Privileged container",
                            "Remove privileged: true.", "CWE-250", "A05");
                }
                if (!t.contains("resources:") || !t.contains("limits:")) {
                    add(out, Category.OPERATIONS, Severity.MEDIUM, rel, 1, "k8s-no-limits", "Workload has no resource limits",
                            "Set resources.requests and limits.", "CWE-770", "A05");
                }
                if (!t.contains("readinessProbe") && !t.contains("livenessProbe")) {
                    add(out, Category.OPERATIONS, Severity.LOW, rel, 1, "k8s-no-probes", "Workload has no liveness/readiness probes",
                            "Add probes backed by the health endpoint.", null, null);
                }
            }
        } else if (name.endsWith(".tf")) {
            List<String> l = Files.readAllLines(p);
            for (int i = 0; i < l.size(); i++) {
                String s = l.get(i);
                if (s.matches(".*cidr_blocks\\s*=\\s*\\[\\s*\"0\\.0\\.0\\.0/0\".*")) {
                    add(out, Category.OPERATIONS, Severity.HIGH, rel, i + 1, "tf-open-cidr", "Security group open to 0.0.0.0/0",
                            "Restrict to known CIDR ranges.", "CWE-284", "A05");
                } else if (s.matches("(?i).*(acl\\s*=\\s*\"public-read(-write)?\"|publicly_accessible\\s*=\\s*true|encrypted\\s*=\\s*false).*")) {
                    add(out, Category.OPERATIONS, Severity.HIGH, rel, i + 1, "tf-insecure-setting", "Public or unencrypted resource",
                            "Make it private and encrypted.", "CWE-311", "A02");
                }
            }
        }
    }

    // ---- helpers ----------------------------------------------------------------------------------------------

    /** Tiny adapter so the walk callback receives relative path, file name and size. */
    interface Visitor { void visit(Path p, String rel, String name, long size) throws IOException; }

    static final class RepoWalkerHolder {
        static void walk(Path root, Visitor v) throws IOException {
            RepoWalker.walk(root, (p, a) -> {
                if (a.size() > 1_000_000) return;
                try {
                    v.visit(p, root.relativize(p).toString().replace('\\', '/'), p.getFileName().toString(), a.size());
                } catch (IOException e) {
                    // skip unreadable
                }
            });
        }
    }

    private static String read(Path p) {
        try {
            return Files.exists(p) ? Files.readString(p) : "";
        } catch (IOException e) {
            return "";
        }
    }

    private static void add(List<Finding> out, Category c, Severity s, String file, int line, String rule, String msg, String fix) {
        out.add(new Finding(NAME, c, s, file, line, rule, msg, null, null, fix));
    }

    private static void add(List<Finding> out, Category c, Severity s, String file, int line, String rule, String msg, String fix,
                            String cwe, String owasp) {
        out.add(new Finding(NAME, c, s, file, line, rule, msg, cwe, owasp, fix));
    }
}
