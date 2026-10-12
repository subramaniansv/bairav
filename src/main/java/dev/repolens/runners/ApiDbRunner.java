package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * API quality and database review: OpenAPI lint + breaking-change detection against a git ref
 * (BAIRAV_API_BASE_REF, default HEAD), rate-limiting hints, Flyway/Liquibase migration safety,
 * likely missing indexes for Spring Data finders / foreign keys, and N+1 query patterns.
 */
public class ApiDbRunner implements ToolRunner {

    public static final String NAME = "api-db";

    private static final List<String> METHODS = List.of("get", "post", "put", "delete", "patch");
    private static final Pattern FLYWAY = Pattern.compile("^[VR](\\d+(?:[._]\\d+)*)__.+\\.sql$");
    private static final Pattern FINDER = Pattern.compile("\\b(?:find|exists|count|delete|read|get)(?:\\w*?)By(\\w+)\\s*\\(");
    private static final Pattern LOOP = Pattern.compile("\\b(for|while)\\s*\\(");
    private static final Pattern REPO_READ = Pattern.compile("\\b\\w*[Rr]epo(?:sitory)?\\w*\\s*\\.\\s*(find|get|count|exists|read)\\w*\\s*\\(");
    private static final Pattern REPO_SAVE = Pattern.compile("\\b\\w*[Rr]epo(?:sitory)?\\w*\\s*\\.\\s*save\\s*\\(");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    @Override public String name() { return NAME; }

    @Override public boolean applicable(RepoInfo repo) { return !repo.stacks().isEmpty(); }

    @Override
    public ToolResult run(Context ctx) throws Exception {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        List<Finding> out = new ArrayList<>();
        List<Path> specs = new ArrayList<>();
        List<Path> migrations = new ArrayList<>();
        List<Path> javaMain = new ArrayList<>();
        List<Path> changelogs = new ArrayList<>();

        RepoWalker.walk(root, (p, a) -> {
            String n = p.getFileName().toString().toLowerCase();
            String rel = rel(root, p);
            if (a.size() > 3_000_000) return;
            if (n.matches("(openapi|swagger)[\\w.-]*\\.(json|ya?ml)")) specs.add(p);
            else if (n.endsWith(".sql") && rel.matches("(?i).*db/(migration|migrations).*|.*flyway.*")) migrations.add(p);
            else if (n.matches(".*(changelog|liquibase).*\\.(xml|ya?ml)") && !rel.contains("/test/")) changelogs.add(p);
            else if (n.endsWith(".java") && !rel.contains("/test/")) javaMain.add(p);
        });

        for (Path s : specs) openApi(ctx, s, rel(root, s), out);
        if (specs.isEmpty()) {
            String pom = read(root.resolve("pom.xml"));
            if (pom.contains("spring-boot-starter-web") && !pom.matches("(?s).*(springdoc|springfox|swagger).*")) {
                add(out, Category.QUALITY, Severity.INFO, "pom.xml", 0, "no-openapi", "REST API has no OpenAPI spec or springdoc",
                        "Add springdoc-openapi so consumers and breaking-change checks have a contract.");
            }
        }
        rateLimiting(root, javaMain, out);
        flyway(migrations, root, out);
        liquibase(changelogs, root, out);
        indexes(root, javaMain, migrations, out);
        for (Path j : javaMain) nPlusOne(root, j, out);
        return ToolResult.ok(NAME, out, out.size() + " finding(s)", System.currentTimeMillis() - start);
    }

    // ---- OpenAPI ----------------------------------------------------------------------------------------------

    void openApi(Context ctx, Path file, String rel, List<Finding> out) {
        JsonNode spec = parse(file);
        if (spec == null || !spec.has("paths")) return;
        lint(spec, rel, out);
        String ref = System.getenv().getOrDefault("BAIRAV_API_BASE_REF", "HEAD");
        try {
            Path o = ctx.rawFile("openapi-base-" + Math.abs(rel.hashCode()) + ".txt");
            int rc = ProcessRunner.run(List.of("git", "show", ref + ":./" + ctx.root().relativize(file).toString().replace('\\', '/')),
                    ctx.root(), o, ctx.logFile(NAME), 30);
            if (rc == 0) {
                JsonNode old = parse(o, file.toString().endsWith(".json"));
                if (old != null && old.has("paths")) {
                    for (String b : breaking(old, spec)) {
                        add(out, Category.QUALITY, Severity.HIGH, rel, 0, "breaking-api-change", "Breaking API change vs " + ref + ": " + b,
                                "Version the endpoint or keep the old contract until clients migrate.");
                    }
                }
            }
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
        }
    }

    static void lint(JsonNode spec, String rel, List<Finding> out) {
        if (spec.path("info").path("version").asText("").isEmpty()) {
            add(out, Category.QUALITY, Severity.LOW, rel, 0, "openapi-no-version", "OpenAPI info.version is missing", "Set info.version.");
        }
        if (!spec.has("servers") && !spec.has("host")) {
            add(out, Category.QUALITY, Severity.LOW, rel, 0, "openapi-no-servers", "OpenAPI declares no servers", "Add a servers section.");
        }
        boolean hasSec = spec.path("components").has("securitySchemes") || spec.has("securityDefinitions");
        if (!hasSec) {
            add(out, Category.SECURITY, Severity.MEDIUM, rel, 0, "openapi-no-auth-scheme",
                    "API defines no authentication scheme (securitySchemes)", "Declare how clients authenticate.", "CWE-306", "A07");
        }
        int noOpId = 0, noSummary = 0, noErr = 0, unpagedList = 0, total = 0;
        boolean has429 = false;
        for (var pe : iter(spec.path("paths"))) {
            for (String m : METHODS) {
                JsonNode op = pe.getValue().path(m);
                if (op.isMissingNode()) continue;
                total++;
                if (!op.has("operationId")) noOpId++;
                if (!op.has("summary") && !op.has("description")) noSummary++;
                JsonNode resp = op.path("responses");
                boolean err = false;
                for (var r : iter(resp)) {
                    if (r.getKey().startsWith("4") || r.getKey().startsWith("5") || r.getKey().equals("default")) err = true;
                    if (r.getKey().equals("429")) has429 = true;
                }
                if (!err) noErr++;
                if (m.equals("get") && returnsArray(op) && !hasPaging(op, pe.getValue())) unpagedList++;
            }
        }
        if (noOpId > 0) add(out, Category.QUALITY, Severity.LOW, rel, 0, "openapi-no-operationid", noOpId + " of " + total + " operations lack operationId", "Add stable operationIds (client generators need them).");
        if (noSummary > 0) add(out, Category.QUALITY, Severity.LOW, rel, 0, "openapi-undocumented-operations", noSummary + " operations have no summary/description", "Document every operation.");
        if (noErr > 0) add(out, Category.QUALITY, Severity.LOW, rel, 0, "openapi-no-error-responses", noErr + " operations document no 4xx/5xx response", "Document error responses.");
        if (unpagedList > 0) add(out, Category.PERFORMANCE, Severity.LOW, rel, 0, "openapi-unpaged-list", unpagedList + " list endpoints have no pagination parameters", "Add page/size or cursor parameters.");
        if (total > 0 && !has429) add(out, Category.OPERATIONS, Severity.INFO, rel, 0, "openapi-no-rate-limit-doc", "No 429 (rate limit) response documented", "Document rate limits and the 429 response.");
    }

    /** Removed paths/operations/2xx responses and newly required parameters or bodies. */
    static List<String> breaking(JsonNode old, JsonNode cur) {
        List<String> out = new ArrayList<>();
        for (var pe : iter(old.path("paths"))) {
            JsonNode curPath = cur.path("paths").path(pe.getKey());
            if (curPath.isMissingNode()) {
                out.add("removed path " + pe.getKey());
                continue;
            }
            for (String m : METHODS) {
                JsonNode o = pe.getValue().path(m);
                if (o.isMissingNode()) continue;
                JsonNode c = curPath.path(m);
                String id = m.toUpperCase() + " " + pe.getKey();
                if (c.isMissingNode()) {
                    out.add("removed operation " + id);
                    continue;
                }
                Map<String, Boolean> oldReq = params(pe.getValue(), o);
                for (var p : params(curPath, c).entrySet()) {
                    if (p.getValue() && !oldReq.getOrDefault(p.getKey(), false)) out.add("new required parameter '" + p.getKey() + "' on " + id);
                }
                if (c.path("requestBody").path("required").asBoolean(false) && !o.path("requestBody").path("required").asBoolean(false)) {
                    out.add("request body became required on " + id);
                }
                for (var r : iter(o.path("responses"))) {
                    if (r.getKey().startsWith("2") && c.path("responses").path(r.getKey()).isMissingNode()) {
                        out.add("removed " + r.getKey() + " response on " + id);
                    }
                }
            }
        }
        return out;
    }

    private static Map<String, Boolean> params(JsonNode pathItem, JsonNode op) {
        Map<String, Boolean> m = new HashMap<>();
        for (JsonNode src : List.of(pathItem.path("parameters"), op.path("parameters"))) {
            for (JsonNode p : src) m.put(p.path("in").asText() + ":" + p.path("name").asText(), p.path("required").asBoolean(false));
        }
        return m;
    }

    private static boolean returnsArray(JsonNode op) {
        for (var r : iter(op.path("responses"))) {
            if (!r.getKey().startsWith("2")) continue;
            JsonNode content = r.getValue().path("content");
            for (var c : iter(content)) if ("array".equals(c.getValue().path("schema").path("type").asText())) return true;
            if ("array".equals(r.getValue().path("schema").path("type").asText())) return true;
        }
        return false;
    }

    private static boolean hasPaging(JsonNode op, JsonNode item) {
        for (JsonNode src : List.of(op.path("parameters"), item.path("parameters"))) {
            for (JsonNode p : src) if (p.path("name").asText().matches("(?i)page|size|limit|offset|cursor|per_?page|pageSize|take|skip")) return true;
        }
        return false;
    }

    private void rateLimiting(Path root, List<Path> javaMain, List<Finding> out) {
        String pom = read(root.resolve("pom.xml")) + read(root.resolve("build.gradle"));
        if (pom.contains("spring-boot-starter-web") && !pom.matches("(?s).*(bucket4j|resilience4j|spring-cloud-gateway|ratelimit|rate-limit).*")) {
            boolean custom = javaMain.stream().anyMatch(p -> read(p).matches("(?s).*(RateLimit|rateLimit|RateLimiter).*"));
            if (!custom) {
                add(out, Category.SECURITY, Severity.LOW, "pom.xml", 0, "no-rate-limiting",
                        "No rate-limiting library or filter found (abuse / brute-force protection)",
                        "Add Bucket4j/Resilience4j, or enforce limits at the gateway and document it.", "CWE-770", "A04");
            }
        }
    }

    // ---- migrations ---------------------------------------------------------------------------------------------

    static void flyway(List<Path> files, Path root, List<Finding> out) {
        Map<String, String> versions = new HashMap<>();
        List<int[]> parsed = new ArrayList<>();
        for (Path f : files) {
            String n = f.getFileName().toString();
            Matcher m = FLYWAY.matcher(n);
            if (n.startsWith("V") && m.matches()) {
                String v = m.group(1);
                String prev = versions.put(v, rel(root, f));
                if (prev != null) {
                    add(out, Category.OPERATIONS, Severity.HIGH, rel(root, f), 1, "flyway-duplicate-version",
                            "Flyway version " + v + " is used twice (also " + prev + "); startup will fail", "Renumber one migration.");
                }
                parsed.add(Arrays.stream(v.split("[._]")).mapToInt(Integer::parseInt).toArray());
            }
            sqlSafety(f, rel(root, f), out);
        }
        List<Integer> majors = parsed.stream().map(a -> a[0]).distinct().sorted().toList();
        for (int i = 1; i < majors.size(); i++) {
            if (majors.get(i) - majors.get(i - 1) > 1) {
                add(out, Category.OPERATIONS, Severity.INFO, "db/migration", 0, "flyway-version-gap",
                        "Migration versions jump from V" + majors.get(i - 1) + " to V" + majors.get(i),
                        "Gaps are legal but often mean a lost or renamed migration.");
                break;
            }
        }
    }

    static void sqlSafety(Path f, String rel, List<Finding> out) {
        String sql;
        try {
            sql = Files.readString(f);
        } catch (IOException e) {
            return;
        }
        String[] lines = sql.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i].replaceAll("--.*$", "").trim();
            String u = l.toUpperCase();
            if (u.isEmpty()) continue;
            if (u.matches(".*\\bDROP\\s+(TABLE|COLUMN|SCHEMA|DATABASE)\\b.*") || u.matches(".*\\bTRUNCATE\\b.*")) {
                add(out, Category.OPERATIONS, Severity.HIGH, rel, i + 1, "migration-destructive", "Destructive migration (drops data or schema)",
                        "Use expand/contract: stop using the column first, drop it in a later release after a backup.");
            } else if (u.matches(".*\\bADD\\s+(COLUMN\\s+)?.*\\bNOT\\s+NULL\\b.*") && !u.contains("DEFAULT")) {
                add(out, Category.OPERATIONS, Severity.MEDIUM, rel, i + 1, "migration-notnull-no-default",
                        "NOT NULL column added without DEFAULT: fails on populated tables or locks them",
                        "Add it nullable, backfill, then add the constraint (or give a DEFAULT).");
            } else if (u.matches(".*\\bALTER\\s+COLUMN\\b.*\\b(TYPE|MODIFY)\\b.*") || u.matches(".*\\bMODIFY\\s+COLUMN\\b.*")) {
                add(out, Category.OPERATIONS, Severity.MEDIUM, rel, i + 1, "migration-column-type-change",
                        "Column type change can rewrite the table and lock it", "Do it in a maintenance window or via a new column + backfill.");
            } else if (u.matches(".*\\bRENAME\\s+(TO|COLUMN)\\b.*")) {
                add(out, Category.OPERATIONS, Severity.MEDIUM, rel, i + 1, "migration-rename",
                        "Rename breaks the previous app version during a rolling deploy", "Add the new name, migrate, then drop the old one later.");
            } else if (u.matches("^(DELETE\\s+FROM\\s+\\w+|UPDATE\\s+\\w+\\s+SET\\b).*;$") && !u.contains("WHERE")) {
                add(out, Category.OPERATIONS, Severity.HIGH, rel, i + 1, "migration-no-where", "DELETE/UPDATE without WHERE touches every row", "Add a WHERE clause.");
            } else if (u.matches("^CREATE\\s+(UNIQUE\\s+)?INDEX\\s+(?!CONCURRENTLY|IF).*") && sql.toLowerCase().contains("postgres")) {
                add(out, Category.OPERATIONS, Severity.LOW, rel, i + 1, "migration-index-not-concurrent",
                        "CREATE INDEX without CONCURRENTLY blocks writes on PostgreSQL", "Use CREATE INDEX CONCURRENTLY (needs a non-transactional migration).");
            }
        }
    }

    static void liquibase(List<Path> files, Path root, List<Finding> out) {
        for (Path f : files) {
            String t = read(f);
            Matcher m = Pattern.compile("(?i)<(dropTable|dropColumn|dropSchema|dropAllForeignKeyConstraints)\\b|\\b(dropTable|dropColumn):").matcher(t);
            if (m.find()) {
                add(out, Category.OPERATIONS, Severity.HIGH, rel(root, f), 1, "migration-destructive",
                        "Liquibase changeset drops tables/columns", "Use expand/contract and keep a rollback plan.");
            }
        }
    }

    // ---- indexes / N+1 ------------------------------------------------------------------------------------------

    static void indexes(Path root, List<Path> java, List<Path> migrations, List<Finding> out) {
        boolean anyEntity = false;
        Set<String> indexed = new HashSet<>();
        Map<String, String> finders = new HashMap<>();
        for (Path p : java) {
            String t = read(p);
            if (t.contains("@Entity")) {
                anyEntity = true;
                Matcher ix = Pattern.compile("columnList\\s*=\\s*\"([^\"]+)\"").matcher(t);
                while (ix.find()) for (String c : ix.group(1).split(",")) indexed.add(norm(c.replaceAll("(?i)\\s+(asc|desc)", "")));
                Matcher id = Pattern.compile("@Id\\b[^;]*?\\b(\\w+)\\s*;", Pattern.DOTALL).matcher(t);
                while (id.find()) indexed.add(norm(id.group(1)));
                Matcher un = Pattern.compile("@Column\\([^)]*unique\\s*=\\s*true[^)]*\\)[^;]*?\\b(\\w+)\\s*;", Pattern.DOTALL).matcher(t);
                while (un.find()) indexed.add(norm(un.group(1)));
                Matcher fk = Pattern.compile("@(?:ManyToOne|OneToOne)[^;]*?\\b\\w+\\s+(\\w+)\\s*;", Pattern.DOTALL).matcher(t);
                boolean fkIdx = t.contains("@Index");
                if (fk.find() && !fkIdx) {
                    String field = fk.group(1);
                    out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, rel(root, p), 1, "fk-without-index",
                            "Foreign key '" + field + "' has no explicit @Index (PostgreSQL/Oracle do not index FKs automatically)",
                            null, null, "Add @Table(indexes = @Index(columnList = \"" + field + "_id\")) or a CREATE INDEX migration."));
                }
            }
            Matcher fm = FINDER.matcher(t);
            if (t.contains("Repository") && !t.contains("@Entity")) {
                while (fm.find()) finders.putIfAbsent(fm.group(1), rel(root, p));
            }
        }
        if (!anyEntity) return;
        for (Path m : migrations) {
            String t = read(m);
            Matcher ix = Pattern.compile("(?i)\\(([^)]+)\\)").matcher(t);
            while (ix.find()) for (String c : ix.group(1).split(",")) indexed.add(norm(c.trim().split("\\s+")[0]));
        }
        int n = 0;
        for (var e : finders.entrySet()) {
            for (String prop : e.getKey().split("And|Or")) {
                String base = prop.replaceAll("(OrderBy.*|Containing|Like|In|IsNull|IsNotNull|Between|GreaterThan|LessThan|Not|True|False|StartingWith|EndingWith|IgnoreCase|Desc|Asc)$", "");
                if (base.isBlank() || base.equals("Id") || indexed.contains(norm(base)) || indexed.contains(norm(base + "Id"))) continue;
                if (n++ >= 15) return;
                out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, e.getValue(), 0, "finder-without-index",
                        "Query method filters on '" + base + "' but no index/unique constraint on it was found",
                        null, null, "Add an index on " + base + " if this table is large (verify with EXPLAIN)."));
            }
        }
    }

    static void nPlusOne(Path root, Path p, List<Finding> out) {
        List<String> lines;
        try {
            lines = Files.readAllLines(p);
        } catch (IOException | RuntimeException e) {
            return;
        }
        int depth = 0;
        List<Integer> loopDepths = new ArrayList<>();
        boolean flaggedRead = false, flaggedSave = false;
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            String code = l.replaceAll("//.*$", "");
            boolean inLoop = !loopDepths.isEmpty() || code.matches(".*\\.(forEach|map|flatMap)\\s*\\(.*->.*");
            if (inLoop) {
                if (REPO_READ.matcher(code).find() && !flaggedRead) {
                    out.add(new Finding(NAME, Category.PERFORMANCE, Severity.MEDIUM, rel(root, p), i + 1, "n-plus-one-query",
                            "Repository read inside a loop/stream: likely N+1 queries", null, null,
                            "Fetch in bulk (findAllById / IN query / JOIN FETCH) before the loop."));
                    flaggedRead = true;
                } else if (REPO_SAVE.matcher(code).find() && !flaggedSave) {
                    out.add(new Finding(NAME, Category.PERFORMANCE, Severity.LOW, rel(root, p), i + 1, "save-in-loop",
                            "save() inside a loop issues one statement per item", null, null, "Collect and call saveAll(), enable JDBC batching."));
                    flaggedSave = true;
                }
            }
            if (LOOP.matcher(code).find()) loopDepths.add(depth);
            for (char c : code.toCharArray()) {
                if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    while (!loopDepths.isEmpty() && depth <= loopDepths.get(loopDepths.size() - 1)) loopDepths.remove(loopDepths.size() - 1);
                }
            }
        }
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    private static JsonNode parse(Path f) {
        return parse(f, f.getFileName().toString().endsWith(".json"));
    }

    private static JsonNode parse(Path f, boolean json) {
        try {
            return (json ? JSON : YAML).readTree(f.toFile());
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static Iterable<Map.Entry<String, JsonNode>> iter(JsonNode n) {
        return n::fields;
    }

    private static String norm(String s) {
        return s.toLowerCase().replace("_", "").trim();
    }

    private static String rel(Path root, Path p) {
        return root.relativize(p).toString().replace('\\', '/');
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
