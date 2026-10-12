package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Supply-chain hygiene: unpinned GitHub Actions, over-broad workflow permissions, script injection,
 * curl-pipe-shell, mutable Docker tags, insecure/floating dependency sources and missing signing/provenance.
 */
public class SupplyChainRunner implements ToolRunner {

    public static final String NAME = "supply-chain";

    private static final Pattern USES = Pattern.compile("^\\s*-?\\s*uses:\\s*([^\\s#]+)");
    private static final Pattern SHA = Pattern.compile("[0-9a-f]{40}");
    private static final Pattern CURL_SH = Pattern.compile("(curl|wget)[^|\\n]*\\|\\s*(sudo\\s+)?(ba|z)?sh\\b");
    private static final Pattern INJECTION = Pattern.compile(
            "\\$\\{\\{\\s*github\\.(event\\.(issue|pull_request|comment|review|head_commit|commits)[\\w.\\[\\]*]*"
                    + "\\.(title|body|message|name|label|ref)|head_ref)\\s*}}");
    private static final Pattern ENV_ASSIGN = Pattern.compile("^\\s*[A-Za-z_][\\w]*:\\s*\\$\\{\\{.*}}\\s*$");
    private static final Pattern PUBLISH = Pattern.compile("docker push|mvn[^\\n]* deploy|npm publish|build-push-action|gh release");
    private static final Pattern PROVENANCE = Pattern.compile("(?i)cosign|slsa-framework|attest|sigstore|provenance");
    private static final Pattern DOCKER_FROM = Pattern.compile("(?i)^\\s*FROM\\s+(?:--platform=\\S+\\s+)?(\\S+)(?:\\s+AS\\s+(\\S+))?");

    @Override public String name() { return NAME; }

    @Override public boolean applicable(RepoInfo repo) { return true; }

    @Override
    public ToolResult run(Context ctx) throws IOException {
        long start = System.currentTimeMillis();
        List<Finding> out = new ArrayList<>();
        Path root = ctx.root();
        boolean[] flags = new boolean[2]; // [0] has workflows, [1] publishes
        boolean[] provenance = new boolean[1];
        String[] firstWorkflow = new String[1];

        RepoWalker.walk(root, (p, a) -> {
            if (a.size() > 500_000) return;
            String rel = root.relativize(p).toString().replace('\\', '/');
            String n = p.getFileName().toString();
            try {
                if (rel.contains(".github/workflows/") && (n.endsWith(".yml") || n.endsWith(".yaml"))) {
                    List<String> lines = Files.readAllLines(p);
                    flags[0] = true;
                    if (firstWorkflow[0] == null) firstWorkflow[0] = rel;
                    String all = String.join("\n", lines);
                    if (PUBLISH.matcher(all).find()) flags[1] = true;
                    if (PROVENANCE.matcher(all).find()) provenance[0] = true;
                    workflow(rel, lines, out);
                } else if (n.equals("Dockerfile") || n.startsWith("Dockerfile.") || n.endsWith(".Dockerfile")) {
                    dockerfile(rel, Files.readAllLines(p), out);
                } else if (n.equals("pom.xml")) {
                    maven(rel, Files.readAllLines(p), out);
                } else if (n.equals("package.json")) {
                    packageJson(rel, p, out);
                } else if (n.equals(".npmrc")) {
                    List<String> lines = Files.readAllLines(p);
                    for (int i = 0; i < lines.size(); i++) {
                        if (lines.get(i).replace(" ", "").equalsIgnoreCase("strict-ssl=false")) {
                            add(out, Severity.HIGH, rel, i + 1, "npm-strict-ssl-off", "npm TLS verification disabled",
                                    "CWE-295", "A08", "Remove strict-ssl=false; fix the certificate chain instead.");
                        }
                    }
                }
            } catch (IOException | RuntimeException e) {
                // unreadable / binary file: ignore
            }
        });

        if (flags[0] && flags[1] && !provenance[0]) {
            add(out, Severity.LOW, firstWorkflow[0], 1, "no-provenance",
                    "Workflows publish artifacts but nothing signs them or attests provenance", null, "A08",
                    "Add cosign signing and/or actions/attest-build-provenance (SLSA) to the publish job.");
        }
        return ToolResult.ok(NAME, out, out.size() + " finding(s)", System.currentTimeMillis() - start);
    }

    static void workflow(String rel, List<String> lines, List<Finding> out) {
        boolean topPermissions = false;
        boolean anyPermissions = false;
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            if (l.startsWith("permissions:")) topPermissions = true;
            if (l.stripLeading().startsWith("permissions:")) anyPermissions = true;
            Matcher m = USES.matcher(l);
            if (m.find()) {
                String ref = m.group(1);
                if (!ref.startsWith("./") && !ref.startsWith("docker://") && ref.contains("@")) {
                    String version = ref.substring(ref.lastIndexOf('@') + 1);
                    if (!SHA.matcher(version).matches()) {
                        boolean official = ref.startsWith("actions/") || ref.startsWith("github/");
                        add(out, official ? Severity.LOW : Severity.MEDIUM, rel, i + 1, "action-not-pinned",
                                "Action " + ref.substring(0, ref.lastIndexOf('@')) + " is pinned to a mutable ref, not a commit SHA",
                                "CWE-829", "A08", "Pin to the full commit SHA (keep the tag in a comment); let Dependabot/Renovate bump it.");
                    }
                }
            }
            if (l.contains("pull_request_target")) {
                add(out, Severity.MEDIUM, rel, i + 1, "pull-request-target",
                        "pull_request_target runs with secrets; never check out untrusted PR code with it",
                        "CWE-829", "A08", "Use pull_request, or do not execute code from the PR head in this workflow.");
            }
            if (!l.stripLeading().startsWith("#") && INJECTION.matcher(l).find() && !ENV_ASSIGN.matcher(l).matches()
                    && !l.stripLeading().startsWith("if:")) {
                add(out, Severity.HIGH, rel, i + 1, "workflow-script-injection",
                        "Untrusted GitHub event data interpolated directly into a script",
                        "CWE-94", "A03", "Pass it through an env: variable and reference \"$VAR\" in the script.");
            }
            if (CURL_SH.matcher(l).find()) {
                add(out, Severity.MEDIUM, rel, i + 1, "curl-pipe-shell", "Downloads and executes a script without verification",
                        "CWE-494", "A08", "Download, verify a checksum/signature, then run.");
            }
        }
        if (!topPermissions && !anyPermissions) {
            add(out, Severity.MEDIUM, rel, 1, "workflow-default-permissions",
                    "Workflow does not restrict GITHUB_TOKEN permissions", "CWE-250", "A05",
                    "Add a top-level 'permissions: contents: read' and grant more per job only where needed.");
        }
    }

    static void dockerfile(String rel, List<String> lines, List<Finding> out) {
        List<String> stages = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            Matcher m = DOCKER_FROM.matcher(l);
            if (m.find()) {
                String img = m.group(1);
                if (m.group(2) != null) stages.add(m.group(2).toLowerCase());
                if (!img.equalsIgnoreCase("scratch") && !stages.contains(img.toLowerCase()) && !img.contains("@sha256:")
                        && !img.startsWith("$")) {
                    String tag = img.contains(":") ? img.substring(img.lastIndexOf(':') + 1) : "";
                    if (tag.isEmpty() || tag.equals("latest")) {
                        add(out, Severity.MEDIUM, rel, i + 1, "docker-mutable-tag",
                                "Base image " + img + " uses a mutable tag (latest/none)", "CWE-1357", "A08",
                                "Pin to a specific version, ideally with an @sha256 digest.");
                    }
                }
            }
            if (CURL_SH.matcher(l).find()) {
                add(out, Severity.MEDIUM, rel, i + 1, "curl-pipe-shell", "Downloads and executes a script without verification",
                        "CWE-494", "A08", "Download, verify a checksum, then run.");
            }
        }
    }

    static void maven(String rel, List<String> lines, List<Finding> out) {
        Pattern httpRepo = Pattern.compile("<url>\\s*http://(?!localhost|127\\.0\\.0\\.1)[^<]+</url>");
        Pattern floating = Pattern.compile("<version>\\s*(LATEST|RELEASE)\\s*</version>");
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            if (httpRepo.matcher(l).find()) {
                add(out, Severity.HIGH, rel, i + 1, "maven-insecure-repo", "Maven repository fetched over plain HTTP",
                        "CWE-494", "A08", "Use https:// for every repository.");
            }
            if (floating.matcher(l).find()) {
                add(out, Severity.MEDIUM, rel, i + 1, "maven-floating-version", "Dependency uses LATEST/RELEASE (non-reproducible)",
                        "CWE-1104", "A06", "Pin an explicit version.");
            }
        }
    }

    static void packageJson(String rel, Path p, List<Finding> out) throws IOException {
        JsonNode root = new ObjectMapper().readTree(p.toFile());
        for (String section : List.of("dependencies", "devDependencies", "optionalDependencies")) {
            JsonNode deps = root.path(section);
            for (Map.Entry<String, JsonNode> e : (Iterable<Map.Entry<String, JsonNode>>) deps::fields) {
                String v = e.getValue().asText("");
                String lv = v.toLowerCase();
                if (v.isBlank() || v.equals("*") || lv.equals("latest") || lv.startsWith("git") || lv.startsWith("http")
                        || lv.startsWith("github:")) {
                    add(out, Severity.MEDIUM, rel, 1, "npm-unpinned-source",
                            "Dependency " + e.getKey() + " uses '" + (v.isBlank() ? "*" : v) + "' (floating or non-registry source)",
                            "CWE-1104", "A06", "Use a semver range from the registry and commit the lockfile.");
                }
            }
        }
    }

    private static void add(List<Finding> out, Severity s, String file, int line, String rule, String msg,
                            String cwe, String owasp, String fix) {
        out.add(new Finding(NAME, Category.SUPPLY_CHAIN, s, file, line, rule, msg, cwe, owasp, fix));
    }
}
