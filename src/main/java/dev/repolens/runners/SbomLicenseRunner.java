package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.config.Config;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.Severity;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** CycloneDX SBOM (via Trivy) plus license-policy findings computed from the SBOM's component licenses. */
public class SbomLicenseRunner extends ExternalToolRunner {

    public static final String NAME = "sbom-license";

    private static final Set<String> STRONG_COPYLEFT = Set.of("AGPL", "SSPL", "GPL-3", "GPL-2", "GPL-1", "OSL", "EUPL", "CPAL", "RPL");
    private static final Set<String> WEAK_COPYLEFT = Set.of("LGPL", "MPL", "EPL", "CDDL", "CPL", "MS-RL");
    private static final int MAX_FINDINGS = 200;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String name() { return NAME; }
    @Override protected String binary() { return "trivy"; }
    @Override protected String installHint() { return "brew install trivy"; }
    @Override protected String outputFileName() { return "sbom.cdx.json"; }

    @Override
    protected Map<String, String> env() {
        try {
            return Map.of("DOCKER_CONFIG", Files.createTempDirectory("bairav-docker").toString());
        } catch (java.io.IOException e) {
            return Map.of();
        }
    }

    @Override
    protected List<String> command(Context ctx, Path bin, Path out) {
        return List.of(bin.toString(), "fs", "--quiet", "--format", "cyclonedx", "--output", out.toString(),
                ctx.root().toString());
    }

    @Override
    protected List<Finding> parse(Context ctx, Path out) throws Exception {
        return evaluate(MAPPER.readTree(out.toFile()), ctx.config(), manifestFor(ctx));
    }

    @Override
    protected Map<String, String> metrics(Context ctx, Path out) {
        Map<String, String> m = new LinkedHashMap<>();
        try {
            JsonNode comps = MAPPER.readTree(out.toFile()).path("components");
            Map<String, Integer> byLicense = new TreeMap<>();
            int unknown = 0;
            for (JsonNode c : comps) {
                if (!"library".equals(c.path("type").asText())) continue;
                List<String> ls = licensesOf(c);
                if (ls.isEmpty()) unknown++;
                ls.forEach(l -> byLicense.merge(l, 1, Integer::sum));
            }
            m.put("SBOM components", String.valueOf(comps.size()));
            m.put("Components without license", String.valueOf(unknown));
            m.put("Licenses", byLicense.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(8)
                    .map(e -> e.getKey() + " x" + e.getValue()).collect(java.util.stream.Collectors.joining(", ")));
            m.put("SBOM file", out.toString());
        } catch (Exception ignored) {
            // metrics are best-effort
        }
        return m;
    }

    private static String manifestFor(Context ctx) {
        for (String f : List.of("pom.xml", "package-lock.json", "build.gradle")) {
            if (Files.exists(ctx.root().resolve(f))) return f;
        }
        return ".";
    }

    /** Pure function over a CycloneDX document so it can be unit-tested without Trivy. */
    public static List<Finding> evaluate(JsonNode bom, Config cfg, String manifest) {
        List<Finding> out = new ArrayList<>();
        boolean allowUnknown = cfg.allowUnknownLicenses != null && cfg.allowUnknownLicenses;
        for (JsonNode c : bom.path("components")) {
            String pkg = (c.path("group").asText("").isEmpty() ? "" : c.path("group").asText() + "/")
                    + c.path("name").asText("?") + "@" + c.path("version").asText("?");
            List<String> licenses = licensesOf(c);
            if (licenses.isEmpty()) {
                if (!allowUnknown && "library".equals(c.path("type").asText())) {
                    out.add(new Finding(NAME, Category.LICENSE, Severity.LOW, manifest, 0, "license/unknown",
                            "Dependency without a declared license: " + pkg, "CWE-1357", null,
                            "Check the package's repository for its license; replace it or record an approved exception."));
                }
                continue;
            }
            for (String l : licenses) {
                Severity s = classify(l, cfg);
                if (s == null) continue;
                String denied = s == Severity.HIGH ? "license/denied" : "license/restricted";
                out.add(new Finding(NAME, Category.LICENSE, s, manifest, 0, denied,
                        (s == Severity.HIGH ? "Disallowed license " : "Copyleft license ") + l + " in dependency " + pkg,
                        null, null, s == Severity.HIGH
                                ? "Remove or replace this dependency; the license conflicts with company policy."
                                : "Review the license obligations with legal before shipping this dependency."));
            }
        }
        return out.size() > MAX_FINDINGS ? out.subList(0, MAX_FINDINGS) : out;
    }

    /** null = acceptable. Handles SPDX expressions: "A OR B" is fine if any alternative is; linking exceptions neutralise GPL. */
    static Severity classify(String license, Config cfg) {
        String[] alternatives = license.replace("(", "").replace(")", "").split("(?i)\\s+OR\\s+");
        Severity worst = null;
        for (String alt : alternatives) {
            Severity s = classifySingle(alt.trim(), cfg);
            if (s == null) return null;
            if (worst == null || s.weight > worst.weight) worst = s;
        }
        return worst;
    }

    private static Severity classifySingle(String license, Config cfg) {
        String u = license.toUpperCase(Locale.ROOT);
        boolean explicitDeny = cfg.licenseDeny.stream().anyMatch(d -> u.startsWith(d.toUpperCase(Locale.ROOT)));
        if (u.contains(" WITH ") && u.matches(".*(CLASSPATH|FOSS-EXCEPTION|LINKING-EXCEPTION).*")) return null;
        if (explicitDeny) return Severity.HIGH;
        if (cfg.licenseWarn.stream().anyMatch(d -> u.startsWith(d.toUpperCase(Locale.ROOT)))) return Severity.MEDIUM;
        if (!cfg.licenseDeny.isEmpty() || !cfg.licenseWarn.isEmpty()) return null; // explicit policy replaces defaults
        if (u.startsWith("AGPL") || u.startsWith("SSPL")) return Severity.HIGH;
        if (STRONG_COPYLEFT.stream().anyMatch(u::startsWith)) return Severity.MEDIUM;
        if (WEAK_COPYLEFT.stream().anyMatch(u::startsWith)) return Severity.LOW;
        return null;
    }

    private static List<String> licensesOf(JsonNode component) {
        List<String> r = new ArrayList<>();
        for (JsonNode l : component.path("licenses")) {
            String id = l.path("license").path("id").asText(l.path("license").path("name").asText(l.path("expression").asText("")));
            if (!id.isBlank()) r.add(id);
        }
        return r;
    }
}
