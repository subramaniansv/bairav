package dev.repolens.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import dev.repolens.model.Finding;
import dev.repolens.model.Severity;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * .bairav.yml: suppressions and overrides (all keys optional).
 * ignorePaths (globs relative to scan root), ignoreRules, severityOverrides (rule: LEVEL), disableRunners.
 */
public class Config {

    public static final List<String> DEFAULT_IGNORE_PATHS = List.of(
            "**/node_modules/**", "**/dist/**", "**/build/**", "**/target/**", "**/playwright-report/**",
            "**/test-results/**", "**/coverage/**", "**/.git/**");

    /** Rules that are pure noise in typical Spring apps (constructor-injected mutable beans). */
    public static final List<String> DEFAULT_IGNORE_RULES = List.of("spotbugs:EI_EXPOSE_REP", "spotbugs:EI_EXPOSE_REP2");

    public List<String> ignorePaths = new ArrayList<>();
    public List<String> ignoreRules = new ArrayList<>();
    public Map<String, String> severityOverrides = new HashMap<>();
    public List<String> disableRunners = new ArrayList<>();
    /** project name -> runners to disable only for that project (e.g. admin: [seo-geo-aeo]) */
    public Map<String, List<String>> disableRunnersFor = new HashMap<>();

    // Quality gates and thresholds (typically set once in a central --policy file)
    public Integer minCoverage;
    public Integer maxComplexity;
    public Integer minScore;
    public String failOn;
    public List<String> licenseDeny = new ArrayList<>();
    public List<String> licenseWarn = new ArrayList<>();
    public Boolean allowUnknownLicenses;

    public int minCoverage() { return minCoverage == null ? 60 : minCoverage; }

    public int maxComplexity() { return maxComplexity == null ? 15 : maxComplexity; }

    /**
     * Central policy + per-repo config: lists are unioned; scalar thresholds from the policy are enforced
     * (a repo cannot weaken them), otherwise the repo value is used.
     */
    public static Config merge(Config policy, Config repo) {
        Config c = new Config();
        c.ignorePaths = union(policy.ignorePaths, repo.ignorePaths);
        c.ignoreRules = union(policy.ignoreRules, repo.ignoreRules);
        c.disableRunners = union(policy.disableRunners, repo.disableRunners);
        c.licenseDeny = union(policy.licenseDeny, repo.licenseDeny);
        c.licenseWarn = union(policy.licenseWarn, repo.licenseWarn);
        c.severityOverrides = new HashMap<>(repo.severityOverrides);
        c.severityOverrides.putAll(policy.severityOverrides);
        c.disableRunnersFor = new HashMap<>(repo.disableRunnersFor);
        policy.disableRunnersFor.forEach((k, v) -> c.disableRunnersFor.merge(k, v, Config::union));
        c.minCoverage = policy.minCoverage != null ? policy.minCoverage : repo.minCoverage;
        c.maxComplexity = policy.maxComplexity != null ? policy.maxComplexity : repo.maxComplexity;
        c.minScore = policy.minScore != null ? policy.minScore : repo.minScore;
        c.failOn = policy.failOn != null ? policy.failOn : repo.failOn;
        c.allowUnknownLicenses = policy.allowUnknownLicenses != null ? policy.allowUnknownLicenses : repo.allowUnknownLicenses;
        return c;
    }

    private static List<String> union(List<String> a, List<String> b) {
        return new ArrayList<>(new java.util.LinkedHashSet<>(java.util.stream.Stream.concat(a.stream(), b.stream()).toList()));
    }

    private List<PathMatcher> matchers;

    public static Config load(Path file) throws IOException {
        if (file == null || !Files.isRegularFile(file)) return new Config();
        ObjectMapper m = new ObjectMapper(new YAMLFactory())
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        Config c = m.readValue(file.toFile(), Config.class);
        return c == null ? new Config() : c;
    }

    /** Returns null when the finding is suppressed. */
    public Finding apply(Finding f) {
        if (ignoreRules.contains(f.rule()) || DEFAULT_IGNORE_RULES.contains(f.rule())) return null;
        if (matchers == null) {
            matchers = new ArrayList<>();
            List<String> all = new ArrayList<>(DEFAULT_IGNORE_PATHS);
            all.addAll(ignorePaths);
            for (String g : all) matchers.add(FileSystems.getDefault().getPathMatcher("glob:" + g));
        }
        Path p = Path.of(f.file());
        for (PathMatcher pm : matchers) {
            // second check: Java's "**/x/**" needs a leading directory, so also test with a "/" prefix
            if (pm.matches(p) || pm.matches(Path.of("/").resolve(p))) return null;
        }
        String o = severityOverrides.get(f.rule());
        return o == null ? f : f.withSeverity(Severity.parse(o));
    }
}
