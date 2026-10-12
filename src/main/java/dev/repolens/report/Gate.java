package dev.repolens.report;

import dev.repolens.model.Finding;
import dev.repolens.model.ProjectResult;
import dev.repolens.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Pass/fail decision for CI: severity threshold, minimum score, optionally only for findings new since the baseline. */
public record Gate(boolean passed, List<String> violations) {

    public static Gate evaluate(List<ProjectResult> projects, Severity failOn, Integer minScore, Set<String> onlyFingerprints) {
        List<String> v = new ArrayList<>();
        for (ProjectResult p : projects) {
            if (failOn != null) {
                long n = p.findings().stream()
                        .filter(f -> f.severity().weight >= failOn.weight)
                        .filter(f -> onlyFingerprints == null || onlyFingerprints.contains(f.fingerprint()))
                        .count();
                if (n > 0) {
                    v.add(p.name() + ": " + n + (onlyFingerprints == null ? "" : " new") + " finding(s) at or above " + failOn);
                }
            }
            if (minScore != null && p.scores().overall() < minScore) {
                v.add(p.name() + ": score " + p.scores().overall() + " is below the required " + minScore);
            }
        }
        return new Gate(v.isEmpty(), v);
    }

    public static Set<String> fingerprints(List<Finding> findings) {
        return findings.stream().map(Finding::fingerprint).collect(java.util.stream.Collectors.toSet());
    }
}
