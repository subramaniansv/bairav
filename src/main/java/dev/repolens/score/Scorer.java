package dev.repolens.score;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Scorer {

    public record Scores(Map<String, Integer> byArea, int overall, String grade) {}

    private record Area(Set<Category> categories, double weight, boolean frontendOnly) {}

    private static final Map<String, Area> AREAS = new LinkedHashMap<>();

    static {
        AREAS.put("Security", new Area(Set.of(Category.SECURITY, Category.DEPENDENCY, Category.SECRETS), 0.40, false));
        AREAS.put("Performance", new Area(Set.of(Category.PERFORMANCE), 0.15, false));
        AREAS.put("Build health", new Area(Set.of(Category.BUILD_HEALTH), 0.10, false));
        AREAS.put("Quality", new Area(Set.of(Category.QUALITY, Category.TEAM), 0.10, false));
        AREAS.put("Operations", new Area(Set.of(Category.OPERATIONS), 0.05, false));
        AREAS.put("Compliance", new Area(Set.of(Category.LICENSE, Category.SUPPLY_CHAIN, Category.PRIVACY), 0.05, false));
        AREAS.put("SEO", new Area(Set.of(Category.SEO), 0.10, true));
        AREAS.put("GEO/AEO", new Area(Set.of(Category.GEO_AEO), 0.05, true));
        AREAS.put("Accessibility", new Area(Set.of(Category.ACCESSIBILITY), 0.10, true));
    }

    private Scorer() {}

    /** score = 100 * 100 / (100 + penalty): smooth, never negative, 50 at penalty 100. */
    static int score(double penalty) {
        return (int) Math.round(10000.0 / (100.0 + penalty));
    }

    /** @param webFrontend include SEO / GEO-AEO / accessibility areas (only for indexable frontends) */
    public static Scores compute(List<Finding> findings, boolean webFrontend) {
        Map<String, Integer> byArea = new LinkedHashMap<>();
        double sum = 0;
        double weights = 0;
        for (var e : AREAS.entrySet()) {
            Area a = e.getValue();
            if (a.frontendOnly() && !webFrontend) continue;
            double penalty = findings.stream()
                    .filter(f -> a.categories().contains(f.category()))
                    .mapToDouble(f -> f.severity().weight)
                    .sum();
            int s = score(penalty);
            byArea.put(e.getKey(), s);
            sum += s * a.weight();
            weights += a.weight();
        }
        int o = (int) Math.round(sum / weights);
        return new Scores(byArea, o, grade(o));
    }

    static String grade(int s) {
        if (s >= 90) return "A";
        if (s >= 75) return "B";
        if (s >= 60) return "C";
        if (s >= 40) return "D";
        return "F";
    }
}
