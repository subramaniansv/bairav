package dev.repolens.owasp;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Indicative mapping from findings to SOC 2, ISO 27001:2022, PCI-DSS 4.0 and GDPR controls.
 * It helps triage audit evidence; it is not an audit and does not prove compliance.
 */
public final class ComplianceMapper {

    public static final List<String> FRAMEWORKS = List.of("SOC2", "ISO27001", "PCI-DSS", "GDPR");

    private static final Map<String, List<String>> BY_OWASP = new LinkedHashMap<>();
    private static final Map<Category, List<String>> BY_CATEGORY = new LinkedHashMap<>();

    static {
        BY_OWASP.put("A01", List.of("SOC2:CC6.1", "SOC2:CC6.3", "ISO27001:A.5.15", "ISO27001:A.8.3", "PCI-DSS:7.2", "GDPR:Art.32"));
        BY_OWASP.put("A02", List.of("SOC2:CC6.1", "SOC2:CC6.7", "ISO27001:A.8.24", "PCI-DSS:3.5", "PCI-DSS:4.2.1", "GDPR:Art.32"));
        BY_OWASP.put("A03", List.of("SOC2:CC7.1", "ISO27001:A.8.28", "PCI-DSS:6.2.4", "GDPR:Art.32"));
        BY_OWASP.put("A04", List.of("SOC2:CC8.1", "ISO27001:A.8.25", "PCI-DSS:6.2", "GDPR:Art.25"));
        BY_OWASP.put("A05", List.of("SOC2:CC6.6", "ISO27001:A.8.9", "PCI-DSS:2.2", "GDPR:Art.32"));
        BY_OWASP.put("A06", List.of("SOC2:CC7.1", "ISO27001:A.8.8", "PCI-DSS:6.3.3", "GDPR:Art.32"));
        BY_OWASP.put("A07", List.of("SOC2:CC6.1", "ISO27001:A.8.5", "PCI-DSS:8.3", "GDPR:Art.32"));
        BY_OWASP.put("A08", List.of("SOC2:CC8.1", "ISO27001:A.8.32", "PCI-DSS:6.3.2"));
        BY_OWASP.put("A09", List.of("SOC2:CC7.2", "ISO27001:A.8.15", "PCI-DSS:10.2", "GDPR:Art.33"));
        BY_OWASP.put("A10", List.of("SOC2:CC6.6", "ISO27001:A.8.20", "PCI-DSS:1.4"));

        BY_CATEGORY.put(Category.SECRETS, List.of("SOC2:CC6.1", "ISO27001:A.8.24", "PCI-DSS:8.6.2", "GDPR:Art.32"));
        BY_CATEGORY.put(Category.LICENSE, List.of("ISO27001:A.5.32"));
        BY_CATEGORY.put(Category.SUPPLY_CHAIN, List.of("SOC2:CC9.2", "ISO27001:A.5.21", "PCI-DSS:6.3.2"));
        BY_CATEGORY.put(Category.PRIVACY, List.of("GDPR:Art.5", "GDPR:Art.25", "GDPR:Art.32", "ISO27001:A.5.34"));
        BY_CATEGORY.put(Category.OPERATIONS, List.of("SOC2:CC7.2", "ISO27001:A.8.16"));
    }

    private ComplianceMapper() {}

    /** Control tags such as "SOC2:CC6.1" for one finding (empty for non-compliance findings like SEO). */
    public static List<String> controls(Finding f) {
        List<String> out = new ArrayList<>();
        if (f.owasp() != null && BY_OWASP.containsKey(f.owasp())) out.addAll(BY_OWASP.get(f.owasp()));
        List<String> byCat = BY_CATEGORY.get(f.category());
        if (byCat != null) byCat.stream().filter(c -> !out.contains(c)).forEach(out::add);
        return out;
    }

    /** framework -> control -> finding count. */
    public static Map<String, Map<String, Integer>> summarize(List<Finding> findings) {
        Map<String, Map<String, Integer>> out = new LinkedHashMap<>();
        FRAMEWORKS.forEach(fw -> out.put(fw, new TreeMap<>()));
        for (Finding f : findings) {
            if (f.severity().weight == 0) continue;
            for (String c : controls(f)) {
                int i = c.indexOf(':');
                out.get(c.substring(0, i)).merge(c.substring(i + 1), 1, Integer::sum);
            }
        }
        return out;
    }
}
