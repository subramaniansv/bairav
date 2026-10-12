package dev.repolens.owasp;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;

import java.util.HashMap;
import java.util.Map;

/** Tags findings with an OWASP Top 10 (2021) category: explicit tag first, then CWE, then category. */
public final class OwaspMapper {

    public static final Map<String, String> NAMES = Map.ofEntries(
            Map.entry("A01", "A01 Broken Access Control"),
            Map.entry("A02", "A02 Cryptographic Failures"),
            Map.entry("A03", "A03 Injection"),
            Map.entry("A04", "A04 Insecure Design"),
            Map.entry("A05", "A05 Security Misconfiguration"),
            Map.entry("A06", "A06 Vulnerable and Outdated Components"),
            Map.entry("A07", "A07 Identification and Authentication Failures"),
            Map.entry("A08", "A08 Software and Data Integrity Failures"),
            Map.entry("A09", "A09 Security Logging and Monitoring Failures"),
            Map.entry("A10", "A10 Server-Side Request Forgery"));

    private static final Map<Integer, String> CWE_TO_OWASP = new HashMap<>();

    static {
        put("A01", 22, 23, 35, 200, 201, 219, 264, 275, 284, 285, 352, 359, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275);
        put("A02", 261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916);
        put("A03", 20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917);
        put("A04", 73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173);
        put("A05", 2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174);
        put("A06", 937, 1035, 1104);
        put("A07", 255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216);
        put("A08", 345, 353, 426, 494, 502, 565, 784, 829, 830, 915);
        put("A09", 117, 223, 532, 778);
        put("A10", 918);
    }

    private OwaspMapper() {}

    private static void put(String owasp, int... cwes) {
        for (int c : cwes) CWE_TO_OWASP.putIfAbsent(c, owasp);
    }

    public static Finding tag(Finding f) {
        if (f.owasp() != null && NAMES.containsKey(f.owasp())) return f;
        if (f.cwe() != null) {
            try {
                String o = CWE_TO_OWASP.get(Integer.parseInt(f.cwe().replaceAll("\\D", "")));
                if (o != null) return f.withOwasp(o);
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        if (f.category() == Category.DEPENDENCY) return f.withOwasp("A06");
        if (f.category() == Category.SECRETS) return f.withOwasp("A07");
        return f.withOwasp(f.category() == Category.SECURITY ? "UNMAPPED" : null);
    }
}
