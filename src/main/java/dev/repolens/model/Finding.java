package dev.repolens.model;

public record Finding(
        String tool,
        Category category,
        Severity severity,
        String file,
        int line,
        String rule,
        String message,
        String cwe,
        String owasp,
        String fix) {

    public Finding withOwasp(String owasp) {
        return new Finding(tool, category, severity, file, line, rule, message, cwe, owasp, fix);
    }

    public Finding withFile(String file) {
        return new Finding(tool, category, severity, file, line, rule, message, cwe, owasp, fix);
    }

    public Finding withSeverity(Severity severity) {
        return new Finding(tool, category, severity, file, line, rule, message, cwe, owasp, fix);
    }

    /** Stable identity across runs (ignores line number so edits above don't make a finding "new"). */
    public String fingerprint() {
        return fingerprint(tool, rule, file, message);
    }

    public static String fingerprint(String tool, String rule, String file, String message) {
        return tool + "|" + rule + "|" + file + "|" + message;
    }
}
