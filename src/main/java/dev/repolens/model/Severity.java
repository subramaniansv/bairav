package dev.repolens.model;

public enum Severity {
    INFO(0), LOW(1), MEDIUM(3), HIGH(7), CRITICAL(10);

    public final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public static Severity parse(String s) {
        if (s == null) return MEDIUM;
        return switch (s.trim().toLowerCase()) {
            case "critical" -> CRITICAL;
            case "high", "error" -> HIGH;
            case "medium", "moderate", "warning" -> MEDIUM;
            case "low" -> LOW;
            case "info", "note", "none" -> INFO;
            default -> MEDIUM;
        };
    }
}
