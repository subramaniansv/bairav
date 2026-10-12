package dev.repolens.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Outcome of one tool: findings plus a status so skipped/failed tools stay visible in the report. */
public record ToolResult(String tool, Status status, String detail, List<Finding> findings,
                         Map<String, String> metrics, long millis) {

    public enum Status { OK, SKIPPED, FAILED }

    public static ToolResult skipped(String tool, String why) {
        return new ToolResult(tool, Status.SKIPPED, why, new ArrayList<>(), new LinkedHashMap<>(), 0);
    }

    public static ToolResult failed(String tool, String why, long millis) {
        return new ToolResult(tool, Status.FAILED, why, new ArrayList<>(), new LinkedHashMap<>(), millis);
    }

    public static ToolResult ok(String tool, List<Finding> f, String detail, long millis) {
        return new ToolResult(tool, Status.OK, detail, f, new LinkedHashMap<>(), millis);
    }

    public ToolResult withMetrics(Map<String, String> m) {
        return new ToolResult(tool, status, detail, findings, m, millis);
    }
}
