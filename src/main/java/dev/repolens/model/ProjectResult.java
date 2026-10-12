package dev.repolens.model;

import dev.repolens.score.Scorer.Scores;

import java.util.List;
import java.util.Set;

/** Everything produced for one project; finding paths are relative to the scan root. */
public record ProjectResult(String name, String path, Set<RepoInfo.Stack> stacks, List<ToolResult> tools,
                            List<Finding> findings, int suppressed, Scores scores, boolean webFrontend) {}
