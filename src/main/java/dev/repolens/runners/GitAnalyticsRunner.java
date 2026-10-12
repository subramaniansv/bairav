package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.ProcessRunner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Team health from git history: bus factor / code ownership, stale branches, oversized commits, plus DORA
 * proxies (deploy frequency from tags, lead time, change-failure ratio). Real DORA needs CI/deploy data;
 * these proxies say so in their metric names.
 */
public class GitAnalyticsRunner implements ToolRunner {

    public static final String NAME = "git-analytics";

    private static final long DAY = 86_400L;
    private static final int STALE_DAYS = 90;
    private static final int BIG_COMMIT_LINES = 1000;
    private static final int MIN_COMMITS_FOR_BUS_FACTOR = 20;
    private static final Pattern SHORTSTAT = Pattern.compile("(\\d+) insertion|(\\d+) deletion");

    @Override public String name() { return NAME; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return Files.exists(repo.root().resolve(".git")) || ProcessRunner.which("git") != null;
    }

    @Override
    public ToolResult run(Context ctx) throws Exception {
        long start = System.currentTimeMillis();
        if (ProcessRunner.which("git") == null) return ToolResult.skipped(NAME, "git not installed");
        List<String> top = git(ctx, "toplevel", "rev-parse", "--show-toplevel");
        if (top == null || top.isEmpty()) return ToolResult.skipped(NAME, "not a git repository");

        List<Finding> out = new ArrayList<>();
        Map<String, String> metrics = new LinkedHashMap<>();
        long now = Instant.now().getEpochSecond();

        // ownership / bus factor (this project directory only)
        List<String> authors = git(ctx, "authors", "log", "--no-merges", "--format=%an", "--", ".");
        if (authors != null && !authors.isEmpty()) {
            Map<String, Integer> byAuthor = new LinkedHashMap<>();
            authors.stream().filter(s -> !s.isBlank()).forEach(a -> byAuthor.merge(a, 1, Integer::sum));
            int total = byAuthor.values().stream().mapToInt(Integer::intValue).sum();
            List<Map.Entry<String, Integer>> sorted = byAuthor.entrySet().stream()
                    .sorted((a, b) -> b.getValue() - a.getValue()).toList();
            int bus = busFactor(sorted.stream().map(Map.Entry::getValue).toList(), total);
            int topPct = total == 0 ? 0 : sorted.get(0).getValue() * 100 / total;
            metrics.put("Contributors", String.valueOf(byAuthor.size()));
            metrics.put("Commits (no merges)", String.valueOf(total));
            metrics.put("Bus factor", String.valueOf(bus));
            metrics.put("Top contributor share", topPct + "%");
            if (total >= MIN_COMMITS_FOR_BUS_FACTOR && bus == 1) {
                out.add(new Finding(NAME, Category.TEAM, topPct >= 90 ? Severity.MEDIUM : Severity.LOW, ".", 0, "bus-factor-1",
                        "Bus factor 1: one person wrote " + topPct + "% of the commits",
                        null, null, "Spread knowledge: pair/rotate reviews, document the module, add a CODEOWNERS file."));
            }
        }

        if (!Files.exists(ctx.root().resolve("CODEOWNERS")) && !Files.exists(ctx.root().resolve(".github/CODEOWNERS"))
                && !Files.exists(ctx.root().resolve("docs/CODEOWNERS")) && authors != null && authors.size() >= 20) {
            out.add(new Finding(NAME, Category.TEAM, Severity.INFO, ".", 0, "no-codeowners",
                    "No CODEOWNERS file", null, null, "Add .github/CODEOWNERS so reviews route to owners."));
        }

        // stale branches
        List<String> refs = git(ctx, "branches", "for-each-ref", "--format=%(refname:short)|%(committerdate:unix)",
                "refs/heads", "refs/remotes");
        if (refs != null) {
            List<String> stale = new ArrayList<>();
            for (String r : refs) {
                String[] p = r.split("\\|");
                if (p.length != 2) continue;
                String b = p[0];
                if (b.endsWith("/HEAD") || b.matches("(origin/)?(main|master|develop|trunk|release.*)")) continue;
                try {
                    if (now - Long.parseLong(p[1].trim()) > STALE_DAYS * DAY) stale.add(b);
                } catch (NumberFormatException ignored) {
                    // skip
                }
            }
            metrics.put("Stale branches (>" + STALE_DAYS + "d)", String.valueOf(stale.size()));
            if (stale.size() >= 5) {
                out.add(new Finding(NAME, Category.TEAM, Severity.LOW, ".", 0, "stale-branches",
                        stale.size() + " branches have had no commits for " + STALE_DAYS + "+ days (e.g. "
                                + String.join(", ", stale.stream().limit(3).toList()) + ")",
                        null, null, "Delete merged branches; archive or revive the rest."));
            }
        }

        // large commits in the last 90 days
        List<String> stat = git(ctx, "shortstat", "log", "--no-merges", "--since=" + STALE_DAYS + ".days.ago", "--shortstat",
                "--format=@@", "--", ".");
        if (stat != null) {
            List<Integer> sizes = commitSizes(stat);
            long big = sizes.stream().filter(s -> s > BIG_COMMIT_LINES).count();
            if (!sizes.isEmpty()) {
                metrics.put("Commits last " + STALE_DAYS + "d", String.valueOf(sizes.size()));
                metrics.put("Median commit size (lines)", String.valueOf(median(sizes)));
                metrics.put("Large commits (>" + BIG_COMMIT_LINES + " lines)", String.valueOf(big));
            }
            if (big >= 3) {
                out.add(new Finding(NAME, Category.TEAM, Severity.LOW, ".", 0, "large-commits",
                        big + " commits changed more than " + BIG_COMMIT_LINES + " lines in the last " + STALE_DAYS + " days",
                        null, null, "Keep PRs small and focused: they review faster and break less."));
            }
        }

        dora(ctx, now, metrics);
        return ToolResult.ok(NAME, out, out.size() + " finding(s)", System.currentTimeMillis() - start).withMetrics(metrics);
    }

    /** Smallest number of top contributors that together account for at least half of the commits. */
    static int busFactor(List<Integer> sortedDesc, int total) {
        if (total == 0) return 0;
        int acc = 0;
        int n = 0;
        for (int c : sortedDesc) {
            acc += c;
            n++;
            if (acc * 2 >= total) return n;
        }
        return n;
    }

    /** Lines changed (insertions + deletions) for each commit in `git log --shortstat --format=@@` output. */
    static List<Integer> commitSizes(List<String> lines) {
        List<Integer> sizes = new ArrayList<>();
        int cur = -1;
        for (String l : lines) {
            if (l.equals("@@")) {
                if (cur >= 0) sizes.add(cur);
                cur = 0;
            } else if (cur >= 0 && l.contains("changed")) {
                Matcher m = SHORTSTAT.matcher(l);
                while (m.find()) cur += Integer.parseInt(m.group(1) != null ? m.group(1) : m.group(2));
            }
        }
        if (cur >= 0) sizes.add(cur);
        return sizes.stream().filter(s -> s > 0).toList();
    }

    static int median(List<Integer> v) {
        List<Integer> s = v.stream().sorted().toList();
        return s.get(s.size() / 2);
    }

    private void dora(Context ctx, long now, Map<String, String> metrics) throws Exception {
        List<String> tags = git(ctx, "tags", "tag", "--sort=-creatordate", "--format=%(refname:short)|%(creatordate:unix)");
        if (tags == null || tags.isEmpty()) return;
        int recent = 0;
        List<Long> leadTimes = new ArrayList<>();
        List<String[]> parsed = new ArrayList<>();
        for (String t : tags) {
            String[] p = t.split("\\|");
            if (p.length == 2 && p[1].trim().matches("\\d+")) parsed.add(p);
        }
        for (String[] p : parsed) if (now - Long.parseLong(p[1].trim()) <= STALE_DAYS * DAY) recent++;
        metrics.put("DORA proxy: releases (tags) last " + STALE_DAYS + "d", String.valueOf(recent));
        for (int i = 0; i + 1 < parsed.size() && i < 10; i++) {
            List<String> c = git(ctx, "lead" + i, "log", "--format=%ct", parsed.get(i + 1)[0] + ".." + parsed.get(i)[0]);
            if (c == null || c.isEmpty()) continue;
            long oldest = c.stream().filter(s -> s.trim().matches("\\d+")).mapToLong(s -> Long.parseLong(s.trim())).min().orElse(0);
            long tagTime = Long.parseLong(parsed.get(i)[1].trim());
            if (oldest > 0 && tagTime >= oldest) leadTimes.add((tagTime - oldest) / DAY);
        }
        if (!leadTimes.isEmpty()) {
            List<Long> s = leadTimes.stream().sorted().toList();
            metrics.put("DORA proxy: lead time to release (median days)", String.valueOf(s.get(s.size() / 2)));
        }
        List<String> subjects = git(ctx, "subjects", "log", "--no-merges", "--since=" + STALE_DAYS + ".days.ago", "--format=%s");
        if (subjects != null && !subjects.isEmpty()) {
            long fixes = subjects.stream().filter(s -> s.matches("(?i).*\\b(revert|hotfix|rollback)\\b.*")).count();
            metrics.put("DORA proxy: change-failure (revert/hotfix share)", fixes * 100 / subjects.size() + "%");
        }
    }

    private List<String> git(Context ctx, String id, String... args) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>(List.of("git"));
        cmd.addAll(Arrays.asList(args));
        Path o = ctx.rawFile("git-" + id + ".txt");
        int rc = ProcessRunner.run(cmd, ctx.root(), o, ctx.logFile("git-analytics"), 60);
        if (rc != 0) return null;
        return Files.readAllLines(o);
    }
}
