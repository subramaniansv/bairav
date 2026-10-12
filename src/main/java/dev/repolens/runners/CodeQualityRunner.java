package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.ProcessRunner;
import dev.repolens.util.RepoWalker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;

/**
 * Built-in maintainability checks (no external install): approximate cyclomatic complexity and length per
 * method, duplicated blocks, TODO count and git-churn hotspots. Numbers are approximations from a lightweight
 * scanner, good enough to rank refactoring candidates, not a replacement for a full parser.
 */
public class CodeQualityRunner implements ToolRunner {

    public static final String NAME = "code-quality";

    private static final int DUP_WINDOW = 8;
    private static final long MAX_BYTES = 300_000;
    private static final int MAX_COMPLEXITY_FINDINGS = 100;
    private static final int MAX_DUP_FINDINGS = 30;
    private static final int LONG_METHOD_LINES = 100;
    private static final int HOTSPOT_MIN_CHURN = 10;

    private static final Set<String> CONTROL = Set.of("if", "for", "while", "switch", "catch", "return", "new", "else",
            "try", "synchronized", "throw", "do", "super", "this", "function", "await", "typeof");
    private static final Pattern JAVA_METHOD = Pattern.compile(
            "^\\s*(?:(?:public|protected|private|static|final|abstract|synchronized|default|native)\\s+)*"
                    + "(?:<[^>]+>\\s+)?[\\w.<>\\[\\],?]+(?:\\s+[\\w.<>\\[\\],?]+)*\\s+(\\w+)\\s*\\(");
    private static final Pattern JS_FUNCTION = Pattern.compile("\\bfunction\\s*\\*?\\s*(\\w+)\\s*\\(");
    private static final Pattern JS_ARROW = Pattern.compile(
            "\\b(?:const|let|var)\\s+(\\w+)\\s*(?::[^=]+)?=\\s*(?:async\\s*)?(?:function\\b|\\([^)]*\\)\\s*(?::[^=>]+)?=>|\\w+\\s*=>)");
    private static final Pattern JS_METHOD = Pattern.compile(
            "^\\s*(?:(?:static|async|get|set|public|private|protected|readonly)\\s+)*(\\w+)\\s*\\([^)]*\\)\\s*(?::\\s*[\\w<>\\[\\]|. ,]+)?\\s*\\{");
    private static final Pattern DECISION = Pattern.compile("\\b(?:if|for|while|case|catch)\\b|&&|\\|\\||(?<!\\?)\\?(?![.?:])");
    private static final Pattern TODO = Pattern.compile("\\b(?:TODO|FIXME|HACK|XXX)\\b");

    record Method(String file, String name, int line, int length, int complexity) {}

    @Override public String name() { return NAME; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return !repo.stacks().isEmpty();
    }

    @Override
    public ToolResult run(Context ctx) throws Exception {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        int maxCx = ctx.config().maxComplexity();

        List<Path> files = new ArrayList<>();
        RepoWalker.walk(root, (p, a) -> {
            String n = p.getFileName().toString();
            if (a.size() > MAX_BYTES || a.size() == 0) return;
            if (!(n.endsWith(".java") || n.matches(".*\\.(js|jsx|ts|tsx|mjs)$")) || n.endsWith(".d.ts") || n.endsWith(".min.js")) return;
            if (isTest(root.relativize(p).toString().replace('\\', '/'))) return;
            files.add(p);
        });

        List<Method> methods = new ArrayList<>();
        Map<String, Integer> maxByFile = new HashMap<>();
        int todos = 0;
        int totalLines = 0;
        Map<Long, String> seenWindows = new HashMap<>();
        Map<String, Set<Integer>> dupLines = new HashMap<>();
        Map<String, Map<Integer, String>> dupOther = new HashMap<>();

        for (Path p : files) {
            String rel = root.relativize(p).toString().replace('\\', '/');
            String text;
            try {
                text = Files.readString(p);
            } catch (IOException e) {
                continue; // binary / odd encoding
            }
            String[] raw = text.split("\n", -1);
            totalLines += raw.length;
            Matcher tm = TODO.matcher(text);
            while (tm.find()) todos++;
            String[] clean = strip(text).split("\n", -1);
            boolean java = rel.endsWith(".java");
            for (Method mth : methods(rel, clean, java)) {
                methods.add(mth);
                maxByFile.merge(rel, mth.complexity(), Math::max);
            }
            detectDuplicates(rel, raw, seenWindows, dupLines, dupOther);
        }

        List<Finding> findings = new ArrayList<>();
        methods.stream().filter(m -> m.complexity() > maxCx)
                .sorted(Comparator.comparingInt(Method::complexity).reversed()).limit(MAX_COMPLEXITY_FINDINGS)
                .forEach(m -> findings.add(new Finding(NAME, Category.QUALITY,
                        m.complexity() > maxCx * 2 ? Severity.HIGH : Severity.MEDIUM, m.file(), m.line(),
                        "quality/high-complexity", "Method " + m.name() + " is too complex (limit " + maxCx + ")", "CWE-1121", null,
                        "Cyclomatic complexity is about " + m.complexity() + ". Extract branches into small named methods, "
                                + "replace nested conditionals with guard clauses or a lookup table, and add tests first.")));
        methods.stream().filter(m -> m.length() > LONG_METHOD_LINES && m.complexity() <= maxCx)
                .sorted(Comparator.comparingInt(Method::length).reversed()).limit(50)
                .forEach(m -> findings.add(new Finding(NAME, Category.QUALITY, Severity.LOW, m.file(), m.line(),
                        "quality/long-method", "Method " + m.name() + " is very long (limit " + LONG_METHOD_LINES + " lines)",
                        "CWE-1121", null, "It is " + m.length() + " lines. Split it into cohesive steps.")));

        int dupCount = dupLines.values().stream().mapToInt(Set::size).sum();
        findings.addAll(duplicateFindings(dupLines, dupOther));

        Map<String, Integer> churn = churn(ctx);
        int hotspots = 0;
        for (var e : churn.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).toList()) {
            int cx = maxByFile.getOrDefault(e.getKey(), 0);
            if (e.getValue() >= HOTSPOT_MIN_CHURN && cx > maxCx && hotspots < 5) {
                hotspots++;
                findings.add(new Finding(NAME, Category.QUALITY, Severity.LOW, e.getKey(), 0, "quality/hotspot",
                        "Frequently changed and complex file (refactoring hotspot)", null, null,
                        "Changed " + e.getValue() + " times in 6 months with a method of complexity ~" + cx
                                + ". Simplify and cover it with tests: bugs concentrate here."));
            }
        }

        Map<String, String> m = new LinkedHashMap<>();
        m.put("Files analysed", String.valueOf(files.size()));
        m.put("Methods analysed", String.valueOf(methods.size()));
        m.put("Avg complexity", String.format("%.1f", methods.stream().mapToInt(Method::complexity).average().orElse(0)));
        m.put("Max complexity", String.valueOf(methods.stream().mapToInt(Method::complexity).max().orElse(0)));
        m.put("Duplicated lines", totalLines == 0 ? "0%" : String.format("%.1f%% (%d lines)", dupCount * 100.0 / totalLines, dupCount));
        m.put("TODO/FIXME markers", String.valueOf(todos));
        m.put("Git churn", churn.isEmpty() ? "n/a (not a git repo or no history)" : churn.size() + " files changed in 6 months");
        return ToolResult.ok(NAME, findings, findings.size() + " finding(s)", System.currentTimeMillis() - start).withMetrics(m);
    }

    static boolean isTest(String rel) {
        return rel.contains("src/test/") || rel.contains("__tests__/") || rel.startsWith("tests/") || rel.contains("/tests/")
                || rel.matches(".*\\.(test|spec)\\.[jt]sx?$") || rel.matches(".*(Test|Tests|IT)\\.java$");
    }

    /** Blanks comments and string/char/template literals, preserving newlines so line numbers stay valid. */
    static String strip(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            char d = i + 1 < n ? s.charAt(i + 1) : 0;
            if (c == '/' && d == '/') {
                while (i < n && s.charAt(i) != '\n') { out.append(' '); i++; }
            } else if (c == '/' && d == '*') {
                out.append("  ");
                i += 2;
                while (i < n && !(s.charAt(i) == '*' && i + 1 < n && s.charAt(i + 1) == '/')) {
                    out.append(s.charAt(i) == '\n' ? '\n' : ' ');
                    i++;
                }
                if (i < n) { out.append("  "); i += 2; }
            } else if (c == '"' || c == '\'' || c == '`') {
                out.append(c);
                i++;
                while (i < n && s.charAt(i) != c && (c == '`' || s.charAt(i) != '\n')) {
                    if (s.charAt(i) == '\\' && i + 1 < n) { out.append("  "); i += 2; continue; }
                    out.append(s.charAt(i) == '\n' ? '\n' : ' ');
                    i++;
                }
                if (i < n) { out.append(c); i++; }
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    static List<Method> methods(String file, String[] clean, boolean java) {
        List<Method> out = new ArrayList<>();
        for (int i = 0; i < clean.length; i++) {
            String name = declaredName(clean[i], java);
            if (name == null) continue;
            int open = findBodyStart(clean, i);
            if (open < 0) continue;
            int end = matchBrace(clean, open);
            if (end < 0) continue;
            int cx = 1;
            for (int k = open; k <= end; k++) {
                String body = k == open ? clean[k].substring(clean[k].indexOf('{')) : clean[k];
                Matcher m = DECISION.matcher(body);
                while (m.find()) cx++;
            }
            out.add(new Method(file, name, i + 1, end - i + 1, cx));
        }
        return out;
    }

    private static String declaredName(String line, boolean java) {
        if (line.isBlank() || line.length() > 300) return null;
        Matcher m;
        if (java) {
            m = JAVA_METHOD.matcher(line);
            if (m.find() && !CONTROL.contains(m.group(1)) && !line.trim().startsWith("return ") && !line.contains(" new ")
                    && !line.contains("=")) return m.group(1);
            return null;
        }
        m = JS_FUNCTION.matcher(line);
        if (m.find()) return m.group(1);
        m = JS_ARROW.matcher(line);
        if (m.find()) return m.group(1);
        m = JS_METHOD.matcher(line);
        if (m.find() && !CONTROL.contains(m.group(1))) return m.group(1);
        return null;
    }

    /** Index of the line holding the body's opening brace, or -1 for abstract/expression-bodied declarations. */
    private static int findBodyStart(String[] clean, int from) {
        for (int j = from; j < Math.min(clean.length, from + 8); j++) {
            String l = clean[j];
            int brace = l.indexOf('{');
            int semi = l.indexOf(';');
            if (brace >= 0 && (semi < 0 || brace < semi)) return j;
            if (semi >= 0) return -1;
            if (j == from && l.contains("=>") && !l.contains("{")) return -1;
        }
        return -1;
    }

    private static int matchBrace(String[] clean, int open) {
        int depth = 0;
        boolean started = false;
        for (int j = open; j < clean.length; j++) {
            String l = j == open ? clean[j].substring(clean[j].indexOf('{')) : clean[j];
            for (int k = 0; k < l.length(); k++) {
                char c = l.charAt(k);
                if (c == '{') { depth++; started = true; }
                else if (c == '}' && --depth == 0 && started) return j;
            }
        }
        return -1;
    }

    private static void detectDuplicates(String rel, String[] raw, Map<Long, String> seen,
                                         Map<String, Set<Integer>> dupLines, Map<String, Map<Integer, String>> dupOther) {
        List<Integer> nums = new ArrayList<>();
        List<String> norm = new ArrayList<>();
        for (int i = 0; i < raw.length; i++) {
            String t = raw[i].trim().replaceAll("\\s+", " ");
            if (t.length() < 6 || t.startsWith("//") || t.startsWith("*") || t.startsWith("/*") || t.startsWith("import ")
                    || t.startsWith("package ") || t.startsWith("@")) continue;
            nums.add(i + 1);
            norm.add(t);
        }
        for (int i = 0; i + DUP_WINDOW <= norm.size(); i++) {
            CRC32 crc = new CRC32();
            String joined = String.join("\n", norm.subList(i, i + DUP_WINDOW));
            crc.update(joined.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            long key = (crc.getValue() << 32) | (joined.hashCode() & 0xffffffffL);
            String loc = rel + ":" + nums.get(i);
            String prev = seen.putIfAbsent(key, loc);
            if (prev == null) continue;
            String prevFile = prev.substring(0, prev.lastIndexOf(':'));
            int prevLine = Integer.parseInt(prev.substring(prev.lastIndexOf(':') + 1));
            if (prevFile.equals(rel) && Math.abs(prevLine - nums.get(i)) < DUP_WINDOW * 2) continue;
            for (int k = i; k < i + DUP_WINDOW; k++) {
                dupLines.computeIfAbsent(rel, x -> new HashSet<>()).add(nums.get(k));
                dupOther.computeIfAbsent(rel, x -> new HashMap<>()).putIfAbsent(nums.get(k), prev);
            }
        }
    }

    private static List<Finding> duplicateFindings(Map<String, Set<Integer>> dupLines, Map<String, Map<Integer, String>> dupOther) {
        record Block(String file, int start, int lines, String other) {}
        List<Block> blocks = new ArrayList<>();
        for (var e : dupLines.entrySet()) {
            List<Integer> ls = new ArrayList<>(new java.util.TreeSet<>(e.getValue()));
            int s = ls.get(0);
            int prev = s;
            int count = 1;
            for (int i = 1; i <= ls.size(); i++) {
                if (i < ls.size() && ls.get(i) - prev <= 3) { prev = ls.get(i); count++; continue; }
                blocks.add(new Block(e.getKey(), s, count, dupOther.get(e.getKey()).get(s)));
                if (i < ls.size()) { s = ls.get(i); prev = s; count = 1; }
            }
        }
        List<Finding> out = new ArrayList<>();
        blocks.stream().sorted(Comparator.comparingInt(Block::lines).reversed()).limit(MAX_DUP_FINDINGS).forEach(b ->
                out.add(new Finding(NAME, Category.QUALITY, Severity.LOW, b.file(), b.start(), "quality/duplicate-block",
                        "Duplicated code block, also at " + b.other(), "CWE-1041", null,
                        "About " + b.lines() + " duplicated lines. Extract a shared function/component and reuse it.")));
        return out;
    }

    private static Map<String, Integer> churn(Context ctx) {
        Map<String, Integer> out = new TreeMap<>();
        if (ProcessRunner.which("git") == null) return out;
        try {
            Path o = ctx.rawFile("git-churn.txt");
            int rc = ProcessRunner.run(List.of("git", "log", "--since=6.months", "--name-only", "--relative", "--pretty=format:", "--", "."),
                    ctx.root(), o, ctx.logFile("git-churn"), 60);
            if (rc != 0) return out;
            for (String l : Files.readAllLines(o)) if (!l.isBlank()) out.merge(l.trim(), 1, Integer::sum);
        } catch (Exception ignored) {
            // churn is optional
        }
        return out;
    }
}
