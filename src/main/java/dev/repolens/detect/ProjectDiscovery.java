package dev.repolens.detect;

import dev.repolens.util.RepoWalker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Finds project roots (pom.xml / build.gradle / package.json) inside a monorepo or workspace folder. */
public final class ProjectDiscovery {

    private static final int MAX_DEPTH = 4;
    private static final List<String> MARKERS = List.of("pom.xml", "build.gradle", "build.gradle.kts", "package.json");

    private ProjectDiscovery() {}

    public static List<Path> find(Path root) throws IOException {
        List<Path> found = new ArrayList<>();
        walk(root, 0, found);
        // drop nested modules of the same stack (e.g. maven sub-modules, nested package.json in a workspace)
        List<Path> result = new ArrayList<>();
        for (Path p : found) {
            Set<String> stack = markers(p);
            boolean nested = found.stream().anyMatch(o -> !o.equals(p) && p.startsWith(o)
                    && markers(o).stream().anyMatch(stack::contains));
            if (!nested) result.add(p);
        }
        if (result.isEmpty()) result.add(root);
        return result;
    }

    private static void walk(Path dir, int depth, List<Path> out) throws IOException {
        if (markers(dir).size() > 0) out.add(dir);
        if (depth >= MAX_DEPTH) return;
        try (var s = Files.list(dir)) {
            for (Path c : (Iterable<Path>) s.filter(Files::isDirectory).sorted()::iterator) {
                String n = c.getFileName().toString();
                if (RepoWalker.SKIP_DIRS.contains(n) || n.startsWith(".")) continue;
                walk(c, depth + 1, out);
            }
        }
    }

    private static Set<String> markers(Path dir) {
        Set<String> s = new java.util.HashSet<>();
        for (String m : MARKERS) {
            if (Files.exists(dir.resolve(m))) s.add(m.startsWith("package") ? "node" : m.startsWith("pom") ? "maven" : "gradle");
        }
        return s;
    }
}
