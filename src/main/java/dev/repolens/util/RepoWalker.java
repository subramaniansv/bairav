package dev.repolens.util;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;
import java.util.function.BiConsumer;

public final class RepoWalker {

    public static final Set<String> SKIP_DIRS = Set.of(
            ".git", "node_modules", "target", "build", "dist", ".idea", ".gradle", ".mvn", "out", "coverage", ".next",
            "playwright-report", "test-results", ".vite", ".venv", "venv", "__pycache__", ".cache");

    private RepoWalker() {}

    /** Visits regular files, skipping VCS/build/dependency directories. */
    public static void walk(Path root, BiConsumer<Path, BasicFileAttributes> visitor) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes a) {
                if (!dir.equals(root) && SKIP_DIRS.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes a) {
                if (a.isRegularFile()) visitor.accept(file, a);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException e) {
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
