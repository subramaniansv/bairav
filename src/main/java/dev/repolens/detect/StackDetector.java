package dev.repolens.detect;

import dev.repolens.model.RepoInfo;
import dev.repolens.model.RepoInfo.Stack;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Set;

public final class StackDetector {

    private StackDetector() {}

    public static RepoInfo detect(Path root) {
        Set<Stack> stacks = EnumSet.noneOf(Stack.class);
        if (Files.exists(root.resolve("pom.xml"))) stacks.add(Stack.MAVEN);
        if (Files.exists(root.resolve("build.gradle")) || Files.exists(root.resolve("build.gradle.kts"))) {
            stacks.add(Stack.GRADLE);
        }
        if (Files.exists(root.resolve("package.json"))) stacks.add(Stack.NODE);
        return new RepoInfo(root, stacks);
    }
}
