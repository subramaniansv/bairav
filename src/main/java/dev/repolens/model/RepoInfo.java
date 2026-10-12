package dev.repolens.model;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Set;

public record RepoInfo(Path root, Set<Stack> stacks) {

    public enum Stack { MAVEN, GRADLE, NODE }

    public boolean has(Stack s) {
        return stacks.contains(s);
    }

    public static Set<Stack> none() {
        return EnumSet.noneOf(Stack.class);
    }
}
