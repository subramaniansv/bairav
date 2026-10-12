package dev.repolens.runners;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.stream.Stream;

/**
 * The runner registry. Teams can add their own checks without forking: drop a jar that declares a
 * {@link ToolRunner} in META-INF/services/dev.repolens.runners.ToolRunner into a plugins directory.
 */
public final class Runners {

    private Runners() {}

    public static List<ToolRunner> defaults() {
        return new ArrayList<>(List.of(new HeuristicRunner(), new BuildHealthRunner(), new CodeQualityRunner(),
                new CoverageRunner(), new SeoRunner(), new SemgrepRunner(), new TrivyRunner(), new SbomLicenseRunner(), new SupplyChainRunner(), new ArchitectureRunner(), new GitAnalyticsRunner(), new OutdatedRunner(), new OperationsRunner(), new ApiDbRunner(), new PerformanceDeepRunner(), new LoadTestRunner(), new PrivacyI18nRunner(),
                new GitleaksRunner(), new OsvScannerRunner(), new NpmAuditRunner(), new SpotBugsRunner(),
                new LighthouseRunner(), new ZapRunner()));
    }

    public static List<ToolRunner> withPlugins(Path pluginDir) throws IOException {
        List<ToolRunner> all = defaults();
        if (pluginDir == null || !Files.isDirectory(pluginDir)) return all;
        List<URL> urls = new ArrayList<>();
        try (Stream<Path> s = Files.list(pluginDir)) {
            for (Path p : s.filter(x -> x.toString().endsWith(".jar")).toList()) urls.add(p.toUri().toURL());
        }
        if (urls.isEmpty()) return all;
        ClassLoader cl = new URLClassLoader(urls.toArray(new URL[0]), Runners.class.getClassLoader());
        for (ToolRunner r : ServiceLoader.load(ToolRunner.class, cl)) {
            System.out.println("Plugin runner loaded: " + r.name());
            all.add(r);
        }
        return all;
    }
}
