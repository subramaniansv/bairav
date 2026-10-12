package dev.repolens.runners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.RepoWalker;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static SEO / GEO (generative engines) / AEO (answer engines) / accessibility checks on the
 * HTML entry point, public assets and React/HTML sources. No running app needed.
 */
public class SeoRunner implements ToolRunner {

    public static final String NAME = "seo-geo-aeo";
    public static final String SCOPE_KEY = "SEO/GEO/AEO scope";
    public static final String SCOPE_ACTIVE = "active";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern IMG_NO_ALT = Pattern.compile("<img\\b(?![^>]*\\balt\\s*=)[^>]*>", Pattern.DOTALL);
    private static final Pattern DIV_CLICK = Pattern.compile("<(div|span)\\b(?![^>]*\\brole\\s*=)[^>]*\\bonClick\\s*=[^>]*>", Pattern.DOTALL);
    private static final List<String> AI_BOTS = List.of("GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "CCBot");

    @Override public String name() { return NAME; }

    @Override
    public boolean applicable(RepoInfo repo) {
        return repo.has(RepoInfo.Stack.NODE);
    }

    @Override
    public ToolResult run(Context ctx) throws IOException {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        Path index = firstExisting(root.resolve("index.html"), root.resolve("public/index.html"), root.resolve("dist/index.html"));
        if (index == null) {
            return ToolResult.skipped(NAME, "no index.html: not a web frontend");
        }
        List<Finding> f = new ArrayList<>();
        Map<String, String> metrics = new LinkedHashMap<>();
        String rel = root.relativize(index).toString();
        Document doc = Jsoup.parse(Files.readString(index));

        boolean noindex = doc.select("meta[name=robots]").stream()
                .anyMatch(e -> e.attr("content").toLowerCase().contains("noindex"));
        metrics.put(SCOPE_KEY, noindex ? "skipped (noindex: private app)" : SCOPE_ACTIVE);
        metrics.put("HTML entry", rel);

        if (!noindex) {
            seoChecks(ctx, doc, rel, f);
            geoAeoChecks(ctx, doc, rel, f);
        }
        accessibilityChecks(ctx, doc, rel, f);
        return ToolResult.ok(NAME, f, f.size() + " finding(s)", System.currentTimeMillis() - start).withMetrics(metrics);
    }

    private void seoChecks(Context ctx, Document doc, String rel, List<Finding> f) throws IOException {
        Path root = ctx.root();
        String title = doc.title().trim();
        if (title.isEmpty()) {
            add(f, Category.SEO, Severity.HIGH, rel, "missing-title", "Page has no <title>",
                    "Add a unique, descriptive <title> of 10-60 characters.");
        } else if (title.length() < 10 || title.length() > 60) {
            add(f, Category.SEO, Severity.LOW, rel, "title-length", "Title is " + title.length() + " chars (\"" + title + "\"); aim for 10-60",
                    "Rewrite the title to include the primary keyword within 10-60 characters.");
        }
        String desc = doc.select("meta[name=description]").attr("content").trim();
        if (desc.isEmpty()) {
            add(f, Category.SEO, Severity.MEDIUM, rel, "missing-meta-description", "No meta description",
                    "Add <meta name=\"description\" content=\"...\"> of 50-160 characters.");
        } else if (desc.length() < 50 || desc.length() > 160) {
            add(f, Category.SEO, Severity.LOW, rel, "meta-description-length",
                    "Meta description is " + desc.length() + " chars; aim for 50-160",
                    "Expand the description to summarise the page value with key terms (50-160 chars).");
        }
        if (doc.select("link[rel=canonical]").isEmpty()) {
            add(f, Category.SEO, Severity.LOW, rel, "missing-canonical", "No canonical link",
                    "Add <link rel=\"canonical\" href=\"https://your-domain/\"> to avoid duplicate-URL dilution.");
        }
        for (String og : List.of("og:title", "og:description", "og:image")) {
            if (doc.select("meta[property=" + og + "]").isEmpty()) {
                add(f, Category.SEO, Severity.LOW, rel, "missing-" + og.replace(':', '-'),
                        "Missing " + og + " (link previews on social/chat)",
                        "Add <meta property=\"" + og + "\" content=\"...\">.");
            }
        }
        if (doc.select("meta[name=twitter:card]").isEmpty()) {
            add(f, Category.SEO, Severity.LOW, rel, "missing-twitter-card", "Missing twitter:card meta",
                    "Add <meta name=\"twitter:card\" content=\"summary_large_image\">.");
        }
        if (doc.select("link[rel~=icon]").isEmpty()) {
            add(f, Category.SEO, Severity.LOW, rel, "missing-favicon", "No favicon link", "Add <link rel=\"icon\" ...>.");
        }

        Path robots = findAsset(root, "robots.txt");
        Path sitemap = findAsset(root, "sitemap.xml");
        if (robots == null) {
            add(f, Category.SEO, Severity.MEDIUM, "public/robots.txt", "missing-robots-txt", "No robots.txt",
                    "Add public/robots.txt with 'User-agent: *' rules and a Sitemap: line.");
        }
        if (sitemap == null) {
            add(f, Category.SEO, Severity.MEDIUM, "public/sitemap.xml", "missing-sitemap", "No sitemap.xml",
                    "Generate a sitemap (e.g. vite-plugin-sitemap) listing all public routes.");
        } else if (robots != null && !Files.readString(robots).toLowerCase().contains("sitemap:")) {
            add(f, Category.SEO, Severity.LOW, root.relativize(robots).toString(), "robots-no-sitemap",
                    "robots.txt does not reference the sitemap", "Add 'Sitemap: https://your-domain/sitemap.xml'.");
        }

        if (isClientRenderedShell(doc)) {
            add(f, Category.SEO, Severity.MEDIUM, rel, "csr-empty-shell",
                    "HTML ships an empty root element; content only appears after JavaScript runs",
                    "Add prerendering/SSR for public routes (Next.js/Remix, vite-ssg, or a prerender plugin) so crawlers get real HTML.");
            add(f, Category.GEO_AEO, Severity.MEDIUM, rel, "ai-bots-cannot-render-js",
                    "Most AI crawlers (GPTBot, ClaudeBot, PerplexityBot) do not execute JS, so they see an empty page",
                    "Serve pre-rendered HTML for pages you want cited by AI answers.");
        }
        checkPerRouteMeta(ctx, f);
    }

    private void geoAeoChecks(Context ctx, Document doc, String rel, List<Finding> f) throws IOException {
        Path root = ctx.root();
        List<Element> ld = doc.select("script[type=application/ld+json]");
        if (ld.isEmpty()) {
            add(f, Category.GEO_AEO, Severity.MEDIUM, rel, "missing-jsonld", "No JSON-LD structured data",
                    "Add schema.org JSON-LD (Organization, WebSite, FAQPage / HowTo / Article as applicable) so answer engines can extract facts.");
        } else {
            for (Element e : ld) {
                try {
                    JsonNode n = MAPPER.readTree(e.data());
                    if (!n.has("@type") && !n.has("@graph")) {
                        add(f, Category.GEO_AEO, Severity.MEDIUM, rel, "jsonld-no-type", "JSON-LD block has no @type", "Add \"@type\" (e.g. Organization).");
                    }
                } catch (Exception ex) {
                    add(f, Category.GEO_AEO, Severity.HIGH, rel, "jsonld-invalid", "JSON-LD block is not valid JSON", "Fix the JSON syntax.");
                }
            }
        }
        if (findAsset(root, "llms.txt") == null) {
            add(f, Category.GEO_AEO, Severity.LOW, "public/llms.txt", "missing-llms-txt", "No llms.txt",
                    "Add public/llms.txt: a short Markdown summary and key links meant for LLM crawlers.");
        }
        Path robots = findAsset(root, "robots.txt");
        if (robots != null) {
            String r = Files.readString(robots);
            boolean mentionsAi = AI_BOTS.stream().anyMatch(b -> r.toLowerCase().contains(b.toLowerCase()));
            if (!mentionsAi) {
                add(f, Category.GEO_AEO, Severity.LOW, root.relativize(robots).toString(), "ai-crawler-policy-undefined",
                        "robots.txt has no explicit rules for AI crawlers (" + String.join(", ", AI_BOTS) + ")",
                        "Decide and state it: Allow to be cited in AI answers, or Disallow to opt out.");
            }
        }
        if (doc.select("h1, h2").isEmpty() && !isClientRenderedShell(doc)) {
            add(f, Category.GEO_AEO, Severity.LOW, rel, "no-headings", "No h1/h2 headings in static HTML",
                    "Use a clear heading hierarchy; phrase some headings as the questions users ask (AEO).");
        }
    }

    private void accessibilityChecks(Context ctx, Document doc, String rel, List<Finding> f) throws IOException {
        if (doc.select("html").attr("lang").isBlank()) {
            add(f, Category.ACCESSIBILITY, Severity.MEDIUM, rel, "missing-lang", "<html> has no lang attribute",
                    "Add lang=\"en\" (or the right language) to <html>.");
        }
        String viewport = doc.select("meta[name=viewport]").attr("content").toLowerCase();
        if (viewport.isEmpty()) {
            add(f, Category.ACCESSIBILITY, Severity.MEDIUM, rel, "missing-viewport", "No viewport meta (breaks mobile rendering)",
                    "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">.");
        } else if (viewport.contains("user-scalable=no") || viewport.matches(".*maximum-scale=1(\\.0)?(,|$).*")) {
            add(f, Category.ACCESSIBILITY, Severity.MEDIUM, rel, "zoom-disabled", "Viewport disables pinch-zoom",
                    "Remove user-scalable=no / maximum-scale=1.");
        }
        int[] caps = {0, 0};
        RepoWalker.walk(ctx.root(), (p, a) -> {
            String n = p.getFileName().toString();
            if (!n.matches(".*\\.(tsx|jsx|html|vue)$") || a.size() > 500_000) return;
            String text;
            try {
                text = Files.readString(p);
            } catch (Exception e) {
                return;
            }
            String relPath = ctx.root().relativize(p).toString();
            Matcher m = IMG_NO_ALT.matcher(text);
            while (m.find() && caps[0]++ < 100) {
                add(f, Category.ACCESSIBILITY, Severity.MEDIUM, relPath, lineOf(text, m.start()), "img-missing-alt",
                        "<img> without alt attribute", "Add a meaningful alt (or alt=\"\" if purely decorative).");
            }
            m = DIV_CLICK.matcher(text);
            while (m.find() && caps[1]++ < 100) {
                add(f, Category.ACCESSIBILITY, Severity.LOW, relPath, lineOf(text, m.start()), "click-on-non-interactive",
                        "onClick on a <" + m.group(1) + "> without a role (not keyboard accessible)",
                        "Use a <button>/<a>, or add role, tabIndex and key handlers.");
            }
        });
    }

    private void checkPerRouteMeta(Context ctx, List<Finding> f) throws IOException {
        Path pkg = ctx.root().resolve("package.json");
        if (!Files.exists(pkg)) return;
        String json = Files.readString(pkg);
        boolean router = json.contains("react-router");
        boolean head = json.contains("react-helmet") || json.contains("@unhead") || json.contains("react-head");
        if (!router || head) return;
        boolean[] usesTitle = {false};
        RepoWalker.walk(ctx.root(), (p, a) -> {
            if (usesTitle[0] || !p.toString().matches(".*\\.(tsx|ts|jsx|js)$") || a.size() > 500_000) return;
            try {
                if (Files.readString(p).contains("document.title")) usesTitle[0] = true;
            } catch (Exception ignored) {
                // skip
            }
        });
        if (!usesTitle[0]) {
            add(f, Category.SEO, Severity.MEDIUM, "package.json", "no-per-route-meta",
                    "Uses react-router but nothing sets per-route <title>/meta (every URL shares one title)",
                    "Add react-helmet-async (or set document.title) per route, with unique titles and descriptions.");
        }
    }

    private static boolean isClientRenderedShell(Document doc) {
        Element root = doc.selectFirst("#root, #app, #__next, #app-root");
        return root != null && root.text().isBlank() && doc.select("h1").isEmpty()
                && doc.select("body").text().trim().length() < 50;
    }

    private static Path findAsset(Path root, String name) {
        return firstExisting(root.resolve("public").resolve(name), root.resolve(name), root.resolve("dist").resolve(name));
    }

    private static Path firstExisting(Path... ps) {
        for (Path p : ps) if (Files.isRegularFile(p)) return p;
        return null;
    }

    private static int lineOf(String text, int idx) {
        int line = 1;
        for (int i = 0; i < idx; i++) if (text.charAt(i) == '\n') line++;
        return line;
    }

    private static void add(List<Finding> l, Category c, Severity s, String file, String rule, String msg, String fix) {
        add(l, c, s, file, 0, rule, msg, fix);
    }

    private static synchronized void add(List<Finding> l, Category c, Severity s, String file, int line,
                                         String rule, String msg, String fix) {
        l.add(new Finding(NAME, c, s, file, line, rule, msg, null, null, fix));
    }
}
