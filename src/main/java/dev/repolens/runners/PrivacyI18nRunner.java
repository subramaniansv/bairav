package dev.repolens.runners;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.RepoInfo;
import dev.repolens.model.Severity;
import dev.repolens.model.ToolResult;
import dev.repolens.util.RepoWalker;

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
 * Privacy and internationalisation checks: personal data or credentials written to logs, trackers loaded
 * without any consent mechanism, insecure cookies, PII in browser storage, and hard-coded UI strings /
 * locales. Heuristics only; they point at places to review, they do not prove a GDPR violation.
 */
public class PrivacyI18nRunner implements ToolRunner {

    public static final String NAME = "privacy-i18n";

    private static final String STRONG = "(password|passwd|pwd|secret|token|apikey|api_key|authorization|cvv|cardnumber|card_number|creditcard|ssn|aadhaar|otp)";
    private static final String PII = "(email|phone|mobile|dob|birthdate|address|ipaddress)";
    private static final Pattern JAVA_LOG = Pattern.compile("\\b(?:log|logger|LOG|LOGGER)\\s*\\.\\s*(?:trace|debug|info|warn|error)\\s*\\((.*)");
    private static final Pattern JS_LOG = Pattern.compile("\\bconsole\\s*\\.\\s*(?:log|info|debug|warn|error)\\s*\\((.*)");
    private static final Pattern TRACKER = Pattern.compile(
            "(?i)googletagmanager\\.com|google-analytics\\.com|\\bgtag\\s*\\(|\\bfbq\\s*\\(|connect\\.facebook\\.net|static\\.hotjar\\.com|"
                    + "\\bmixpanel\\b|cdn\\.segment\\.com|clarity\\.ms|doubleclick\\.net|plausible\\.io|amplitude\\.com|react-ga|@vercel/analytics");
    private static final Pattern CONSENT = Pattern.compile(
            "(?i)cookieconsent|cookie-consent|react-cookie-consent|onetrust|cookiebot|osano|termly|usercentrics|klaro|iubenda|"
                    + "consentmanager|cookieyes|axeptio|didomi|gdpr");
    private static final Pattern I18N_LIB = Pattern.compile("\"(react-i18next|i18next|react-intl|@formatjs/[\\w-]+|@lingui/[\\w-]+|next-intl|vue-i18n|@ngx-translate/core)\"");
    private static final Pattern JSX_TEXT = Pattern.compile(">\\s*([A-Z][a-z]+(?:\\s+[A-Za-z']+){1,8}[.!?]?)\\s*<");

    @Override public String name() { return NAME; }

    @Override public boolean applicable(RepoInfo repo) { return !repo.stacks().isEmpty(); }

    @Override
    public ToolResult run(Context ctx) throws IOException {
        long start = System.currentTimeMillis();
        Path root = ctx.root();
        List<Finding> out = new ArrayList<>();
        Map<String, String> metrics = new LinkedHashMap<>();
        String pkg = Files.exists(root.resolve("package.json")) ? Files.readString(root.resolve("package.json")) : "";
        boolean react = pkg.contains("\"react\"");

        List<String[]> trackerHits = new ArrayList<>();
        boolean[] consent = {CONSENT.matcher(pkg).find()};
        boolean[] privacyLink = {false};
        int[] hardcoded = {0};
        String[] firstHardcoded = {null};
        boolean[] usLocale = {false};

        RepoWalker.walk(root, (p, a) -> {
            if (a.size() > 400_000) return;
            String n = p.getFileName().toString();
            String rel = root.relativize(p).toString().replace('\\', '/');
            boolean java = n.endsWith(".java");
            boolean js = n.matches(".*\\.(js|jsx|ts|tsx|mjs|html|vue)$") && !n.endsWith(".min.js");
            if (!java && !js) return;
            if (rel.contains("/test/") || rel.contains("__tests__") || n.matches(".*\\.(test|spec)\\..*")) return;
            try {
                List<String> lines = Files.readAllLines(p);
                String all = String.join("\n", lines);
                if (js) {
                    if (CONSENT.matcher(all).find()) consent[0] = true;
                    if (all.toLowerCase().contains("privacy")) privacyLink[0] = true;
                    if (all.matches("(?s).*\\.toLocale\\w*String\\(\\s*['\"]en-US['\"].*")) usLocale[0] = true;
                    if ((n.endsWith("x") || n.endsWith(".html") || n.endsWith(".vue")) && react) {
                        Matcher m = JSX_TEXT.matcher(all);
                        while (m.find()) {
                            hardcoded[0]++;
                            if (firstHardcoded[0] == null) firstHardcoded[0] = rel;
                        }
                    }
                }
                for (int i = 0; i < lines.size(); i++) {
                    String l = lines.get(i);
                    String t = l.trim();
                    if (t.startsWith("//") || t.startsWith("*") || t.startsWith("#")) continue;
                    if (js && TRACKER.matcher(l).find()) trackerHits.add(new String[]{rel, String.valueOf(i + 1)});
                    Matcher lm = (java ? JAVA_LOG : JS_LOG).matcher(l);
                    if (lm.find()) logPii(rel, i + 1, lm.group(1), out);
                    if (js && l.matches("(?i).*localStorage\\.setItem\\(\\s*['\"][^'\"]*" + PII + "[^'\"]*['\"].*")) {
                        out.add(new Finding(NAME, Category.PRIVACY, Severity.LOW, rel, i + 1, "pii-in-browser-storage",
                                "Personal data stored in localStorage (readable by any script on the page)", "CWE-359", "A04",
                                "Keep PII server-side; store only an opaque session reference."));
                    }
                    if (js && l.matches(".*document\\.cookie\\s*=.*") && !l.toLowerCase().contains("secure")) {
                        out.add(new Finding(NAME, Category.PRIVACY, Severity.LOW, rel, i + 1, "cookie-no-secure-flag",
                                "Cookie set from JavaScript without Secure/SameSite", "CWE-614", "A05",
                                "Add ; Secure; SameSite=Lax (prefer server-set HttpOnly cookies)."));
                    }
                    if (java && l.contains("new Cookie(")) {
                        int end = Math.min(lines.size(), i + 8);
                        String ctxLines = String.join("\n", lines.subList(i, end));
                        if (!ctxLines.contains("setHttpOnly") || !ctxLines.contains("setSecure")) {
                            out.add(new Finding(NAME, Category.PRIVACY, Severity.MEDIUM, rel, i + 1, "cookie-missing-flags",
                                    "Cookie created without setHttpOnly(true) and setSecure(true)", "CWE-1004", "A05",
                                    "Set HttpOnly, Secure and SameSite (ResponseCookie.from(..).httpOnly(true).secure(true).sameSite(\"Lax\"))."));
                        }
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                // unreadable file
            }
        });

        if (!trackerHits.isEmpty() && !consent[0]) {
            String[] h = trackerHits.get(0);
            out.add(new Finding(NAME, Category.PRIVACY, Severity.MEDIUM, h[0], Integer.parseInt(h[1]), "tracker-without-consent",
                    "Analytics/advertising tracker loaded (" + trackerHits.size() + " reference(s)) but no cookie-consent mechanism found",
                    "CWE-359", "A04", "Load trackers only after opt-in (consent banner / CMP) for EU users; document it in the privacy policy."));
        }
        metrics.put("Trackers referenced", String.valueOf(trackerHits.size()));
        if (react) {
            boolean hasLib = I18N_LIB.matcher(pkg).find();
            metrics.put("Hard-coded UI strings (approx.)", String.valueOf(hardcoded[0]));
            metrics.put("i18n library", hasLib ? "yes" : "no");
            if (hardcoded[0] >= 20) {
                out.add(new Finding(NAME, Category.QUALITY, hasLib ? Severity.LOW : Severity.INFO, firstHardcoded[0], 0,
                        hasLib ? "hardcoded-strings" : "no-i18n",
                        hasLib ? "About " + hardcoded[0] + " user-facing strings bypass the i18n library"
                                : "No i18n framework; about " + hardcoded[0] + " user-facing strings are hard-coded",
                        null, null, "Move copy into translation files (react-i18next / react-intl) if you will ever localise."));
            }
        }
        if (usLocale[0]) {
            out.add(new Finding(NAME, Category.QUALITY, Severity.LOW, ".", 0, "hardcoded-locale",
                    "Dates/numbers formatted with a fixed 'en-US' locale", null, null,
                    "Pass the user's locale (navigator.language / i18n locale) instead."));
        }
        if (react && !trackerHits.isEmpty() && !privacyLink[0]) {
            out.add(new Finding(NAME, Category.PRIVACY, Severity.LOW, ".", 0, "no-privacy-policy-link",
                    "Site uses trackers but no 'privacy' policy reference was found in the frontend",
                    "CWE-359", "A04", "Link a privacy policy and cookie policy in the footer."));
        }
        return ToolResult.ok(NAME, out, out.size() + " finding(s)", System.currentTimeMillis() - start).withMetrics(metrics);
    }

    static void logPii(String rel, int line, String args, List<Finding> out) {
        String a = stripStringLiterals(args).toLowerCase();
        if (Pattern.compile("\\b\\w*" + STRONG + "\\w*\\b").matcher(a).find()) {
            out.add(new Finding(NAME, Category.PRIVACY, Severity.HIGH, rel, line, "secret-in-log",
                    "Credential/secret-like value passed to a log statement", "CWE-532", "A09",
                    "Never log passwords, tokens or card data; log an id or a masked value."));
        } else if (Pattern.compile("\\b\\w*" + PII + "\\w*\\b").matcher(a).find()) {
            out.add(new Finding(NAME, Category.PRIVACY, Severity.MEDIUM, rel, line, "pii-in-log",
                    "Personal data (email/phone/address) passed to a log statement", "CWE-532", "A09",
                    "Log a user id instead, or mask the value; logs are widely readable and long-lived."));
        }
    }

    /** Words inside "quoted text" are not variables; only identifiers in the argument list matter. */
    static String stripStringLiterals(String s) {
        StringBuilder expr = new StringBuilder();
        Matcher t = Pattern.compile("`([^`]*)`").matcher(s);
        while (t.find()) {
            Matcher e = Pattern.compile("\\$\\{([^}]*)}").matcher(t.group(1));
            while (e.find()) expr.append(' ').append(e.group(1));
        }
        return s.replaceAll("\"(?:\\\\.|[^\"\\\\])*\"", "\"\"").replaceAll("'(?:\\\\.|[^'\\\\])*'", "''")
                .replaceAll("`[^`]*`", "``") + expr;
    }
}
