package dev.repolens;

import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import dev.repolens.model.Severity;
import dev.repolens.normalize.SarifParser;
import dev.repolens.owasp.OwaspMapper;
import dev.repolens.score.Scorer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CoreTest {

    @TempDir
    Path tmp;

    @Test
    void parsesSarifAndMapsOwasp() throws Exception {
        String sarif = """
                {"runs":[{"tool":{"driver":{"rules":[
                  {"id":"r1","properties":{"tags":["CWE-89: SQL Injection"],"security-severity":"8.1"}}]}},
                 "results":[{"ruleId":"r1","level":"error","message":{"text":"bad sql\\nmore"},
                  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/A.java"},"region":{"startLine":12}}}]}]}]}
                """;
        Path f = tmp.resolve("x.sarif");
        Files.writeString(f, sarif);
        List<Finding> found = SarifParser.parse(f, "semgrep", Category.SECURITY, tmp);
        assertEquals(1, found.size());
        Finding x = found.get(0);
        assertEquals(Severity.HIGH, x.severity());
        assertEquals("src/A.java", x.file());
        assertEquals(12, x.line());
        assertEquals("bad sql", x.message());
        assertEquals("A03", OwaspMapper.tag(x).owasp());
    }

    @Test
    void scoreDropsWithSeverity() {
        Finding crit = new Finding("t", Category.SECURITY, Severity.CRITICAL, "a", 1, "r", "m", null, null, null);
        int clean = Scorer.compute(List.of(), false).overall();
        int dirty = Scorer.compute(List.of(crit, crit, crit), false).overall();
        assertEquals(100, clean);
        assertTrue(dirty < clean);
    }
}
