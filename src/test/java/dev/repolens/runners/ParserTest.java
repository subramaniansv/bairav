package dev.repolens.runners;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.repolens.model.Category;
import dev.repolens.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ParserTest {

    @Test
    void lighthouseFailedAuditsBecomeFindings() throws Exception {
        String json = """
                {"finalDisplayedUrl":"http://localhost:5173/",
                 "categories":{"seo":{"score":0.8,"auditRefs":[{"id":"meta-description","weight":1}]},
                               "performance":{"score":0.4,"auditRefs":[{"id":"largest-contentful-paint","weight":25}]}},
                 "audits":{"meta-description":{"title":"Document has a meta description","score":0,"scoreDisplayMode":"binary","description":"Add one. [Learn](http://x)"},
                           "largest-contentful-paint":{"title":"LCP","score":0.3,"scoreDisplayMode":"numeric","displayValue":"4.1 s","description":"Slow."}}}
                """;
        List<Finding> f = LighthouseRunner.parseJson(new ObjectMapper().readTree(json));
        assertEquals(2, f.size());
        assertEquals(Category.SEO, f.get(0).category());
        assertEquals("Add one.", f.get(0).fix());
        assertEquals(Category.PERFORMANCE, f.get(1).category());
    }

    @Test
    void zapAlertsMapRiskToSeverity() throws Exception {
        String json = """
                {"site":[{"alerts":[{"pluginid":"10038","name":"CSP missing","riskcode":"2","cweid":"693",
                  "solution":"<p>Set CSP</p>","instances":[{"uri":"http://localhost:8080/"}]}]}]}
                """;
        List<Finding> f = ZapRunner.parseJson(new ObjectMapper().readTree(json), "http://localhost:8080");
        assertEquals(1, f.size());
        assertEquals("MEDIUM", f.get(0).severity().name());
        assertEquals("CWE-693", f.get(0).cwe());
        assertEquals("Set CSP", f.get(0).fix());
    }
}
