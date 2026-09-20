package com.cybershield.education;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.util.List;

/** Serves the educational awareness modules (problem statement requirement). */
@Service
public class EducationService {

    private static final Logger log = LoggerFactory.getLogger(EducationService.class);

    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    public record Module(String id, String icon, String title, String rule, String summary,
                         List<String> doThis, List<String> keyPoints,
                         List<String> redFlags, String category) {}

    public static final List<String> LANGS = List.of("en", "te", "hi");

    private final ObjectMapper mapper;
    private final java.util.Map<String, List<Module>> byLang = new java.util.HashMap<>();

    public EducationService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @PostConstruct
    void load() {
        for (String lang : LANGS) {
            String file = "en".equals(lang) ? "education/modules.json" : "education/modules_" + lang + ".json";
            try (var in = new ClassPathResource(file).getInputStream()) {
                byLang.put(lang, List.of(mapper.readValue(in, Module[].class)));
                log.info("Loaded {} education modules ({})", byLang.get(lang).size(), lang);
            } catch (Exception e) {
                log.warn("Could not load education modules {}: {}", file, e.toString());
            }
        }
    }

    private List<Module> forLang(String lang) {
        List<Module> m = byLang.get(lang == null ? "en" : lang.toLowerCase());
        return m == null || m.isEmpty() ? byLang.getOrDefault("en", List.of()) : m;
    }

    public List<Module> all() {
        return forLang("en");
    }

    public List<Module> all(String lang) {
        return forLang(lang);
    }

    public Module byId(String id) {
        return byId(id, "en");
    }

    public Module byId(String id, String lang) {
        return forLang(lang).stream().filter(m -> m.id().equals(id)).findFirst().orElse(null);
    }
}
