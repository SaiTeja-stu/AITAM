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

    public record Module(String id, String title, String summary, List<String> keyPoints,
                         List<String> redFlags, String category) {}

    private final ObjectMapper mapper;
    private List<Module> modules = List.of();

    public EducationService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @PostConstruct
    void load() {
        try (var in = new ClassPathResource("education/modules.json").getInputStream()) {
            modules = List.of(mapper.readValue(in, Module[].class));
            log.info("Loaded {} education modules", modules.size());
        } catch (Exception e) {
            log.warn("Could not load education modules: {}", e.toString());
        }
    }

    public List<Module> all() {
        return modules;
    }

    public Module byId(String id) {
        return modules.stream().filter(m -> m.id().equals(id)).findFirst().orElse(null);
    }
}
