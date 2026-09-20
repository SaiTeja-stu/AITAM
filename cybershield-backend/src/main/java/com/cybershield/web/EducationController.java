package com.cybershield.web;

import com.cybershield.education.EducationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/education")
public class EducationController {

    private final EducationService education;

    public EducationController(EducationService education) {
        this.education = education;
    }

    @GetMapping("/modules")
    public List<EducationService.Module> modules(@org.springframework.web.bind.annotation.RequestParam(defaultValue = "en") String lang) {
        return education.all(lang);
    }

    @GetMapping("/modules/{id}")
    public ResponseEntity<EducationService.Module> module(@PathVariable String id,
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "en") String lang) {
        EducationService.Module m = education.byId(id, lang);
        return m == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(m);
    }
}
