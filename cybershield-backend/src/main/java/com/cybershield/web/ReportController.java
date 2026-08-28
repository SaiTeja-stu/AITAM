package com.cybershield.web;

import com.cybershield.report.ReportService;
import com.cybershield.web.dto.ReportRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class ReportController {

    private final ReportService reports;

    public ReportController(ReportService reports) {
        this.reports = reports;
    }

    /** Any authenticated user can report suspicious content (problem statement: threat reporting). */
    @PostMapping("/report")
    public ResponseEntity<Map<String, String>> submit(@Valid @RequestBody ReportRequest req) {
        String id = reports.submit(req.type(), req.content(), req.note(), CurrentUser.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "reportId", id,
                "message", "Thank you. Your report has been queued for review."));
    }
}
