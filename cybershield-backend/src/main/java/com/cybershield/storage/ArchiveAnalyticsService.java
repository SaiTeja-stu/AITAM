package com.cybershield.storage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;

/**
 * Lightweight analytics over the Tier-2 cold JSONL logs (current + rolled .gz),
 * for the dashboard's "scam trends" view. Reads at most {@code maxFiles} recent
 * files and {@code maxLines} lines to stay cheap. A DuckDB-backed version can
 * replace this later for large archives.
 */
@Service
public class ArchiveAnalyticsService {

    private static final Logger log = LoggerFactory.getLogger(ArchiveAnalyticsService.class);
    private static final int MAX_FILES = 14;
    private static final int MAX_LINES = 50_000;

    private final ObjectMapper mapper;
    private final Path archiveDir;

    public ArchiveAnalyticsService(ObjectMapper mapper,
                                   @Value("${CYBERSHIELD_ARCHIVE_DIR:./data/archive}") String dir) {
        this.mapper = mapper;
        this.archiveDir = Path.of(dir);
    }

    public Map<String, Object> trends() {
        Map<String, Long> perDay = new TreeMap<>();
        Map<String, Long> perLevel = new LinkedHashMap<>();
        Map<String, Long> perType = new LinkedHashMap<>();
        Map<String, Long> perCategory = new HashMap<>();
        Map<String, Long> perPolicy = new HashMap<>();
        long total = 0;

        List<Path> files = recentArchiveFiles();
        int lines = 0;
        for (Path f : files) {
            if (lines >= MAX_LINES) break;
            try (BufferedReader r = open(f)) {
                String line;
                while ((line = r.readLine()) != null && lines < MAX_LINES) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    lines++;
                    try {
                        JsonNode n = mapper.readTree(line);
                        total++;
                        String ts = n.path("ts").asText("");
                        if (ts.length() >= 10) perDay.merge(ts.substring(0, 10), 1L, Long::sum);
                        perLevel.merge(n.path("risk_level").asText("UNKNOWN"), 1L, Long::sum);
                        perType.merge(n.path("type").asText("UNKNOWN"), 1L, Long::sum);
                        n.path("categories").forEach(c -> perCategory.merge(c.asText(), 1L, Long::sum));
                        n.path("signals").forEach(s -> perPolicy.merge(
                                s.path("id").asText() + " " + s.path("name").asText(), 1L, Long::sum));
                    } catch (Exception ignore) {
                        // skip malformed line
                    }
                }
            } catch (Exception e) {
                log.debug("could not read archive file {}: {}", f, e.toString());
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("totalAnalyzed", total);
        out.put("windowDays", MAX_FILES);
        out.put("perDay", perDay);
        out.put("perRiskLevel", perLevel);
        out.put("perContentType", perType);
        out.put("topCategories", topN(perCategory, 8));
        out.put("topSignals", topN(perPolicy, 10));
        return out;
    }

    private List<Path> recentArchiveFiles() {
        List<Path> files = new ArrayList<>();
        try {
            if (!Files.isDirectory(archiveDir)) return files;
            try (Stream<Path> s = Files.list(archiveDir)) {
                files = s.filter(p -> {
                            String name = p.getFileName().toString();
                            return name.startsWith("scans-") && (name.endsWith(".jsonl") || name.endsWith(".jsonl.gz"));
                        })
                        .sorted(Comparator.comparing((Path p) -> p.getFileName().toString()).reversed())
                        .limit(MAX_FILES)
                        .toList();
            }
        } catch (Exception e) {
            log.debug("archive listing failed: {}", e.toString());
        }
        // Fallback: also handle the current, un-suffixed file today
        Path current = archiveDir.resolve("scans-current.jsonl");
        if (Files.exists(current) && files.stream().noneMatch(p -> p.equals(current))) {
            List<Path> withCurrent = new ArrayList<>();
            withCurrent.add(current);
            withCurrent.addAll(files);
            return withCurrent;
        }
        return files;
    }

    private BufferedReader open(Path f) throws Exception {
        InputStream in = Files.newInputStream(f);
        if (f.getFileName().toString().endsWith(".gz")) {
            in = new GZIPInputStream(in);
        }
        return new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    private List<Map<String, Object>> topN(Map<String, Long> counts, int n) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(n)
                .map(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("label", e.getKey());
                    m.put("count", e.getValue());
                    return m;
                })
                .toList();
    }

    // kept for symmetry with ZoneOffset import usage if extended later
    @SuppressWarnings("unused")
    private String today() {
        return LocalDate.now(ZoneOffset.UTC).toString();
    }
}
