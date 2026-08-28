package com.cybershield.web.dto;

import com.cybershield.domain.ContentType;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Submit a piece of content as a suspected threat (problem statement: threat reporting). */
public record ReportRequest(

        @NotNull(message = "type is required")
        ContentType type,

        @NotNull(message = "content is required")
        @Size(min = 1, max = 20000)
        String content,

        @Size(max = 400, message = "note must be at most 400 characters")
        String note
) {}
