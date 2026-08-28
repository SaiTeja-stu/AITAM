package com.cybershield.web.dto;

import com.cybershield.domain.ContentType;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Request to analyse a piece of content.
 *
 * @param type     what kind of content this is (required, whitelisted enum)
 * @param content  the raw content: a URL, message body, page HTML, or decoded QR string
 *                 (required unless an image is supplied on the /analyze/qr endpoint)
 * @param pageUrl  for WEBPAGE: the address the HTML came from (optional)
 * @param source   free-form client tag, e.g. "chrome-ext" / "android" (optional, bounded)
 */
public record AnalyzeRequest(

        @NotNull(message = "type is required")
        ContentType type,

        @NotNull(message = "content is required")
        @Size(min = 1, max = 20000, message = "content must be 1-20000 characters")
        String content,

        @Size(max = 2048, message = "pageUrl too long")
        String pageUrl,

        @Size(max = 40, message = "source too long")
        String source
) {}
