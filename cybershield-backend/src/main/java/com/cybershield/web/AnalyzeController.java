package com.cybershield.web;

import com.cybershield.analyze.AnalysisService;
import com.cybershield.domain.ContentType;
import com.cybershield.qr.QrDecoder;
import com.cybershield.web.dto.AnalyzeRequest;
import com.cybershield.web.dto.AnalyzeResponse;
import com.cybershield.web.upload.ImageUploadValidator;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RestController
@RequestMapping("/api/v1/analyze")
public class AnalyzeController {

    private final AnalysisService analysis;
    private final QrDecoder qrDecoder;
    private final ImageUploadValidator uploadValidator;

    public AnalyzeController(AnalysisService analysis, QrDecoder qrDecoder, ImageUploadValidator uploadValidator) {
        this.analysis = analysis;
        this.qrDecoder = qrDecoder;
        this.uploadValidator = uploadValidator;
    }

    /** Analyse text content: URL, EMAIL, SMS, QR (decoded string), WEBPAGE (HTML or URL), SOCIAL. */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public AnalyzeResponse analyze(@Valid @RequestBody AnalyzeRequest req,
                                   @RequestHeader(value = "X-Client", required = false) String client) {
        String source = req.source() != null ? req.source() : client;
        return analysis.analyze(req.type(), req.content(), req.pageUrl(), source, CurrentUser.id(), true);
    }

    /**
     * Analyse a QR code supplied as an image. The image is validated by real
     * content type and size, decoded on the server, and the payload is routed
     * through the same pipeline as {@code type=QR}.
     */
    @PostMapping(value = "/qr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<AnalyzeResponse> analyzeQrImage(@RequestPart("image") MultipartFile image,
                                                          @RequestHeader(value = "X-Client", required = false) String client) {
        uploadValidator.validate(image);   // throws ResponseStatusException on any problem
        byte[] bytes;
        try {
            bytes = image.getBytes();
        } catch (Exception e) {
            throw new ResponseStatusException(BAD_REQUEST, "Could not read the uploaded image.");
        }
        String payload = qrDecoder.decode(bytes)
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST,
                        "No QR code could be read from the image."));
        return ResponseEntity.ok(
                analysis.analyze(ContentType.QR, payload, null, client, CurrentUser.id(), true));
    }
}
