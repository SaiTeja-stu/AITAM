package com.cybershield.web.upload;

import org.apache.tika.Tika;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.Set;

import static org.springframework.http.HttpStatus.PAYLOAD_TOO_LARGE;
import static org.springframework.http.HttpStatus.UNSUPPORTED_MEDIA_TYPE;

/**
 * Hardened file-upload checks (security spec: File Upload).
 *  - real content type sniffed from magic bytes (Tika), NOT the declared header
 *  - allowlist of image types only
 *  - hard size ceiling
 *  - must actually decode as an image (defeats polyglot / disguised payloads)
 * The client-supplied filename is never used for anything.
 */
@Component
public class ImageUploadValidator {

    private static final Set<String> ALLOWED = Set.of("image/png", "image/jpeg", "image/webp");
    private final Tika tika = new Tika();
    private final long maxBytes;

    public ImageUploadValidator(@Value("${cybershield.upload.max-bytes:5242880}") long maxBytes) {
        this.maxBytes = maxBytes;
    }

    public void validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,
                    "No image was provided.");
        }
        if (file.getSize() > maxBytes) {
            throw new ResponseStatusException(PAYLOAD_TOO_LARGE,
                    "Image exceeds the " + (maxBytes / 1024 / 1024) + " MB limit.");
        }
        byte[] bytes;
        try {
            bytes = file.getBytes();
        } catch (Exception e) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,
                    "Could not read the uploaded file.");
        }

        String detected;
        try {
            detected = tika.detect(bytes);
        } catch (Exception e) {
            detected = "application/octet-stream";
        }
        if (!ALLOWED.contains(detected)) {
            throw new ResponseStatusException(UNSUPPORTED_MEDIA_TYPE,
                    "Only PNG, JPEG or WebP images are accepted (detected: " + detected + ").");
        }

        try {
            BufferedImage img = ImageIO.read(new ByteArrayInputStream(bytes));
            if (img == null || img.getWidth() <= 0 || img.getHeight() <= 0) {
                throw new IllegalStateException("not an image");
            }
        } catch (Exception e) {
            throw new ResponseStatusException(UNSUPPORTED_MEDIA_TYPE,
                    "The file is not a valid image.");
        }
    }
}
