package com.cybershield;

import com.cybershield.web.upload.ImageUploadValidator;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** File-upload hardening (security spec: wrong MIME, oversized, malicious content, bad signature). */
class FileUploadIT {

    private final ImageUploadValidator validator = new ImageUploadValidator(1_000_000);

    @Test
    void rejects_executable_disguised_as_png() {
        byte[] pe = new byte[]{'M', 'Z', (byte) 0x90, 0, 3, 0, 0, 0};
        var file = new MockMultipartFile("image", "photo.png", "image/png", pe);
        assertThatThrownBy(() -> validator.validate(file)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void rejects_text_labelled_as_image() {
        var file = new MockMultipartFile("image", "a.png", "image/png",
                "just some text".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> validator.validate(file)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void rejects_oversized_file() {
        byte[] big = new byte[1_200_000];
        var file = new MockMultipartFile("image", "big.png", "image/png", big);
        assertThatThrownBy(() -> validator.validate(file)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void rejects_empty_file() {
        var file = new MockMultipartFile("image", "empty.png", "image/png", new byte[0]);
        assertThatThrownBy(() -> validator.validate(file)).isInstanceOf(ResponseStatusException.class);
    }
}
