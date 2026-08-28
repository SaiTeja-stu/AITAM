package com.cybershield.qr;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * Decodes a QR code from raw image bytes using ZXing. Used when the client sends
 * an image rather than a pre-decoded string. All failures are swallowed into an
 * empty Optional - callers treat "could not read" as its own outcome.
 */
@Component
public class QrDecoder {

    private static final Map<DecodeHintType, Object> HINTS =
            Map.of(DecodeHintType.TRY_HARDER, Boolean.TRUE);

    public Optional<String> decode(byte[] imageBytes) {
        if (imageBytes == null || imageBytes.length == 0) return Optional.empty();
        try {
            BufferedImage img = ImageIO.read(new ByteArrayInputStream(imageBytes));
            if (img == null) return Optional.empty();
            int w = img.getWidth();
            int h = img.getHeight();
            int[] pixels = img.getRGB(0, 0, w, h, null, 0, w);
            RGBLuminanceSource source = new RGBLuminanceSource(w, h, pixels);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
            Result result = new MultiFormatReader().decode(bitmap, HINTS);
            return Optional.ofNullable(result.getText());
        } catch (NotFoundException e) {
            return Optional.empty();
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }
}
