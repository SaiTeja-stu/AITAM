package com.cybershield.investigate;

import com.cybershield.auth.UserAccount;
import com.cybershield.auth.UserAccountRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Admin-only provisioning for cyber-cell investigator accounts. Investigators
 * are a distinct role from ROLE_ADMIN - they can search the correlation
 * console but cannot moderate reports or see the raw scan queue.
 */
@RestController
@RequestMapping("/api/v1/admin/investigators")
@PreAuthorize("hasRole('ADMIN')")
public class AdminInvestigatorController {

    private static final SecureRandom RNG = new SecureRandom();

    private final UserAccountRepository users;
    private final PasswordEncoder encoder;

    public AdminInvestigatorController(UserAccountRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    public record CreateRequest(String username, String email, String displayName) {}
    public record CreatedView(String username, String email, String temporaryPassword) {}
    public record ListedView(String id, String username, String email, String displayName, Instant createdAt) {}

    /** Creates the account and returns a one-time temporary password - relay it to them out-of-band. */
    @PostMapping
    public ResponseEntity<?> create(@RequestBody CreateRequest req) {
        if (req.username() == null || req.username().isBlank() || req.email() == null || req.email().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("detail", "username and email are required."));
        }
        if (users.existsByUsername(req.username()) || users.existsByEmail(req.email().toLowerCase())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("detail", "That username or email is already in use."));
        }
        String tempPassword = randomPassword();
        UserAccount u = new UserAccount();
        u.setId(UUID.randomUUID().toString());
        u.setUsername(req.username().trim());
        u.setEmail(req.email().trim().toLowerCase());
        u.setDisplayName(req.displayName());
        u.setPasswordHash(encoder.encode(tempPassword));
        u.setRole("ROLE_INVESTIGATOR");
        u.setEnabled(true);
        u.setEmailVerified(true);   // provisioned directly by an admin - no OTP round-trip needed
        users.save(u);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new CreatedView(u.getUsername(), u.getEmail(), tempPassword));
    }

    @GetMapping
    public List<ListedView> list() {
        return users.findAll().stream()
                .filter(u -> "ROLE_INVESTIGATOR".equals(u.getRole()))
                .map(u -> new ListedView(u.getId(), u.getUsername(), u.getEmail(), u.getDisplayName(), u.getCreatedAt()))
                .toList();
    }

    @PostMapping("/{id}/revoke")
    public ResponseEntity<?> revoke(@PathVariable String id) {
        return users.findById(id).map(u -> {
            if (!"ROLE_INVESTIGATOR".equals(u.getRole())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("detail", "Not an investigator account."));
            }
            u.setEnabled(false);
            users.save(u);
            return ResponseEntity.ok(Map.of("id", id, "enabled", false));
        }).orElseGet(() -> ResponseEntity.notFound().build());
    }

    private static String randomPassword() {
        byte[] b = new byte[18];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
