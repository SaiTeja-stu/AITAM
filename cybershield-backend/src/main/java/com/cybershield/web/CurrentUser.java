package com.cybershield.web;

import com.cybershield.security.JwtService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/** Helper to read the authenticated principal set by {@code JwtAuthFilter}. */
public final class CurrentUser {
    private CurrentUser() {}

    public static String id() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a != null && a.getPrincipal() instanceof JwtService.AuthenticatedUser u) {
            return u.userId();
        }
        return null;
    }
}
