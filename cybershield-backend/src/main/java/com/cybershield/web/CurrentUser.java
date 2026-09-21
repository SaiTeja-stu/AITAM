package com.cybershield.web;

import com.cybershield.security.JwtService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/** Helper to read the authenticated principal set by {@code JwtAuthFilter}. */
public final class CurrentUser {
    private CurrentUser() {}

    public static String id() {
        JwtService.AuthenticatedUser u = principal();
        return u == null ? null : u.userId();
    }

    /** The full JWT principal (id, username, role), or null if unauthenticated. */
    public static JwtService.AuthenticatedUser principal() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return (a != null && a.getPrincipal() instanceof JwtService.AuthenticatedUser u) ? u : null;
    }
}
