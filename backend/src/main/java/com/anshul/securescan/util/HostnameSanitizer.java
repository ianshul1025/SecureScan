package com.anshul.securescan.util;

import com.anshul.securescan.exception.InvalidUrlException;

import java.util.regex.Pattern;

/**
 * Sanitizes hostnames to prevent injection and validate acceptable characters.
 */
public final class HostnameSanitizer {

    private static final Pattern VALID_HOSTNAME_PATTERN = Pattern.compile("^[A-Za-z0-9.-]+$");

    private HostnameSanitizer() {
    }

    public static String sanitize(String hostname) {
        if (hostname == null || hostname.isBlank()) {
            throw new InvalidUrlException("Hostname is required");
        }

        String sanitized = hostname.trim().toLowerCase();
        if (!VALID_HOSTNAME_PATTERN.matcher(sanitized).matches()) {
            throw new InvalidUrlException("Hostname contains invalid characters");
        }

        if (sanitized.startsWith("-") || sanitized.endsWith("-")) {
            throw new InvalidUrlException("Hostname contains invalid leading or trailing characters");
        }

        return sanitized;
    }
}
