package com.anshul.securescan.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/**
 * Extracts hostnames and formats display target strings for SecureScan requests.
 */
public final class HostnameExtractor {

    private static final Pattern HAS_SCHEME_PATTERN = Pattern.compile("^(?i)https?://.*$");

    private HostnameExtractor() {
    }

    /**
     * Extracts the target domain or IP from a URL or raw input for Nmap process execution.
     * Removes scheme, port numbers, path, query parameters, and fragments.
     *
     * @param input raw URL or host string (e.g. "https://subdomain.example.com/page?id=10")
     * @return clean host for Nmap execution (e.g. "subdomain.example.com")
     */
    public static String extractHost(String input) {
        if (input == null || input.isBlank()) {
            return null;
        }

        String target = input.trim();
        if (!HAS_SCHEME_PATTERN.matcher(target).matches()) {
            target = "https://" + target;
        }

        try {
            URI uri = new URI(target);
            String host = uri.getHost();
            if (host == null || host.isBlank()) {
                String authority = uri.getAuthority();
                if (authority != null) {
                    host = authority.split(":")[0];
                }
            }

            if (host != null) {
                host = host.trim().toLowerCase();
                if (host.startsWith("[") && host.endsWith("]")) {
                    host = host.substring(1, host.length() - 1);
                }
            }

            return host;
        } catch (URISyntaxException ex) {
            return null;
        }
    }

    /**
     * Formats the target display hostname by stripping only the scheme (https:// or http://)
     * while preserving subdomains, paths, and query strings.
     *
     * @param rawUrl the user-submitted URL or target string (e.g. "https://example.com/products?id=10")
     * @return display string excluding scheme (e.g. "example.com/products?id=10")
     */
    public static String formatDisplayHost(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return "Unknown";
        }

        String formatted = rawUrl.trim();
        if (HAS_SCHEME_PATTERN.matcher(formatted).matches()) {
            formatted = formatted.replaceFirst("^(?i)https?://", "");
        }

        if (formatted.endsWith("/") && !formatted.contains("?")) {
            formatted = formatted.substring(0, formatted.length() - 1);
        }

        return formatted.isBlank() ? "Unknown" : formatted;
    }
}
