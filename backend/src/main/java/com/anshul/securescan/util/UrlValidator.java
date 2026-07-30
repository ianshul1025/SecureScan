package com.anshul.securescan.util;

import com.anshul.securescan.exception.InvalidUrlException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Validates and normalizes URLs for SecureScan requests.
 */
public final class UrlValidator {

    private static final Logger logger = LoggerFactory.getLogger(UrlValidator.class);
    private static final Pattern URL_WITH_SCHEME_PATTERN = Pattern.compile("^(?i)https?://.*$");
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^[A-Za-z0-9.-]+$");
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;

    private UrlValidator() {
    }

    public static String validateAndNormalizeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new InvalidUrlException("URL must not be blank");
        }

        String normalizedUrl = rawUrl.trim();
        if (!URL_WITH_SCHEME_PATTERN.matcher(normalizedUrl).matches()) {
            normalizedUrl = "https://" + normalizedUrl;
        }

        URI uri;
        try {
            uri = URI.create(normalizedUrl);
        } catch (IllegalArgumentException ex) {
            throw new InvalidUrlException("Invalid URL format", ex);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new InvalidUrlException("URL must contain a valid hostname");
        }

        if (!HOSTNAME_PATTERN.matcher(host).matches()) {
            throw new InvalidUrlException("Hostname contains invalid characters");
        }

        if (host.startsWith("-") || host.endsWith("-")) {
            throw new InvalidUrlException("Hostname cannot start or end with a hyphen");
        }

        return normalizedUrl;
    }

    public static boolean isReachable(String normalizedUrl) {
        String host = HostnameExtractor.extractHost(normalizedUrl);
        if (host == null || host.isBlank()) {
            return false;
        }

        // 1. Try DNS Resolution first
        try {
            InetAddress.getByName(host);
        } catch (UnknownHostException ex) {
            logger.warn("DNS resolution failed for host: {}", host);
            return false;
        }

        // 2. Attempt HTTP connection
        try {
            URL url = URI.create(normalizedUrl).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setInstanceFollowRedirects(true);
            int responseCode = connection.getResponseCode();
            // Any HTTP response code (including 401, 403, 404, 500) confirms host is reachable
            return responseCode > 0;
        } catch (Exception ex) {
            // Fallback: If HTTP request failed but DNS resolved, target is still network reachable for port scan
            return true;
        }
    }
}
