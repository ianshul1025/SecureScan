package com.anshul.securescan.model;

import com.anshul.securescan.exception.InvalidScanProfileException;

import java.time.Duration;
import java.util.List;

/**
 * Supported Nmap scan profiles for SecureScan.
 * Centralizes argument building, timeouts, descriptions, and OS detection flags.
 */
public enum ScanProfile {
    QUICK(
            "Quick Scan — Recommended",
            "Fast assessment of common ports.",
            List.of("-Pn", "-F", "-oX", "-"),
            Duration.ofSeconds(30),
            false
    ),
    DETAILED(
            "Detailed Scan",
            "Detect ports, services, and available version information.",
            List.of("-Pn", "-sV", "-oX", "-"),
            Duration.ofSeconds(60),
            false
    ),
    FULL(
            "Full Port Scan",
            "Scan all TCP ports. May take significantly longer.",
            List.of("-Pn", "-p-", "-oX", "-"),
            Duration.ofSeconds(300),
            false
    ),
    OS(
            "OS Detection",
            "Attempt operating-system fingerprinting.",
            List.of("-Pn", "-O", "-oX", "-"),
            Duration.ofSeconds(120),
            true
    ),
    AGGRESSIVE(
            "Aggressive Scan",
            "Advanced Nmap assessment including service detection, OS detection, scripts, and traceroute.",
            List.of("-Pn", "-A", "-oX", "-"),
            Duration.ofSeconds(300),
            true
    );

    private final String displayName;
    private final String description;
    private final List<String> nmapArguments;
    private final Duration timeoutDuration;
    private final boolean osDetectionRequested;

    ScanProfile(String displayName, String description, List<String> nmapArguments, Duration timeoutDuration, boolean osDetectionRequested) {
        this.displayName = displayName;
        this.description = description;
        this.nmapArguments = nmapArguments;
        this.timeoutDuration = timeoutDuration;
        this.osDetectionRequested = osDetectionRequested;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getNmapArguments() {
        return nmapArguments;
    }

    public Duration getTimeoutDuration() {
        return timeoutDuration;
    }

    public boolean isOsDetectionRequested() {
        return osDetectionRequested;
    }

    /**
     * Parses a string into a ScanProfile.
     * Returns QUICK if the input is null or blank.
     * Throws InvalidScanProfileException if an unsupported profile string is provided.
     */
    public static ScanProfile fromString(String value) {
        if (value == null || value.isBlank()) {
            return QUICK;
        }

        String trimmed = value.trim();

        for (ScanProfile profile : values()) {
            if (profile.name().equalsIgnoreCase(trimmed) || profile.getDisplayName().equalsIgnoreCase(trimmed)) {
                return profile;
            }
        }

        throw new InvalidScanProfileException("Unsupported scan profile: " + value);
    }
}
