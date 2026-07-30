package com.anshul.securescan.exception;

import java.time.Duration;

/**
 * Thrown when an Nmap scan exceeds the configured timeout period.
 */
public class NmapTimeoutException extends SecureScanException {

    public NmapTimeoutException(Duration timeout) {
        super("Nmap scan timed out after " + timeout.toSeconds() + " seconds");
    }

    public NmapTimeoutException(String message) {
        super(message);
    }
}
