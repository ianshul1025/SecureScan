package com.anshul.securescan.exception;

/**
 * Thrown when the target host cannot be reached during pre-scan validation.
 */
public class HostUnreachableException extends SecureScanException {

    public HostUnreachableException(String message) {
        super(message);
    }

    public HostUnreachableException(String message, Throwable cause) {
        super(message, cause);
    }
}
