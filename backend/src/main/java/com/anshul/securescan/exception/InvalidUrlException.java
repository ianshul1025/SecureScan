package com.anshul.securescan.exception;

/**
 * Thrown when the requested URL is invalid, malformed, or contains unsafe characters.
 */
public class InvalidUrlException extends SecureScanException {

    public InvalidUrlException(String message) {
        super(message);
    }

    public InvalidUrlException(String message, Throwable cause) {
        super(message, cause);
    }
}
