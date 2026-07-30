package com.anshul.securescan.exception;

/**
 * Base runtime exception for SecureScan application errors.
 */
public class SecureScanException extends RuntimeException {

    public SecureScanException(String message) {
        super(message);
    }

    public SecureScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
