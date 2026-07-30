package com.anshul.securescan.exception;

/**
 * Exception thrown when an invalid or unsupported scan profile is requested.
 */
public class InvalidScanProfileException extends SecureScanException {

    public InvalidScanProfileException(String message) {
        super(message);
    }
}
