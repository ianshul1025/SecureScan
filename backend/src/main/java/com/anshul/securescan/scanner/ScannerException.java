package com.anshul.securescan.scanner;

/**
 * Runtime exception for scanner execution errors.
 */
public class ScannerException extends RuntimeException {

    public ScannerException(String message) {
        super(message);
    }

    public ScannerException(String message, Throwable cause) {
        super(message, cause);
    }
}
