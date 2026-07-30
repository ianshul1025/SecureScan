package com.anshul.securescan.exception;

/**
 * Thrown when Nmap fails to execute correctly or returns an error output.
 */
public class NmapExecutionException extends SecureScanException {

    public NmapExecutionException(String message) {
        super(message);
    }

    public NmapExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
