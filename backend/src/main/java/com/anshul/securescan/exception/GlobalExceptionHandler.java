package com.anshul.securescan.exception;

import com.anshul.securescan.dto.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Global exception handler converting application exceptions into structured JSON responses.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(InvalidScanProfileException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidScanProfile(InvalidScanProfileException ex) {
        logger.warn("Invalid scan profile requested: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse.failure(ex.getMessage()));
    }

    @ExceptionHandler(InvalidUrlException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidUrl(InvalidUrlException ex) {
        logger.warn("Invalid URL request: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse.failure(ex.getMessage()));
    }

    @ExceptionHandler(HostUnreachableException.class)
    public ResponseEntity<ApiResponse<Void>> handleHostUnreachable(HostUnreachableException ex) {
        logger.warn("Host unreachable: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(ApiResponse.failure(ex.getMessage()));
    }

    @ExceptionHandler(NmapTimeoutException.class)
    public ResponseEntity<ApiResponse<Void>> handleNmapTimeout(NmapTimeoutException ex) {
        logger.error("Nmap scan timed out: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).body(ApiResponse.failure("The scan exceeded the allowed execution time."));
    }

    @ExceptionHandler(NmapExecutionException.class)
    public ResponseEntity<ApiResponse<Void>> handleNmapExecutionError(NmapExecutionException ex) {
        logger.error("Nmap execution failed: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiResponse.failure(ex.getMessage()));
    }

    @ExceptionHandler(SecureScanException.class)
    public ResponseEntity<ApiResponse<Void>> handleSecureScanErrors(SecureScanException ex) {
        logger.error("SecureScan exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiResponse.failure(ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationErrors(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        logger.warn("Validation failed: {}", message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse.failure(message));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleUnknownException(Exception ex) {
        logger.error("Unexpected internal server error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiResponse.failure("An unexpected error occurred during operation"));
    }
}
