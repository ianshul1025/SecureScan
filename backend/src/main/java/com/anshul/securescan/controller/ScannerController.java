package com.anshul.securescan.controller;

import com.anshul.securescan.dto.ApiResponse;
import com.anshul.securescan.dto.HistoryResponse;
import com.anshul.securescan.dto.ScanRequest;
import com.anshul.securescan.dto.ScanResponse;
import com.anshul.securescan.service.ScannerService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST controller for SecureScan scan operations.
 * <p>
 * This controller delegates validation and scanning work to service classes.
 * It does not contain business logic.
 * </p>
 */
@RestController
@RequestMapping("/api")
public class ScannerController {

    private final ScannerService scannerService;

    public ScannerController(ScannerService scannerService) {
        this.scannerService = scannerService;
    }

    /**
     * Validates the submitted URL, executes the security scan, and returns the result.
     *
     * @param request the scan request containing the URL
     * @return standardized API response with scan metadata
     */
    @PostMapping(value = "/scan", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiResponse<ScanResponse> scanWebsite(@Valid @RequestBody ScanRequest request) {
        return scannerService.scan(request);
    }

    /**
     * Returns a list of all previous scan history records.
     *
     * @return list of history entries
     */
    @GetMapping(value = "/history", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiResponse<List<HistoryResponse>> getHistory() {
        return ApiResponse.success("History records retrieved", scannerService.listHistory());
    }

    /**
     * Returns a single history record by id.
     *
     * @param id the record identifier
     * @return history entry if found
     */
    @GetMapping(value = "/history/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiResponse<HistoryResponse> getHistoryById(@PathVariable Long id) {
        return scannerService.getHistory(id);
    }
}
