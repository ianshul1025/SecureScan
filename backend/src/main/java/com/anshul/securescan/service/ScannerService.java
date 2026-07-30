package com.anshul.securescan.service;

import com.anshul.securescan.dto.ApiResponse;
import com.anshul.securescan.dto.HistoryResponse;
import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.dto.RiskAnalysis;
import com.anshul.securescan.dto.ScanRequest;
import com.anshul.securescan.dto.ScanResponse;
import com.anshul.securescan.exception.InvalidScanProfileException;
import com.anshul.securescan.exception.InvalidUrlException;
import com.anshul.securescan.exception.NmapExecutionException;
import com.anshul.securescan.exception.NmapTimeoutException;
import com.anshul.securescan.exception.SecureScanException;
import com.anshul.securescan.model.AssessmentStatus;
import com.anshul.securescan.model.ScanProfile;
import com.anshul.securescan.scanner.NmapScanner;
import com.anshul.securescan.util.HostnameExtractor;
import com.anshul.securescan.util.HostnameSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * Central service orchestrating URL validation, Nmap scanning, risk analysis, and response mapping.
 */
@Service
public class ScannerService {

    private static final Logger logger = LoggerFactory.getLogger(ScannerService.class);
    private final WebsiteValidationService validationService;
    private final NmapScanner nmapScanner;
    private final RiskAnalysisService riskAnalysisService;
    private final HistoryService historyService;

    public ScannerService(WebsiteValidationService validationService,
                          NmapScanner nmapScanner,
                          RiskAnalysisService riskAnalysisService,
                          HistoryService historyService) {
        this.validationService = validationService;
        this.nmapScanner = nmapScanner;
        this.riskAnalysisService = riskAnalysisService;
        this.historyService = historyService;
    }

    public ApiResponse<ScanResponse> scan(ScanRequest request) {
        ApiResponse<ScanResponse> validationResponse = validationService.validateWebsiteUrl(request);
        if (!validationResponse.isSuccess()) {
            return validationResponse;
        }

        String normalizedUrl = validationResponse.getData().getUrl();
        String targetHost = extractAndSanitizeHost(normalizedUrl);
        String displayHost = HostnameExtractor.formatDisplayHost(request.getUrl());
        ScanProfile profile = ScanProfile.fromString(request.getScanProfile());

        logger.info("Scan initiated. Target URL: {}, Display Target: {}, Nmap Target Host: {}, Profile: {}",
                normalizedUrl, displayHost, targetHost, profile.name());

        try {
            NmapScanResult scanResult = nmapScanner.scanHost(targetHost, profile.name());
            RiskAnalysis analysis = riskAnalysisService.analyze(scanResult);
            historyService.saveScan(normalizedUrl, scanResult, analysis);

            ScanResponse response = mapScanResponse(normalizedUrl, displayHost, scanResult, analysis, profile);
            return ApiResponse.success("Security assessment completed", response);
        } catch (InvalidScanProfileException ex) {
            throw ex;
        } catch (NmapTimeoutException ex) {
            throw ex;
        } catch (NmapExecutionException ex) {
            throw ex;
        } catch (SecureScanException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.error("Unexpected error during scanning target: {}", targetHost, ex);
            return ApiResponse.failure("An unexpected error occurred during security scan: " + ex.getMessage());
        }
    }

    public List<HistoryResponse> listHistory() {
        return historyService.getAllHistory();
    }

    public ApiResponse<HistoryResponse> getHistory(Long id) {
        return historyService.getHistoryById(id)
                .map(history -> ApiResponse.success("History record found", history))
                .orElseGet(() -> ApiResponse.failure("History record not found"));
    }

    private String extractAndSanitizeHost(String url) {
        String host = HostnameExtractor.extractHost(url);
        if (host == null || host.isBlank()) {
            throw new InvalidUrlException("Unable to extract valid host from target input");
        }
        return HostnameSanitizer.sanitize(host);
    }

    private ScanResponse mapScanResponse(String normalizedUrl, String displayHost, NmapScanResult scanResult, RiskAnalysis analysis, ScanProfile profile) {
        ScanResponse response = new ScanResponse();
        response.setUrl(normalizedUrl);
        response.setStatus("SUCCESS");
        response.setHost(displayHost);
        response.setIpAddress(scanResult.getIpAddress() != null ? scanResult.getIpAddress() : "Not available");
        response.setHostStatus(scanResult.getHostStatus() != null ? scanResult.getHostStatus() : "UNKNOWN");
        response.setAssessmentStatus(scanResult.getAssessmentStatus() != null ? scanResult.getAssessmentStatus() : AssessmentStatus.COMPLETED);
        response.setScanProfile(profile.name());
        response.setScanProfileLabel(profile.getDisplayName());
        response.setOsStatus(scanResult.getOsStatus());
        response.setOs(scanResult.getOs());
        response.setScanDurationSeconds(scanResult.getScanDurationSeconds());
        response.setScanTimestamp(Instant.now().toString());
        response.setOpenPorts(scanResult.getOpenPorts());
        response.setRiskAnalysis(analysis);
        return response;
    }
}
