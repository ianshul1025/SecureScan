package com.anshul.securescan.service;

import com.anshul.securescan.dto.ApiResponse;
import com.anshul.securescan.dto.ScanRequest;
import com.anshul.securescan.dto.ScanResponse;
import com.anshul.securescan.exception.HostUnreachableException;
import com.anshul.securescan.exception.InvalidUrlException;
import com.anshul.securescan.util.UrlValidator;
import org.springframework.stereotype.Service;

/**
 * Service responsible for validating website URLs and determining reachability.
 */
@Service
public class WebsiteValidationService {

    public ApiResponse<ScanResponse> validateWebsiteUrl(ScanRequest request) {
        if (request == null || request.getUrl() == null || request.getUrl().isBlank()) {
            throw new InvalidUrlException("Request body must contain a valid url field");
        }

        String normalizedUrl;
        try {
            normalizedUrl = UrlValidator.validateAndNormalizeUrl(request.getUrl());
        } catch (InvalidUrlException ex) {
            throw ex;
        }

        boolean reachable = UrlValidator.isReachable(normalizedUrl);
        if (!reachable) {
            throw new HostUnreachableException("Target host is unreachable or DNS resolution failed");
        }

        ScanResponse response = new ScanResponse();
        response.setUrl(normalizedUrl);
        response.setStatus("VALIDATED");
        return ApiResponse.success("Website is reachable", response);
    }
}
