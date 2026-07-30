package com.anshul.securescan.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for site scanning operations.
 * Supports both scanProfile and profile fields for flexibility.
 */
public class ScanRequest {

    @NotBlank(message = "url must not be blank")
    private String url;
    
    @JsonAlias({"profile"})
    private String scanProfile;

    public ScanRequest() {
    }

    public ScanRequest(String url) {
        this.url = url;
    }

    public ScanRequest(String url, String scanProfile) {
        this.url = url;
        this.scanProfile = scanProfile;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getScanProfile() {
        return scanProfile;
    }

    public void setScanProfile(String scanProfile) {
        this.scanProfile = scanProfile;
    }

    // Backwards compatibility alias getter/setter for 'profile'
    public String getProfile() {
        return scanProfile;
    }

    public void setProfile(String profile) {
        this.scanProfile = profile;
    }
}