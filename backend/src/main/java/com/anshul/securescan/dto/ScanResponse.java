package com.anshul.securescan.dto;

import com.anshul.securescan.model.AssessmentStatus;

import java.time.Instant;
import java.util.List;

/**
 * Response DTO for security scan results returned to API clients.
 */
public class ScanResponse {

    private String url;
    private String status;
    private String host;
    private String ipAddress;
    private String hostStatus;
    private AssessmentStatus assessmentStatus = AssessmentStatus.COMPLETED;
    private String scanProfile;
    private String scanProfileLabel;
    private String osStatus;
    private String os;
    private double scanDurationSeconds;
    private String scanTimestamp;
    private List<PortInfo> openPorts;
    private RiskAnalysis riskAnalysis;

    public ScanResponse() {
        this.scanTimestamp = Instant.now().toString();
    }

    public ScanResponse(String url, String status) {
        this();
        this.url = url;
        this.status = status;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getHostStatus() {
        return hostStatus;
    }

    public void setHostStatus(String hostStatus) {
        this.hostStatus = hostStatus;
    }

    public AssessmentStatus getAssessmentStatus() {
        return assessmentStatus;
    }

    public void setAssessmentStatus(AssessmentStatus assessmentStatus) {
        this.assessmentStatus = assessmentStatus;
    }

    public String getScanProfile() {
        return scanProfile;
    }

    public void setScanProfile(String scanProfile) {
        this.scanProfile = scanProfile;
    }

    public String getScanProfileLabel() {
        return scanProfileLabel;
    }

    public void setScanProfileLabel(String scanProfileLabel) {
        this.scanProfileLabel = scanProfileLabel;
    }

    public String getOsStatus() {
        return osStatus;
    }

    public void setOsStatus(String osStatus) {
        this.osStatus = osStatus;
    }

    public String getOs() {
        return os;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public double getScanDurationSeconds() {
        return scanDurationSeconds;
    }

    public void setScanDurationSeconds(double scanDurationSeconds) {
        this.scanDurationSeconds = scanDurationSeconds;
    }

    public String getScanTimestamp() {
        return scanTimestamp;
    }

    public void setScanTimestamp(String scanTimestamp) {
        this.scanTimestamp = scanTimestamp;
    }

    public List<PortInfo> getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(List<PortInfo> openPorts) {
        this.openPorts = openPorts;
    }

    public RiskAnalysis getRiskAnalysis() {
        return riskAnalysis;
    }

    public void setRiskAnalysis(RiskAnalysis riskAnalysis) {
        this.riskAnalysis = riskAnalysis;
    }
}