package com.anshul.securescan.dto;

import com.anshul.securescan.model.AssessmentStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Holds structured Nmap scan results parsed from raw command output.
 */
public class NmapScanResult {

    private String host;
    private String ipAddress;
    private String hostStatus = "UNKNOWN";
    private AssessmentStatus assessmentStatus = AssessmentStatus.COMPLETED;
    private String scanProfile;
    private String osStatus = "Not scanned";
    private String os = "Not scanned";
    private boolean osDetectionRequested = false;
    private double scanDurationSeconds;
    private List<PortInfo> openPorts = new ArrayList<>();
    private String rawOutput;

    public NmapScanResult() {
    }

    public NmapScanResult(String host, String ipAddress, String os, double scanDurationSeconds, List<PortInfo> openPorts, String rawOutput) {
        this.host = host;
        this.ipAddress = ipAddress;
        this.os = os;
        this.scanDurationSeconds = scanDurationSeconds;
        this.openPorts = openPorts;
        this.rawOutput = rawOutput;
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

    public boolean isOsDetectionRequested() {
        return osDetectionRequested;
    }

    public void setOsDetectionRequested(boolean osDetectionRequested) {
        this.osDetectionRequested = osDetectionRequested;
    }

    public double getScanDurationSeconds() {
        return scanDurationSeconds;
    }

    public void setScanDurationSeconds(double scanDurationSeconds) {
        this.scanDurationSeconds = scanDurationSeconds;
    }

    public List<PortInfo> getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(List<PortInfo> openPorts) {
        this.openPorts = openPorts;
    }

    public String getRawOutput() {
        return rawOutput;
    }

    public void setRawOutput(String rawOutput) {
        this.rawOutput = rawOutput;
    }
}
