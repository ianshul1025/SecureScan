package com.anshul.securescan.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Response DTO for scan history retrieval.
 */
public class HistoryResponse {

    private Long id;
    private String url;
    private LocalDateTime scanDate;
    private String riskLevel;
    private String summary;
    private List<PortInfo> openPorts;

    public HistoryResponse() {
    }

    public HistoryResponse(Long id, String url, LocalDateTime scanDate, String riskLevel, String summary, List<PortInfo> openPorts) {
        this.id = id;
        this.url = url;
        this.scanDate = scanDate;
        this.riskLevel = riskLevel;
        this.summary = summary;
        this.openPorts = openPorts;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public LocalDateTime getScanDate() {
        return scanDate;
    }

    public void setScanDate(LocalDateTime scanDate) {
        this.scanDate = scanDate;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<PortInfo> getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(List<PortInfo> openPorts) {
        this.openPorts = openPorts;
    }
}
