package com.anshul.securescan.dto;

import java.util.List;

/**
 * Holds risk analysis metadata generated after scan results are parsed.
 */
public class RiskAnalysis {

    private String riskLevel;
    private String summary;
    private List<String> recommendations;

    public RiskAnalysis() {
    }

    public RiskAnalysis(String riskLevel, String summary, List<String> recommendations) {
        this.riskLevel = riskLevel;
        this.summary = summary;
        this.recommendations = recommendations;
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

    public List<String> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<String> recommendations) {
        this.recommendations = recommendations;
    }
}
