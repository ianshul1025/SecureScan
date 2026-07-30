package com.anshul.securescan.service;

import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.dto.PortInfo;
import com.anshul.securescan.dto.RiskAnalysis;
import com.anshul.securescan.model.AssessmentStatus;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskAnalysisServiceTest {

    private final RiskAnalysisService service = new RiskAnalysisService();

    @Test
    void inconclusiveAssessmentMustReturnInconclusiveRiskLevelAndNeverLowRisk() {
        NmapScanResult result = new NmapScanResult();
        result.setHost("example.com");
        result.setIpAddress("unknown");
        result.setHostStatus("UNKNOWN");
        result.setAssessmentStatus(AssessmentStatus.INCONCLUSIVE);
        result.setOpenPorts(Collections.emptyList());

        RiskAnalysis analysis = service.analyze(result);

        assertEquals("INCONCLUSIVE", analysis.getRiskLevel(), "Inconclusive assessment must return INCONCLUSIVE risk level");
        assertNotEquals("LOW", analysis.getRiskLevel(), "Inconclusive assessment must NEVER return LOW risk");
        assertTrue(analysis.getSummary().contains("could not obtain sufficient network information"));
    }

    @Test
    void completedAssessmentWithZeroPortsReturnsLowRiskWithDisclaimer() {
        NmapScanResult result = new NmapScanResult();
        result.setHost("example.com");
        result.setIpAddress("93.184.216.34");
        result.setHostStatus("UP");
        result.setAssessmentStatus(AssessmentStatus.COMPLETED);
        result.setOpenPorts(Collections.emptyList());

        RiskAnalysis analysis = service.analyze(result);

        assertEquals("LOW", analysis.getRiskLevel());
        assertTrue(analysis.getSummary().contains("No open ports were identified"));
        assertTrue(analysis.getRecommendations().get(0).contains("No exposed services were identified"));
    }

    @Test
    void completedAssessmentWithSensitivePortsReturnsHighRisk() {
        NmapScanResult result = new NmapScanResult();
        result.setHost("example.com");
        result.setIpAddress("93.184.216.34");
        result.setHostStatus("UP");
        result.setAssessmentStatus(AssessmentStatus.COMPLETED);
        result.setOpenPorts(List.of(
                new PortInfo(23, "TCP", "telnet", "open"),
                new PortInfo(445, "TCP", "microsoft-ds", "open")
        ));

        RiskAnalysis analysis = service.analyze(result);

        assertEquals("HIGH", analysis.getRiskLevel());
        assertTrue(analysis.getSummary().contains("2 sensitive service exposures detected"));
    }
}
