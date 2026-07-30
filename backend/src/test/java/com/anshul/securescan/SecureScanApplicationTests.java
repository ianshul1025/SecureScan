package com.anshul.securescan;

import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.dto.RiskAnalysis;
import com.anshul.securescan.model.AssessmentStatus;
import com.anshul.securescan.service.RiskAnalysisService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class SecureScanApplicationTests {

    @Test
    void contextLoads() {
    }

    @Test
    void analyzeHandlesNullOsWithoutThrowing() {
        RiskAnalysisService service = new RiskAnalysisService();
        NmapScanResult result = new NmapScanResult();
        result.setHost("example.com");
        result.setIpAddress("93.184.216.34");
        result.setHostStatus("UP");
        result.setAssessmentStatus(AssessmentStatus.COMPLETED);
        result.setOs(null);
        result.setOpenPorts(Collections.emptyList());

        assertDoesNotThrow(() -> service.analyze(result));
        RiskAnalysis analysis = service.analyze(result);
        assertEquals("LOW", analysis.getRiskLevel());
        assertTrue(analysis.getSummary().contains("No open ports"));
    }

}
