package com.anshul.securescan.service;

import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.dto.PortInfo;
import com.anshul.securescan.dto.RiskAnalysis;
import com.anshul.securescan.model.AssessmentStatus;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Service responsible for performing rule-based risk analysis and generating recommendations from Nmap scan findings.
 */
@Service
public class RiskAnalysisService {

    private static final String LOW = "LOW";
    private static final String MEDIUM = "MEDIUM";
    private static final String HIGH = "HIGH";
    private static final String INCONCLUSIVE = "INCONCLUSIVE";

    public RiskAnalysis analyze(NmapScanResult result) {
        List<String> recommendations = new ArrayList<>();

        // Handle INCONCLUSIVE assessments - MUST NEVER return LOW RISK
        if (result.getAssessmentStatus() == AssessmentStatus.INCONCLUSIVE || "UNKNOWN".equalsIgnoreCase(result.getHostStatus())) {
            String inconclusiveSummary = String.format(
                    "SecureScan could not obtain sufficient network information for target host %s (%s) to determine exposure. " +
                            "Network filtering, firewall rules, CDN/proxy infrastructure, target configuration, or transient connectivity conditions may affect scan visibility.",
                    result.getHost() != null ? result.getHost() : "target",
                    (result.getIpAddress() != null && !"unknown".equalsIgnoreCase(result.getIpAddress())) ? result.getIpAddress() : "Unresolved IP"
            );
            recommendations.add("Verify network access controls and host reachability for the target hostname.");
            recommendations.add("Consider re-assessing using a different scan profile or validating target firewall configurations.");
            return new RiskAnalysis(INCONCLUSIVE, inconclusiveSummary, recommendations);
        }

        List<PortInfo> openPorts = result.getOpenPorts();

        // Handle COMPLETED assessment with ZERO discovered open ports
        if (openPorts == null || openPorts.isEmpty()) {
            String zeroPortSummary = String.format(
                    "Security assessment completed for target host %s (%s). No open ports were identified within the scope of this scan.",
                    result.getHost() != null ? result.getHost() : "target",
                    (result.getIpAddress() != null && !"unknown".equalsIgnoreCase(result.getIpAddress())) ? result.getIpAddress() : "Resolved IP"
            );
            recommendations.add("No exposed services were identified during this assessment. Continue maintaining secure configurations, applying security updates, and restricting unnecessary network exposure.");
            recommendations.add("Consider performing an authorized assessment using a more comprehensive scan profile when deeper network visibility is required.");
            return new RiskAnalysis(LOW, zeroPortSummary, recommendations);
        }

        // Handle COMPLETED assessment with DISCOVERED open ports
        int sensitiveExposures = 0;
        for (PortInfo portInfo : openPorts) {
            if (isSensitivePort(portInfo.getPort())) {
                sensitiveExposures++;
            }
            String recommendation = generatePortRecommendation(portInfo);
            if (recommendation != null && !recommendations.contains(recommendation)) {
                recommendations.add(recommendation);
            }
        }

        String riskLevel = determineRiskLevel(openPorts.size(), sensitiveExposures);
        String summary = buildSummary(result, riskLevel, openPorts.size(), sensitiveExposures);

        return new RiskAnalysis(riskLevel, summary, recommendations);
    }

    private boolean isSensitivePort(int port) {
        return switch (port) {
            case 20, 21, 23, 69, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432, 6379, 27017 -> true;
            default -> false;
        };
    }

    private String generatePortRecommendation(PortInfo portInfo) {
        int port = portInfo.getPort();
        String service = portInfo.getService() != null ? portInfo.getService().toLowerCase() : "";

        if (port == 80 || "http".equals(service)) {
            return "Port 80 (HTTP) exposed: Consider redirecting unencrypted HTTP traffic to HTTPS where appropriate.";
        }
        if (port == 443 || "https".equals(service)) {
            return "Port 443 (HTTPS) exposed: Ensure modern TLS protocols and valid SSL/TLS certificates are maintained.";
        }
        if (port == 22 || "ssh".equals(service)) {
            return "Port 22 (SSH) exposed: Enforce strong key-based authentication and limit SSH access to authorized management IP ranges.";
        }
        if (port == 23 || "telnet".equals(service)) {
            return "Port 23 (Telnet) exposed: Telnet transmits data without modern transport security. Consider disabling external exposure and using SSH where remote administration is required.";
        }
        if (port == 445 || port == 139 || "smb".equals(service) || "netbios-ssn".equals(service)) {
            return String.format("Port %d (%s) exposed: Restrict SMB exposure to trusted networks and avoid unnecessary public accessibility.", port, portInfo.getService());
        }
        if (port == 3389 || "ms-wbt-server".equals(service) || "rdp".equals(service)) {
            return "Port 3389 (RDP) exposed: Restrict Remote Desktop Protocol exposure using network firewalls, multi-factor authentication, or VPNs.";
        }
        if (port == 3306 || port == 5432 || port == 27017 || port == 6379 || port == 1433 || port == 1521 || service.contains("mysql") || service.contains("postgres") || service.contains("mongo") || service.contains("redis")) {
            return String.format("Port %d (%s) exposed: Restrict direct database exposure using network controls and allow access only from required backend systems.", port, portInfo.getService());
        }

        return String.format("Port %d/%s (%s) exposed: Review access controls and restrict unnecessary public accessibility if unused.",
                port, portInfo.getProtocol(), portInfo.getService());
    }

    private String determineRiskLevel(int totalOpenPorts, int sensitiveExposures) {
        if (sensitiveExposures >= 2) {
            return HIGH;
        }
        if (sensitiveExposures == 1 || totalOpenPorts >= 5) {
            return MEDIUM;
        }
        return LOW;
    }

    private String buildSummary(NmapScanResult result, String riskLevel, int totalPorts, int sensitiveExposures) {
        StringBuilder summary = new StringBuilder();
        summary.append("Security assessment completed for target host ").append(result.getHost());
        if (result.getIpAddress() != null && !"unknown".equalsIgnoreCase(result.getIpAddress())) {
            summary.append(" (").append(result.getIpAddress()).append(")");
        }
        summary.append(". Identified ").append(totalPorts).append(" open port").append(totalPorts == 1 ? "" : "s").append(" with an overall risk classification of ").append(riskLevel).append(".");

        if (sensitiveExposures > 0) {
            summary.append(" ").append(sensitiveExposures).append(" sensitive service exposure").append(sensitiveExposures == 1 ? "" : "s").append(" detected.");
        }

        return summary.toString();
    }
}
