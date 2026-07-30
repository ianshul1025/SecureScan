package com.anshul.securescan.service;

import com.anshul.securescan.dto.HistoryResponse;
import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.dto.PortInfo;
import com.anshul.securescan.dto.RiskAnalysis;
import com.anshul.securescan.entity.ScanHistory;
import com.anshul.securescan.repository.ScanHistoryRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service responsible for storing scan history and returning past scan records.
 */
@Service
public class HistoryService {

    private final ScanHistoryRepository repository;

    public HistoryService(ScanHistoryRepository repository) {
        this.repository = repository;
    }

    /**
     * Saves a completed scan record to the database.
     *
     * @param url the scanned URL
     * @param result the parsed Nmap result
     * @param analysis the risk analysis metadata
     * @return saved scan history entity
     */
    public ScanHistory saveScan(String url, NmapScanResult result, RiskAnalysis analysis) {
        ScanHistory history = new ScanHistory();
        history.setUrl(url);
        history.setScanDate(LocalDateTime.now());
        history.setRiskLevel(analysis.getRiskLevel());
        history.setSummary(analysis.getSummary());
        history.setRawOutput(result.getRawOutput());
        history.setOpenPorts(serializePorts(result.getOpenPorts()));
        return repository.save(history);
    }

    /**
     * Retrieves all saved scan histories.
     *
     * @return list of history response DTOs
     */
    public List<HistoryResponse> getAllHistory() {
        return repository.findAll().stream()
                .map(this::toHistoryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Retrieves a single scan history by its ID.
     *
     * @param id the history record identifier
     * @return optional history response
     */
    public Optional<HistoryResponse> getHistoryById(Long id) {
        return repository.findById(id).map(this::toHistoryResponse);
    }

    private String serializePorts(List<PortInfo> openPorts) {
        if (openPorts == null || openPorts.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (PortInfo port : openPorts) {
            builder.append(port.getPort())
                    .append("/")
                    .append(port.getProtocol())
                    .append(" ")
                    .append(port.getState())
                    .append(" ")
                    .append(port.getService())
                    .append("; ");
        }
        return Base64.getEncoder().encodeToString(builder.toString().getBytes());
    }

    private List<PortInfo> deserializePorts(String text) {
        if (text == null || text.isBlank()) {
            return new ArrayList<>();
        }
        String decoded = new String(Base64.getDecoder().decode(text));
        List<PortInfo> list = new ArrayList<>();
        for (String token : decoded.split(";")) {
            String trimmed = token.trim();
            if (trimmed.isBlank()) {
                continue;
            }
            String[] parts = trimmed.split(" ");
            if (parts.length >= 4) {
                String[] portProto = parts[0].split("/");
                int port = Integer.parseInt(portProto[0]);
                String protocol = portProto[1];
                String state = parts[1];
                String service = parts[2];
                list.add(new PortInfo(port, protocol, service, state));
            }
        }
        return list;
    }

    private HistoryResponse toHistoryResponse(ScanHistory history) {
        HistoryResponse response = new HistoryResponse();
        response.setId(history.getId());
        response.setUrl(history.getUrl());
        response.setScanDate(history.getScanDate());
        response.setRiskLevel(history.getRiskLevel());
        response.setSummary(history.getSummary());
        response.setOpenPorts(deserializePorts(history.getOpenPorts()));
        return response;
    }
}
