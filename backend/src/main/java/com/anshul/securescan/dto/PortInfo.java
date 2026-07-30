package com.anshul.securescan.dto;

/**
 * Represents a single open port discovered during a security scan.
 */
public class PortInfo {

    private int port;
    private String protocol;
    private String service;
    private String state;
    private String version;

    public PortInfo() {
        this.version = "—";
    }

    public PortInfo(int port, String protocol, String service, String state) {
        this.port = port;
        this.protocol = protocol;
        this.service = service;
        this.state = state;
        this.version = "—";
    }

    public PortInfo(int port, String protocol, String service, String state, String version) {
        this.port = port;
        this.protocol = protocol;
        this.service = service;
        this.state = state;
        this.version = (version == null || version.isBlank()) ? "—" : version;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getVersion() {
        return (version == null || version.isBlank()) ? "—" : version;
    }

    public void setVersion(String version) {
        this.version = (version == null || version.isBlank()) ? "—" : version;
    }
}
