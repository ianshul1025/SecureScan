package com.anshul.securescan.scanner;

import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.dto.PortInfo;
import com.anshul.securescan.model.ScanProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses Nmap XML output into structured scan result data.
 */
public class NmapParser {

    private static final Logger logger = LoggerFactory.getLogger(NmapParser.class);

    public NmapScanResult parseXml(String xml) {
        return parseXml(xml, ScanProfile.QUICK, "unknown");
    }

    public NmapScanResult parseXml(String xml, ScanProfile profile) {
        return parseXml(xml, profile, "unknown");
    }

    public NmapScanResult parseXml(String xml, ScanProfile profile, String defaultHost) {
        NmapScanResult result = new NmapScanResult();
        result.setHost(defaultHost != null && !defaultHost.isBlank() ? defaultHost : "unknown");
        result.setScanProfile(profile != null ? profile.name() : ScanProfile.QUICK.name());

        boolean osRequested = profile != null && profile.isOsDetectionRequested();
        result.setOsDetectionRequested(osRequested);

        if (!osRequested) {
            result.setOs("Not scanned");
            result.setOsStatus("Not scanned");
        } else {
            result.setOs("Not detected");
            result.setOsStatus("Not detected");
        }

        if (xml == null || xml.isBlank()) {
            logger.warn("XML output provided to NmapParser is empty or null");
            result.setRawOutput(xml);
            return result;
        }

        String cleanXml = extractCleanXml(xml);
        if (cleanXml == null || cleanXml.isBlank()) {
            logger.warn("Could not extract valid XML tags (<nmaprun> ... </nmaprun>) from raw scanner output");
            result.setRawOutput(xml);
            return result;
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(cleanXml.getBytes(StandardCharsets.UTF_8)));
            Element root = doc.getDocumentElement();

            // Host element parsing
            NodeList hostNodes = root.getElementsByTagName("host");
            if (hostNodes.getLength() > 0) {
                Element hostEl = (Element) hostNodes.item(0);

                // Host Status
                NodeList statusNodes = hostEl.getElementsByTagName("status");
                if (statusNodes.getLength() > 0) {
                    Element st = (Element) statusNodes.item(0);
                    String stateStr = st.getAttribute("state");
                    if (stateStr != null && !stateStr.isBlank()) {
                        result.setHostStatus(stateStr.toUpperCase());
                    }
                }

                // Address (IPv4 / IPv6)
                NodeList addrNodes = hostEl.getElementsByTagName("address");
                String ip = null;
                for (int i = 0; i < addrNodes.getLength(); i++) {
                    Element addr = (Element) addrNodes.item(i);
                    String addrType = addr.getAttribute("addrtype");
                    if ("ipv4".equalsIgnoreCase(addrType) || "ipv6".equalsIgnoreCase(addrType)) {
                        ip = addr.getAttribute("addr");
                        if ("ipv4".equalsIgnoreCase(addrType)) {
                            break;
                        }
                    }
                }
                if (ip != null && !ip.isBlank()) {
                    result.setIpAddress(ip);
                }

                // Hostname element
                NodeList hostnames = hostEl.getElementsByTagName("hostname");
                if (hostnames.getLength() > 0) {
                    Element hn = (Element) hostnames.item(0);
                    String xmlHostname = hn.getAttribute("name");
                    if (xmlHostname != null && !xmlHostname.isBlank()) {
                        result.setHost(xmlHostname);
                    }
                }

                // Scan duration / latency
                NodeList times = hostEl.getElementsByTagName("times");
                if (times.getLength() > 0) {
                    Element t = (Element) times.item(0);
                    String srtt = t.getAttribute("srtt");
                    if (srtt != null && !srtt.isBlank()) {
                        try {
                            result.setScanDurationSeconds(Double.parseDouble(srtt) / 1000.0);
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }

                // Discovered Ports
                List<PortInfo> ports = new ArrayList<>();
                NodeList portsNodes = hostEl.getElementsByTagName("ports");
                if (portsNodes.getLength() > 0) {
                    Element portsEl = (Element) portsNodes.item(0);
                    NodeList portList = portsEl.getElementsByTagName("port");
                    for (int i = 0; i < portList.getLength(); i++) {
                        Element p = (Element) portList.item(i);
                        String protocol = p.getAttribute("protocol");
                        if (protocol != null) {
                            protocol = protocol.toUpperCase();
                        }
                        int portid = Integer.parseInt(p.getAttribute("portid"));
                        String state = "unknown";
                        String serviceName = "unknown";
                        StringBuilder versionBuilder = new StringBuilder();

                        NodeList stateNodes = p.getElementsByTagName("state");
                        if (stateNodes.getLength() > 0) {
                            Element st = (Element) stateNodes.item(0);
                            state = st.getAttribute("state");
                        }

                        NodeList svc = p.getElementsByTagName("service");
                        if (svc.getLength() > 0) {
                            Element se = (Element) svc.item(0);
                            if (se.hasAttribute("name") && !se.getAttribute("name").isBlank()) {
                                serviceName = se.getAttribute("name");
                            }

                            if (se.hasAttribute("product")) {
                                versionBuilder.append(se.getAttribute("product"));
                            }
                            if (se.hasAttribute("version")) {
                                if (versionBuilder.length() > 0) {
                                    versionBuilder.append(" ");
                                }
                                versionBuilder.append(se.getAttribute("version"));
                            }
                            if (se.hasAttribute("extrainfo")) {
                                if (versionBuilder.length() > 0) {
                                    versionBuilder.append(" (").append(se.getAttribute("extrainfo")).append(")");
                                }
                            }
                        }

                        String finalVersion = versionBuilder.toString().trim();
                        PortInfo pi = new PortInfo(portid, protocol, serviceName, state, finalVersion);

                        if ("open".equalsIgnoreCase(state)) {
                            ports.add(pi);
                        }
                    }
                }
                result.setOpenPorts(ports);
            }

            // OS Fingerprinting analysis
            if (osRequested) {
                NodeList osMatches = root.getElementsByTagName("osmatch");
                if (osMatches.getLength() > 0) {
                    Element om = (Element) osMatches.item(0);
                    String osName = om.getAttribute("name");
                    if (osName != null && !osName.isBlank()) {
                        result.setOs(osName);
                        result.setOsStatus("Detected");
                    } else {
                        result.setOs("Not detected");
                        result.setOsStatus("Not detected");
                    }
                } else {
                    result.setOs("Not detected");
                    result.setOsStatus("Not detected");
                }
            } else {
                result.setOs("Not scanned");
                result.setOsStatus("Not scanned");
            }

            result.setRawOutput(cleanXml);
        } catch (Exception ex) {
            logger.error("Failed to parse Nmap XML content", ex);
            result.setRawOutput(xml);
        }

        return result;
    }

    private String extractCleanXml(String rawXml) {
        if (rawXml == null || rawXml.isBlank()) {
            return null;
        }

        int start = rawXml.indexOf("<?xml");
        if (start == -1) {
            start = rawXml.indexOf("<nmaprun");
        }

        int end = rawXml.lastIndexOf("</nmaprun>");
        if (start != -1 && end != -1 && end > start) {
            return rawXml.substring(start, end + "</nmaprun>".length());
        }

        return rawXml.trim();
    }
}
