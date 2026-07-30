package com.anshul.securescan.scanner;

import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.dto.PortInfo;
import com.anshul.securescan.model.ScanProfile;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NmapParserTest {

    private final NmapParser parser = new NmapParser();

    @Test
    void parsesOpenPortsAndServiceVersionCorrectly() {
        String xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <nmaprun>
              <host>
                <status state="up"/>
                <address addr="93.184.216.34" addrtype="ipv4"/>
                <hostnames>
                  <hostname name="example.com"/>
                </hostnames>
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="Apache httpd" version="2.4.41"/>
                  </port>
                  <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
            """;

        NmapScanResult result = parser.parseXml(xml, ScanProfile.QUICK, "example.com");

        assertEquals("example.com", result.getHost());
        assertEquals("93.184.216.34", result.getIpAddress());
        assertEquals("UP", result.getHostStatus());
        assertEquals(2, result.getOpenPorts().size());

        PortInfo p1 = result.getOpenPorts().get(0);
        assertEquals(80, p1.getPort());
        assertEquals("TCP", p1.getProtocol());
        assertEquals("http", p1.getService());
        assertEquals("Apache httpd 2.4.41", p1.getVersion());

        PortInfo p2 = result.getOpenPorts().get(1);
        assertEquals(443, p2.getPort());
        assertEquals("—", p2.getVersion());
    }

    @Test
    void preservesDefaultHostWhenXmlHostnameElementIsOmitted() {
        String xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <nmaprun>
              <host>
                <status state="up"/>
                <address addr="45.33.32.156" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
            """;

        NmapScanResult result = parser.parseXml(xml, ScanProfile.QUICK, "scanme.nmap.org");

        assertEquals("scanme.nmap.org", result.getHost());
        assertEquals("45.33.32.156", result.getIpAddress());
        assertEquals("UP", result.getHostStatus());
        assertEquals(1, result.getOpenPorts().size());
    }

    @Test
    void sanitizesXmlOutputWhenContaminatedWithStderrWarningText() {
        String contaminatedOutput = """
            WARNING: Npcap loopback adapter not initialized properly
            <?xml version="1.0" encoding="UTF-8"?>
            <nmaprun>
              <host>
                <status state="up"/>
                <address addr="93.184.216.34" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
            Note: Scan finished with exit code 0
            """;

        NmapScanResult result = parser.parseXml(contaminatedOutput, ScanProfile.QUICK, "example.com");

        assertEquals("example.com", result.getHost());
        assertEquals("93.184.216.34", result.getIpAddress());
        assertEquals("UP", result.getHostStatus());
        assertEquals(1, result.getOpenPorts().size());
    }

    @Test
    void setsOsToNotScannedWhenOsDetectionNotRequested() {
        String xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <nmaprun>
              <host>
                <status state="up"/>
                <address addr="127.0.0.1" addrtype="ipv4"/>
              </host>
            </nmaprun>
            """;

        NmapScanResult resultQuick = parser.parseXml(xml, ScanProfile.QUICK, "localhost");
        assertEquals("Not scanned", resultQuick.getOs());
        assertEquals("Not scanned", resultQuick.getOsStatus());
    }

    @Test
    void setsOsToNotDetectedWhenAttemptedButNotReturned() {
        String xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <nmaprun>
              <host>
                <status state="up"/>
                <address addr="127.0.0.1" addrtype="ipv4"/>
              </host>
            </nmaprun>
            """;

        NmapScanResult resultOs = parser.parseXml(xml, ScanProfile.OS, "localhost");
        assertEquals("Not detected", resultOs.getOs());
        assertEquals("Not detected", resultOs.getOsStatus());
    }

    @Test
    void setsOsNameWhenOsFingerprintSuccessfullyDetected() {
        String xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <nmaprun>
              <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
              </host>
              <osmatch name="Linux 5.4 - 5.10" accuracy="98"/>
            </nmaprun>
            """;

        NmapScanResult result = parser.parseXml(xml, ScanProfile.OS, "router.local");
        assertEquals("Linux 5.4 - 5.10", result.getOs());
        assertEquals("Detected", result.getOsStatus());
    }
}
