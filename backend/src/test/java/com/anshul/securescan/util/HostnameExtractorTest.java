package com.anshul.securescan.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HostnameExtractorTest {

    @Test
    void extractsHostnameFromFullHttpsUrl() {
        assertEquals("example.com", HostnameExtractor.extractHost("https://example.com"));
        assertEquals("example.com", HostnameExtractor.extractHost("http://example.com"));
    }

    @Test
    void extractsHostnameFromRawDomainWithoutProtocol() {
        assertEquals("example.com", HostnameExtractor.extractHost("example.com"));
        assertEquals("www.example.com", HostnameExtractor.extractHost("www.example.com"));
    }

    @Test
    void extractsHostnameFromUrlWithPathAndQueryParams() {
        assertEquals("example.com", HostnameExtractor.extractHost("https://example.com/products?id=10"));
        assertEquals("subdomain.example.com", HostnameExtractor.extractHost("https://subdomain.example.com/page/section?user=test#fragment"));
    }

    @Test
    void extractsHostnameIgnoringPortNumbers() {
        assertEquals("example.com", HostnameExtractor.extractHost("https://example.com:8080/api"));
        assertEquals("localhost", HostnameExtractor.extractHost("http://localhost:8000"));
    }

    @Test
    void formatDisplayHostStripsSchemeWhilePreservingPathAndQueryParams() {
        assertEquals("example.com/products?id=10", HostnameExtractor.formatDisplayHost("https://example.com/products?id=10"));
        assertEquals("example.com/products?id=10", HostnameExtractor.formatDisplayHost("http://example.com/products?id=10"));
        assertEquals("scanme.nmap.org", HostnameExtractor.formatDisplayHost("https://scanme.nmap.org/"));
        assertEquals("example.com", HostnameExtractor.formatDisplayHost("example.com"));
    }

    @Test
    void returnsNullForNullOrBlankInputs() {
        assertNull(HostnameExtractor.extractHost(null));
        assertNull(HostnameExtractor.extractHost(""));
        assertNull(HostnameExtractor.extractHost("   "));
    }
}
