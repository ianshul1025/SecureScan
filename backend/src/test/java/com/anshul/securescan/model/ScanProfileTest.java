package com.anshul.securescan.model;

import com.anshul.securescan.exception.InvalidScanProfileException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScanProfileTest {

    @Test
    void defaultProfileIsQuickWhenNullOrBlank() {
        assertEquals(ScanProfile.QUICK, ScanProfile.fromString(null));
        assertEquals(ScanProfile.QUICK, ScanProfile.fromString(""));
        assertEquals(ScanProfile.QUICK, ScanProfile.fromString("   "));
    }

    @Test
    void parsesValidScanProfilesCaseInsensitively() {
        assertEquals(ScanProfile.QUICK, ScanProfile.fromString("quick"));
        assertEquals(ScanProfile.DETAILED, ScanProfile.fromString("DETAILED"));
        assertEquals(ScanProfile.FULL, ScanProfile.fromString("full"));
        assertEquals(ScanProfile.OS, ScanProfile.fromString("Os"));
        assertEquals(ScanProfile.AGGRESSIVE, ScanProfile.fromString("AGGRESSIVE"));
    }

    @Test
    void throwsInvalidScanProfileExceptionForInvalidProfiles() {
        assertThrows(InvalidScanProfileException.class, () -> ScanProfile.fromString("SUPER_FAST"));
        assertThrows(InvalidScanProfileException.class, () -> ScanProfile.fromString("HACK_SCAN"));
    }

    @Test
    void verifiesNmapArgumentsAndPnFlagForAggressiveProfile() {
        List<String> aggressiveArgs = ScanProfile.AGGRESSIVE.getNmapArguments();
        assertTrue(aggressiveArgs.contains("-Pn"), "Aggressive profile must include -Pn flag for consistent host discovery");
        assertTrue(aggressiveArgs.contains("-A"));

        List<String> quickArgs = ScanProfile.QUICK.getNmapArguments();
        assertEquals(List.of("-Pn", "-F", "-oX", "-"), quickArgs);
    }

    @Test
    void verifiesProfileTimeouts() {
        assertEquals(Duration.ofSeconds(30), ScanProfile.QUICK.getTimeoutDuration());
        assertEquals(Duration.ofSeconds(60), ScanProfile.DETAILED.getTimeoutDuration());
        assertEquals(Duration.ofSeconds(300), ScanProfile.FULL.getTimeoutDuration());
        assertEquals(Duration.ofSeconds(120), ScanProfile.OS.getTimeoutDuration());
        assertEquals(Duration.ofSeconds(300), ScanProfile.AGGRESSIVE.getTimeoutDuration());
    }

    @Test
    void verifiesOsDetectionRequestedFlags() {
        assertFalse(ScanProfile.QUICK.isOsDetectionRequested());
        assertFalse(ScanProfile.DETAILED.isOsDetectionRequested());
        assertFalse(ScanProfile.FULL.isOsDetectionRequested());
        assertTrue(ScanProfile.OS.isOsDetectionRequested());
        assertTrue(ScanProfile.AGGRESSIVE.isOsDetectionRequested());
    }
}
