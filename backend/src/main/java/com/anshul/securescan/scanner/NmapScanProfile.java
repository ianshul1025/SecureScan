package com.anshul.securescan.scanner;

import com.anshul.securescan.model.ScanProfile;

/**
 * Legacy wrapper for ScanProfile enum.
 */
public enum NmapScanProfile {
    QUICK,
    DETAILED,
    FULL,
    OS,
    AGGRESSIVE;

    public static ScanProfile fromString(String s) {
        return ScanProfile.fromString(s);
    }
}
