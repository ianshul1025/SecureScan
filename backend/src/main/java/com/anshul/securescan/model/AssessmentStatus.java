package com.anshul.securescan.model;

/**
 * Represents the execution outcome status of a security assessment.
 */
public enum AssessmentStatus {
    COMPLETED("Completed"),
    INCONCLUSIVE("Inconclusive"),
    FAILED("Failed");

    private final String displayName;

    AssessmentStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
