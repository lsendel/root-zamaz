package com.zerotrust.authcore.trust;

/**
 * Trust levels in Zero Trust architecture.
 */
public enum TrustLevel {
    /** Untrusted - failed authentication, suspicious activity */
    NONE(0),
    
    /** Basic authentication - new devices, minimal verification */
    LOW(25),
    
    /** Known device - standard authentication with known device */
    MEDIUM(50),
    
    /** Verified device + location - trusted environment */
    HIGH(75),
    
    /** Hardware attestation - TPM, secure enclave, biometrics */
    FULL(100);

    private final int value;

    TrustLevel(int value) {
        this.value = value;
    }

    /**
     * Get the numeric value of the trust level.
     * 
     * @return the numeric value (0-100)
     */
    public int getValue() {
        return value;
    }

    /**
     * Create trust level from integer value.
     * 
     * @param value the numeric value
     * @return the corresponding trust level
     */
    public static TrustLevel fromValue(int value) {
        if (value >= 100) {
            return FULL;
        } else if (value >= 75) {
            return HIGH;
        } else if (value >= 50) {
            return MEDIUM;
        } else if (value >= 25) {
            return LOW;
        } else {
            return NONE;
        }
    }

    /**
     * Check if this trust level meets the required minimum.
     * 
     * @param required the required minimum trust level
     * @return true if this level meets the requirement
     */
    public boolean meetsRequirement(TrustLevel required) {
        return this.value >= required.value;
    }

    @Override
    public String toString() {
        return name().charAt(0) + name().substring(1).toLowerCase();
    }
}